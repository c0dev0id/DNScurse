"""Iterative DNS resolver — walks the delegation chain from root servers.

Uses dnspython for wire format and UDP transport.
The iteration logic (following referrals, CNAMEs) is ours.

The algorithm implemented here follows RFC 1034 Section 5.3.3 ("Algorithm")
which describes how a resolver should process responses during iterative
name resolution. Each step below references the specific RFC section that
mandates the behavior.
"""

from __future__ import annotations

import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from .models import (
    RecursionStep,
    get_cname_target,
    get_referral_ns_ips,
    get_referral_ns_names,
    is_referral,
)

# Root hints — the bootstrap addresses for iterative resolution.
#
# RFC 1034 Section 5.3.2 ("Interfaces") states that a resolver needs
# "initial cache data" including "the addresses of the name servers for
# the root domain." These 13 addresses are published by IANA at
# https://www.iana.org/domains/root/servers and distributed as the
# "named.root" (root hints) file. They use anycast (RFC 3258) so each
# letter maps to multiple physical servers worldwide.
#
# We only need one working root to bootstrap — the rest of the tree
# is discovered through referrals.
ROOT_SERVERS: list[tuple[str, str]] = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
]

DEFAULT_TIMEOUT = 5.0

# Safety limits to prevent infinite loops from pathological DNS configs.
# RFC 1035 does not specify exact limits, but all production resolvers
# impose them. BIND uses ~30 referral hops; Unbound uses ~11 CNAME follows.
MAX_STEPS = 30
MAX_CNAME_FOLLOWS = 8


def send_query(name: str, rdtype: int, server_ip: str,
               timeout: float = DEFAULT_TIMEOUT) -> dns.message.Message:
    """Send an iterative DNS query over UDP and return the response.

    RFC 1035 Section 4.2.1 specifies UDP as the standard transport for
    DNS queries. We clear the RD (Recursion Desired) flag because we are
    performing iterative resolution ourselves — we don't want the server
    to recurse on our behalf. Per RFC 1034 Section 5.3.1, a resolver
    operating in iterative mode should send non-recursive queries
    (RD=0) so that servers return referrals instead of chasing the
    answer themselves.
    """
    query = dns.message.make_query(name, rdtype)
    # RFC 1034 Section 5.3.1: iterative queries use RD=0 so servers
    # return referrals rather than recursing for us.
    query.flags &= ~dns.flags.RD
    return dns.query.udp(query, server_ip, timeout=timeout)


def resolve(name: str, rdtype: int = dns.rdatatype.A,
            timeout: float = DEFAULT_TIMEOUT) -> list[RecursionStep]:
    """Iteratively resolve a domain name, returning every step.

    Implements the "standard name resolution algorithm" from
    RFC 1034 Section 5.3.3. The resolver starts at a root server and
    follows referrals down the delegation chain until it reaches an
    authoritative answer (or encounters an error).

    Each step is recorded as a RecursionStep with a human-readable
    explanation of what happened and why.
    """
    steps: list[RecursionStep] = []
    step_num = 0
    cname_follows = 0

    # RFC 1034 Section 5.3.3, Step 1: "See if the answer is in local
    # information" (cache). We have no cache, so we always start from
    # scratch at a root server. The root server is chosen from the
    # root hints (see ROOT_SERVERS above).
    current_name = name
    current_rdtype = rdtype
    server_ip = ROOT_SERVERS[0][1]
    server_name = ROOT_SERVERS[0][0]

    while step_num < MAX_STEPS:
        step_num += 1
        qtype_str = dns.rdatatype.to_text(current_rdtype)

        if step_num == 1:
            desc = f"Query root server for {current_name}"
        else:
            desc = f"Follow referral — query {server_name} for {current_name}"

        step = RecursionStep(
            step_number=step_num,
            description=desc,
            server_ip=server_ip,
            server_name=server_name,
            query_name=current_name,
            query_type=qtype_str,
        )

        # RFC 1034 Section 5.3.3, Step 2: "Send the query to the best
        # server available." We send a non-recursive query (RD=0) to the
        # current server, which is either a root server (first step) or
        # a nameserver we were referred to.
        try:
            response = send_query(current_name, current_rdtype, server_ip, timeout)
        except Exception as exc:
            # Network failure (timeout, unreachable, etc.). Record the
            # error so the user can see exactly which server failed.
            # RFC 1034 Section 5.3.3, Step 3: "if the response shows a
            # network error or other failure, the server is marked as
            # bad and a new server is selected" — we stop instead since
            # this is a debug tool showing each step.
            step.error = str(exc)
            steps.append(step)
            break

        step.response = response
        steps.append(step)

        # RFC 1034 Section 5.3.3, Step 3: "Analyze the response."
        # The response falls into one of several categories handled below.

        # --- Category: Error RCODE ---
        # RFC 1035 Section 4.1.1 defines RCODE values:
        #   0 = NOERROR  — success (even if no records found)
        #   3 = NXDOMAIN — the domain name does not exist
        #   2 = SERVFAIL — the server failed to process the query
        #   5 = REFUSED  — policy refusal
        # Any non-zero RCODE terminates resolution. For NXDOMAIN, the
        # authority section typically contains a SOA record whose MINIMUM
        # field sets the negative caching TTL (RFC 2308 Section 5).
        if response.rcode() != dns.rcode.NOERROR:
            break

        # --- Category: Answer ---
        # RFC 1034 Section 5.3.3, Step 3a: "if the response answers the
        # question...the answer is returned to the client."
        if response.answer:
            # RFC 1034 Section 3.6.2: "If a CNAME RR is found at a node,
            # no other data should be found...a CNAME means that the
            # current query name is an alias for the canonical name
            # specified in the CNAME RDATA. The resolver must restart
            # the query at the canonical name."
            #
            # Exception: if we explicitly asked for CNAME records (the
            # user wants to see the alias itself, not follow it).
            cname_target = get_cname_target(response, current_name)
            if cname_target and current_rdtype != dns.rdatatype.CNAME:
                cname_follows += 1
                # Guard against CNAME loops (A -> B -> A) or absurdly
                # long CNAME chains. No RFC specifies a limit, but
                # production resolvers all impose one.
                if cname_follows > MAX_CNAME_FOLLOWS:
                    break
                # Restart resolution from root for the CNAME target.
                # This is correct per RFC 1034 Section 3.6.2: the
                # resolver "restarts the query at the canonical name."
                current_name = cname_target
                server_ip = ROOT_SERVERS[0][1]
                server_name = ROOT_SERVERS[0][0]
                continue
            # Non-CNAME answer (or explicit CNAME query): done.
            break

        # --- Category: Referral ---
        # RFC 1034 Section 5.3.3, Step 3b: "if the response contains a
        # better delegation to the name" — the server doesn't have the
        # answer but tells us which nameservers are closer to it.
        #
        # A referral is identified by: no answer records, plus NS records
        # in the authority section pointing to the next zone's nameservers.
        # The additional section may contain "glue" A/AAAA records with
        # the IP addresses of those nameservers.
        if is_referral(response):
            glue_ips = get_referral_ns_ips(response)
            if glue_ips:
                # Glue records present: we have the NS's IP address and
                # can query it directly. Glue is provided when the NS
                # name is within the delegated zone (e.g., ns1.example.com
                # for example.com) — without glue we'd have a chicken-
                # and-egg problem. RFC 1034 Section 4.2.1 defines glue
                # as "address records...necessary to allow DNS to
                # function." RFC 7719 Section 6 formalizes the definition.
                server_ip = glue_ips[0]
                ns_names = get_referral_ns_names(response)
                if ns_names:
                    server_name = ns_names[0]
                continue

            # No glue records. This happens when the NS name is in a
            # different zone than the one being delegated:
            #   example.com NS ns1.other-provider.net
            # The .com TLD server doesn't know the IP for a .net name,
            # so no glue is provided. We must resolve the NS name to an
            # IP before we can continue — this is a sub-resolution that
            # itself starts from root.
            #
            # RFC 1034 Section 5.3.3, Step 3: "the resolver needs to
            # start a new query for the NS address" — the spec allows
            # this recursive sub-resolution.
            ns_names = get_referral_ns_names(response)
            if ns_names:
                # Recursively resolve the NS name's A record.
                ns_steps = resolve(ns_names[0], dns.rdatatype.A, timeout)
                # Walk the sub-resolution results backwards to find
                # the A record answer.
                for ns_step in reversed(ns_steps):
                    if ns_step.response and ns_step.response.answer:
                        for rrset in ns_step.response.answer:
                            if rrset.rdtype == dns.rdatatype.A:
                                server_ip = list(rrset)[0].address
                                server_name = ns_names[0]
                                break
                        break
                else:
                    # Could not resolve the NS name — give up.
                    break
                continue

            # Authority section has NS records but we couldn't extract
            # any names — malformed response.
            break

        # --- Category: NODATA ---
        # RFC 2308 Section 2.2: the name exists but has no records of
        # the requested type. Indicated by NOERROR rcode, empty answer
        # section, and SOA in authority. Not a referral (no NS records
        # pointing to child zones). Resolution is complete — the answer
        # is "no records of this type exist."
        break

    return steps
