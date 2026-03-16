"""Data models and helpers for DNS recursion step tracking.

Uses dnspython's dns.message.Message as the packet representation.
This module provides RecursionStep (our value-add) and helper functions
that inspect dns.message.Message objects for referral/CNAME detection.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype


def is_referral(msg: dns.message.Message) -> bool:
    """True if response is a referral (NS in authority, no answers).

    RFC 1034 Section 5.3.3, Step 3b: a referral occurs when the
    response "contains a better delegation to the name." In practice
    this means: empty answer section + NS records in the authority
    section pointing to nameservers for a child zone.

    We check for zero answers AND the presence of NS records in
    authority. If the answer section is non-empty, the response is
    an answer (possibly with additional NS authority), not a referral.
    """
    return (
        len(msg.answer) == 0
        and any(rrset.rdtype == dns.rdatatype.NS for rrset in msg.authority)
    )


def get_referral_ns_ips(msg: dns.message.Message) -> list[str]:
    """Extract glue record IPs from additional section for NS referrals.

    RFC 1034 Section 4.2.1: glue records are A (or AAAA) records in the
    additional section whose names match the NS records in the authority
    section. They provide the IP addresses of the referred nameservers
    so we can query them without a separate lookup.

    Glue is required when the NS name falls within the delegated zone
    (e.g., ns1.example.com for example.com) to break the circular
    dependency. When the NS name is in a different zone, glue is
    optional and may be absent — see RFC 7719 Section 6.
    """
    # Collect the NS target names from authority section.
    ns_names: set[dns.name.Name] = set()
    for rrset in msg.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                ns_names.add(rr.target)

    # Match A/AAAA records in additional whose owner name is one of
    # the NS targets. These are the glue records.
    ips: list[str] = []
    for rrset in msg.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if rrset.name in ns_names:
                for rr in rrset:
                    ips.append(rr.address)
    return ips


def get_referral_ns_names(msg: dns.message.Message) -> list[str]:
    """Extract NS names from authority section.

    These are the nameserver names that the current server is referring
    us to. Per RFC 1034 Section 5.3.3, we should query one of these
    nameservers in the next iteration step.
    """
    names: list[str] = []
    for rrset in msg.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                names.append(str(rr.target))
    return names


def get_delegated_zone(step: RecursionStep) -> str | None:
    """Return the DNS zone covered at this resolution step (with trailing dot).

    - Referral: owner name of the NS rrset in authority (e.g. "com.", "example.com.")
    - Answer / NXDOMAIN / other: step.query_name
    - Error / no response: None
    """
    if step.error or step.response is None:
        return None
    if is_referral(step.response):
        for rrset in step.response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                return str(rrset.name)  # e.g. "com."
    return step.query_name  # answer, NXDOMAIN, NODATA


def get_cname_target(msg: dns.message.Message, name: str) -> str | None:
    """If the answer contains a CNAME for name, return the target.

    RFC 1034 Section 3.6.2: a CNAME record means the queried name is
    an alias for another name (the canonical name). The resolver must
    restart the query using the canonical name.

    DNS name comparison is case-insensitive per RFC 1035 Section 2.3.3;
    dnspython handles this via dns.name.Name.__eq__.
    """
    qname = dns.name.from_text(name)
    for rrset in msg.answer:
        if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
            for rr in rrset:
                return str(rr.target)
    return None


def format_rrset(rrset: dns.rrset.RRset) -> list[str]:
    """Format an rrset as human-readable lines in dig-style format.

    Output: NAME  TTL  TYPE  RDATA
    """
    lines = []
    for rr in rrset:
        type_name = dns.rdatatype.to_text(rrset.rdtype)
        lines.append(f"{rrset.name}\t{rrset.ttl}\t{type_name}\t{rr}")
    return lines


@dataclass
class RecursionStep:
    """One step in the iterative resolution process.

    Each step records what query was sent, to which server, and what
    response was received. The explain() method produces human-readable
    output that describes the step in terms of the DNS resolution
    algorithm (RFC 1034 Section 5.3.3).
    """
    step_number: int
    description: str
    server_ip: str
    server_name: str
    query_name: str
    query_type: str
    response: dns.message.Message | None = None
    error: str | None = None
    rtt_ms: float | None = None
    truncated: bool = False

    def explain(self) -> str:
        """Return a human-readable explanation of this recursion step.

        The output categorizes the response as one of:
        - Answer: RFC 1034 Section 5.3.3, Step 3a — the server has
          authoritative data and returns it directly.
        - Referral: RFC 1034 Section 5.3.3, Step 3b — the server
          delegates us to nameservers closer to the answer.
        - Error: RFC 1035 Section 4.1.1 — RCODE indicates a problem
          (NXDOMAIN, SERVFAIL, REFUSED, etc.).
        - Network failure: the server was unreachable.
        """
        lines = [
            f"=== Step {self.step_number}: {self.description} ===",
            f"  Query:  {self.query_name} {self.query_type}",
            f"  Server: {self.server_ip} ({self.server_name})",
        ]
        if self.error:
            lines.append(f"  Error:  {self.error}")
            return "\n".join(lines)

        resp = self.response
        if resp is None:
            lines.append("  (no response)")
            return "\n".join(lines)

        # RFC 1035 Section 4.1.1: RCODE is a 4-bit field in the header
        # indicating the response status.
        rcode = dns.rcode.to_text(resp.rcode())
        lines.append(f"  RCode:  {rcode}")
        if self.truncated:
            lines.append("  Warning: response was truncated (TC flag set); data may be incomplete")

        # Answer section: RFC 1035 Section 4.1.3 — contains RRs that
        # directly answer the question.
        if resp.answer:
            lines.append("  Answers:")
            for rrset in resp.answer:
                for line in format_rrset(rrset):
                    lines.append(f"    {line}")

        # Referral: authority section has NS records pointing to child
        # zone nameservers; additional section may have glue A/AAAA
        # records with their IP addresses.
        if is_referral(resp):
            ns_names = get_referral_ns_names(resp)
            glue_ips = get_referral_ns_ips(resp)
            lines.append(f"  Referral to: {', '.join(ns_names)}")
            if glue_ips:
                lines.append(f"  Glue IPs: {', '.join(glue_ips)}")
            else:
                # No glue — RFC 1034 Section 5.3.3 requires us to
                # resolve the NS name separately before continuing.
                lines.append("  (no glue records — must resolve NS names)")

        # Non-referral authority: typically SOA for NXDOMAIN/NODATA.
        # RFC 2308 Section 2: negative responses include a SOA record
        # in authority to provide the negative caching TTL.
        elif resp.authority:
            lines.append("  Authority:")
            for rrset in resp.authority:
                for line in format_rrset(rrset):
                    lines.append(f"    {line}")

        return "\n".join(lines)
