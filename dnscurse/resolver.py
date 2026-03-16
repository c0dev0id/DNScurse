"""Iterative DNS resolver — walks the delegation chain from root servers.

Uses dnspython for wire format and UDP transport.
The iteration logic (following referrals, CNAMEs) is ours.
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

# IANA root server addresses (IPv4).
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
MAX_STEPS = 30
MAX_CNAME_FOLLOWS = 8


def send_query(name: str, rdtype: int, server_ip: str,
               timeout: float = DEFAULT_TIMEOUT) -> dns.message.Message:
    """Send an iterative DNS query over UDP and return the response."""
    query = dns.message.make_query(name, rdtype)
    query.flags &= ~dns.flags.RD  # clear Recursion Desired for iterative
    return dns.query.udp(query, server_ip, timeout=timeout)


def resolve(name: str, rdtype: int = dns.rdatatype.A,
            timeout: float = DEFAULT_TIMEOUT) -> list[RecursionStep]:
    """Iteratively resolve a domain name, returning every step.

    Starts at a root server and follows referrals until an answer
    (or error) is reached. Each step is recorded as a RecursionStep
    with a human-readable explanation.
    """
    steps: list[RecursionStep] = []
    step_num = 0
    cname_follows = 0

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

        try:
            response = send_query(current_name, current_rdtype, server_ip, timeout)
        except Exception as exc:
            step.error = str(exc)
            steps.append(step)
            break

        step.response = response
        steps.append(step)

        # Check for error responses
        if response.rcode() != dns.rcode.NOERROR:
            break

        # Got answers?
        if response.answer:
            cname_target = get_cname_target(response, current_name)
            if cname_target and current_rdtype != dns.rdatatype.CNAME:
                cname_follows += 1
                if cname_follows > MAX_CNAME_FOLLOWS:
                    break
                current_name = cname_target
                server_ip = ROOT_SERVERS[0][1]
                server_name = ROOT_SERVERS[0][0]
                continue
            # We have our answer
            break

        # Referral?
        if is_referral(response):
            glue_ips = get_referral_ns_ips(response)
            if glue_ips:
                server_ip = glue_ips[0]
                ns_names = get_referral_ns_names(response)
                if ns_names:
                    server_name = ns_names[0]
                continue

            # No glue — resolve NS name first
            ns_names = get_referral_ns_names(response)
            if ns_names:
                ns_steps = resolve(ns_names[0], dns.rdatatype.A, timeout)
                for ns_step in reversed(ns_steps):
                    if ns_step.response and ns_step.response.answer:
                        for rrset in ns_step.response.answer:
                            if rrset.rdtype == dns.rdatatype.A:
                                server_ip = list(rrset)[0].address
                                server_name = ns_names[0]
                                break
                        break
                else:
                    break
                continue

            break

        # SOA in authority with no referral and no answers = NODATA
        break

    return steps
