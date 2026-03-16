"""Iterative DNS resolver — walks the delegation chain from root servers.

No DNS libraries. Uses raw UDP sockets and manual wire format.
"""

from __future__ import annotations

import socket

from .models import DNSPacket, QType, RecursionStep
from .wire import build_query, decode_packet

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


def send_query(name: str, qtype: int, server_ip: str,
               timeout: float = DEFAULT_TIMEOUT) -> DNSPacket:
    """Send a DNS query over UDP and return the parsed response."""
    query = build_query(name, qtype, rd=0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return decode_packet(data)


def resolve(name: str, qtype: int = QType.A,
            timeout: float = DEFAULT_TIMEOUT) -> list[RecursionStep]:
    """Iteratively resolve a domain name, returning every step.

    Starts at a root server and follows referrals until an answer
    (or error) is reached. Each step is recorded as a RecursionStep
    with a human-readable explanation.
    """
    steps: list[RecursionStep] = []
    step_num = 0
    cname_follows = 0

    # Start with the first root server
    current_name = name
    current_qtype = qtype
    server_ip = ROOT_SERVERS[0][1]
    server_name = ROOT_SERVERS[0][0]

    while step_num < MAX_STEPS:
        step_num += 1
        qtype_name = QType.from_int(current_qtype)
        qtype_str = qtype_name.name if isinstance(qtype_name, QType) else f"TYPE{qtype_name}"

        # Determine description for this step
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
            response = send_query(current_name, current_qtype, server_ip, timeout)
        except Exception as exc:
            step.error = str(exc)
            steps.append(step)
            break

        step.response = response
        steps.append(step)

        # Check for error responses
        if response.header.rcode != 0:
            break

        # Got answers?
        if response.answers:
            # Check for CNAME and follow it
            cname_target = response.get_cname_target(current_name)
            if cname_target and current_qtype != QType.CNAME:
                cname_follows += 1
                if cname_follows > MAX_CNAME_FOLLOWS:
                    break
                current_name = cname_target
                # Restart from root for the CNAME target
                server_ip = ROOT_SERVERS[0][1]
                server_name = ROOT_SERVERS[0][0]
                continue
            # We have our answer
            break

        # Referral?
        if response.is_referral():
            glue_ips = response.get_referral_ns_ips()
            if glue_ips:
                # Use the first glue IP
                server_ip = glue_ips[0]
                # Find corresponding NS name
                for r in response.authorities:
                    if r.rtype == QType.NS:
                        server_name = r.rdata
                        break
                continue

            # No glue — need to resolve an NS name first.
            # For simplicity, pick first NS and try to resolve its A record.
            ns_names = [
                r.rdata for r in response.authorities if r.rtype == QType.NS
            ]
            if ns_names:
                ns_steps = resolve(ns_names[0], QType.A, timeout)
                # Find the A record in the final step
                for ns_step in reversed(ns_steps):
                    if ns_step.response and ns_step.response.answers:
                        for r in ns_step.response.answers:
                            if r.rtype == QType.A:
                                server_ip = r.rdata
                                server_name = ns_names[0]
                                break
                        break
                else:
                    # Could not resolve NS
                    break
                continue

            # No NS at all
            break

        # SOA in authority with no referral and no answers = NXDOMAIN / NODATA
        break

    return steps
