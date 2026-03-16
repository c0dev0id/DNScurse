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
    """True if response is a referral (NS in authority, no answers)."""
    return (
        len(msg.answer) == 0
        and any(rrset.rdtype == dns.rdatatype.NS for rrset in msg.authority)
    )


def get_referral_ns_ips(msg: dns.message.Message) -> list[str]:
    """Extract glue record IPs from additional section for NS referrals."""
    ns_names: set[dns.name.Name] = set()
    for rrset in msg.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                ns_names.add(rr.target)

    ips: list[str] = []
    for rrset in msg.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if rrset.name in ns_names:
                for rr in rrset:
                    ips.append(rr.address)
    return ips


def get_referral_ns_names(msg: dns.message.Message) -> list[str]:
    """Extract NS names from authority section."""
    names: list[str] = []
    for rrset in msg.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                names.append(str(rr.target))
    return names


def get_cname_target(msg: dns.message.Message, name: str) -> str | None:
    """If the answer contains a CNAME for name, return the target."""
    qname = dns.name.from_text(name)
    for rrset in msg.answer:
        if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
            for rr in rrset:
                return str(rr.target)
    return None


def format_rrset(rrset: dns.rrset.RRset) -> list[str]:
    """Format an rrset as human-readable lines."""
    lines = []
    for rr in rrset:
        type_name = dns.rdatatype.to_text(rrset.rdtype)
        lines.append(f"{rrset.name}\t{rrset.ttl}\t{type_name}\t{rr}")
    return lines


@dataclass
class RecursionStep:
    """One step in the iterative resolution process."""
    step_number: int
    description: str
    server_ip: str
    server_name: str
    query_name: str
    query_type: str
    response: dns.message.Message | None = None
    error: str | None = None

    def explain(self) -> str:
        """Return a human-readable explanation of this recursion step."""
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

        rcode = dns.rcode.to_text(resp.rcode())
        lines.append(f"  RCode:  {rcode}")

        if resp.answer:
            lines.append("  Answers:")
            for rrset in resp.answer:
                for line in format_rrset(rrset):
                    lines.append(f"    {line}")

        if is_referral(resp):
            ns_names = get_referral_ns_names(resp)
            glue_ips = get_referral_ns_ips(resp)
            lines.append(f"  Referral to: {', '.join(ns_names)}")
            if glue_ips:
                lines.append(f"  Glue IPs: {', '.join(glue_ips)}")
            else:
                lines.append("  (no glue records — must resolve NS names)")

        elif resp.authority:
            lines.append("  Authority:")
            for rrset in resp.authority:
                for line in format_rrset(rrset):
                    lines.append(f"    {line}")

        return "\n".join(lines)
