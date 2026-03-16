"""Data classes for DNS packets, records, and resolution steps."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class QType(IntEnum):
    """DNS query/record types."""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28

    @classmethod
    def from_int(cls, value: int) -> QType | int:
        try:
            return cls(value)
        except ValueError:
            return value


class QClass(IntEnum):
    """DNS query classes."""
    IN = 1


class RCode(IntEnum):
    """DNS response codes."""
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


@dataclass
class DNSHeader:
    """DNS packet header (12 bytes)."""
    id: int = 0
    qr: int = 0          # 0=query, 1=response
    opcode: int = 0
    aa: int = 0           # authoritative answer
    tc: int = 0           # truncated
    rd: int = 0           # recursion desired
    ra: int = 0           # recursion available
    z: int = 0
    rcode: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0


@dataclass
class DNSQuestion:
    """DNS question section entry."""
    name: str
    qtype: int
    qclass: int = QClass.IN


@dataclass
class DNSRecord:
    """A parsed DNS resource record."""
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: str            # Human-readable form of the record data

    def type_name(self) -> str:
        t = QType.from_int(self.rtype)
        return t.name if isinstance(t, QType) else f"TYPE{t}"

    def __str__(self) -> str:
        return f"{self.name}\t{self.ttl}\t{self.type_name()}\t{self.rdata}"


@dataclass
class DNSPacket:
    """A fully parsed DNS packet."""
    header: DNSHeader
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    def is_referral(self) -> bool:
        """True if this is a referral (NS in authority, no answers)."""
        return (
            len(self.answers) == 0
            and any(r.rtype == QType.NS for r in self.authorities)
        )

    def get_referral_ns_ips(self) -> list[str]:
        """Extract glue record IPs from additional section for NS referrals."""
        ns_names = {
            r.rdata for r in self.authorities if r.rtype == QType.NS
        }
        ips = []
        for r in self.additionals:
            if r.rtype in (QType.A, QType.AAAA) and r.name in ns_names:
                ips.append(r.rdata)
        return ips

    def get_cname_target(self, name: str) -> str | None:
        """If the answer contains a CNAME for name, return target."""
        for r in self.answers:
            if r.rtype == QType.CNAME and r.name.lower() == name.lower():
                return r.rdata
        return None


@dataclass
class RecursionStep:
    """One step in the iterative resolution process."""
    step_number: int
    description: str
    server_ip: str
    server_name: str
    query_name: str
    query_type: str
    response: DNSPacket | None = None
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

        lines.append(f"  RCode:  {RCode(resp.header.rcode).name}")

        if resp.answers:
            lines.append("  Answers:")
            for r in resp.answers:
                lines.append(f"    {r}")

        if resp.is_referral():
            ns_names = [
                r.rdata for r in resp.authorities if r.rtype == QType.NS
            ]
            glue_ips = resp.get_referral_ns_ips()
            lines.append(f"  Referral to: {', '.join(ns_names)}")
            if glue_ips:
                lines.append(f"  Glue IPs: {', '.join(glue_ips)}")
            else:
                lines.append("  (no glue records — must resolve NS names)")

        if resp.authorities and not resp.is_referral():
            lines.append("  Authority:")
            for r in resp.authorities:
                lines.append(f"    {r}")

        return "\n".join(lines)
