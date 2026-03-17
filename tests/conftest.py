"""Pytest configuration for DNScurse tests."""

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype


def _msg(
    *,
    rcode: int = dns.rcode.NOERROR,
    aa: bool = False,
    answer: list[tuple[str, int, int, str]] | None = None,
    authority: list[tuple[str, int, int, str]] | None = None,
    additional: list[tuple[str, int, int, str]] | None = None,
) -> dns.message.Message:
    """Build a dns.message.Message from simplified tuples.

    Each record tuple is (name, rdtype, ttl, rdata_text).
    """
    msg = dns.message.Message()
    msg.flags |= dns.flags.QR
    if aa:
        msg.flags |= dns.flags.AA
    msg.set_rcode(rcode)

    for section, records in [
        (msg.answer, answer or []),
        (msg.authority, authority or []),
        (msg.additional, additional or []),
    ]:
        for name, rdtype, ttl, rdata_text in records:
            rrset = msg.find_rrset(
                section,
                dns.name.from_text(name),
                dns.rdataclass.IN,
                rdtype,
                create=True,
            )
            rrset.update_ttl(ttl)
            rd = dns.rdata.from_text(dns.rdataclass.IN, rdtype, rdata_text)
            rrset.add(rd)

    return msg


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "network: marks tests that require network access (deselect with '-m \"not network\"')",
    )
    config.addinivalue_line(
        "markers",
        "cli: marks tests that exercise the CLI entry point (deselect with '-m \"not cli\"')",
    )
