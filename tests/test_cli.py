"""Tests for the CLI entry point (_cli.py).

These tests exercise the CLI as an installed tool — argument parsing,
output formatting, exit codes, and error handling. The resolver is
mocked so no network access is needed.

Run CLI tests only:  pytest -m cli
Skip CLI tests:      pytest -m "not cli"
"""

from __future__ import annotations

from unittest.mock import patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import pytest

from dnscurse._cli import main
from dnscurse.models import RecursionStep

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _msg(
    *,
    rcode: int = dns.rcode.NOERROR,
    aa: bool = False,
    answer: list[tuple[str, int, int, str]] | None = None,
    authority: list[tuple[str, int, int, str]] | None = None,
    additional: list[tuple[str, int, int, str]] | None = None,
) -> dns.message.Message:
    """Build a dns.message.Message from simplified tuples."""
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


def _three_step_resolution() -> list[RecursionStep]:
    """Return a typical 3-step resolution for example.com."""
    return [
        RecursionStep(
            step_number=1,
            description="Query root server for example.com",
            server_ip="198.41.0.4",
            server_name="a.root-servers.net",
            query_name="example.com",
            query_type="A",
            rtt_ms=12.4,
            response=_msg(
                authority=[("com.", dns.rdatatype.NS, 172800, "a.gtld-servers.net.")],
                additional=[("a.gtld-servers.net.", dns.rdatatype.A, 172800, "192.5.6.30")],
            ),
        ),
        RecursionStep(
            step_number=2,
            description="Follow referral — query a.gtld-servers.net for example.com",
            server_ip="192.5.6.30",
            server_name="a.gtld-servers.net",
            query_name="example.com",
            query_type="A",
            rtt_ms=18.7,
            response=_msg(
                authority=[("example.com.", dns.rdatatype.NS, 172800, "a.iana-servers.net.")],
                additional=[("a.iana-servers.net.", dns.rdatatype.A, 172800, "199.43.135.53")],
            ),
        ),
        RecursionStep(
            step_number=3,
            description="Follow referral — query a.iana-servers.net for example.com",
            server_ip="199.43.135.53",
            server_name="a.iana-servers.net",
            query_name="example.com",
            query_type="A",
            rtt_ms=9.1,
            response=_msg(
                aa=True,
                answer=[("example.com.", dns.rdatatype.A, 3600, "93.184.216.34")],
            ),
        ),
    ]


# -----------------------------------------------------------------------
# CLI tests
# -----------------------------------------------------------------------

@pytest.mark.cli
class TestCLIArgumentParsing:
    """Tests for CLI argument parsing and validation."""

    def test_missing_domain_exits_with_error(self):
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code != 0

    def test_invalid_type_exits_with_error(self):
        with pytest.raises(SystemExit):
            main(["-t", "BOGUS", "example.com"])

    def test_invalid_domain_returns_1(self, capsys):
        rc = main(["..invalid" * 50])
        assert rc == 1
        captured = capsys.readouterr()
        assert "invalid domain" in captured.err.lower() or "error" in captured.err.lower()


@pytest.mark.cli
class TestCLIBlockOutput:
    """Tests for the default block output mode."""

    def test_successful_resolution_prints_answer(self, capsys):
        steps = _three_step_resolution()

        with patch("dnscurse._cli.resolve", return_value=steps):
            rc = main(["example.com"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "a.root-servers.net" in out
        assert "a.gtld-servers.net" in out
        assert "a.iana-servers.net" in out
        assert "93.184.216.34" in out
        assert "3 steps" in out

    def test_type_flag_passed_to_resolver(self):
        steps = [
            RecursionStep(
                step_number=1,
                description="Query root server",
                server_ip="198.41.0.4",
                server_name="a.root-servers.net",
                query_name="example.com",
                query_type="AAAA",
                rtt_ms=10.0,
                response=_msg(
                    aa=True,
                    answer=[("example.com.", dns.rdatatype.AAAA, 300,
                             "2606:2800:21f:cb07:6820:80da:af6b:8b2c")],
                ),
            ),
        ]

        with patch("dnscurse._cli.resolve", return_value=steps) as mock_resolve:
            main(["-t", "AAAA", "example.com"])

        _, kwargs = mock_resolve.call_args
        args = mock_resolve.call_args[0]
        assert args[0] == "example.com"
        assert args[1] == dns.rdatatype.AAAA

    def test_timeout_flag_passed_to_resolver(self):
        steps = _three_step_resolution()

        with patch("dnscurse._cli.resolve", return_value=steps) as mock_resolve:
            main(["--timeout", "10", "example.com"])

        assert mock_resolve.call_args[1]["timeout"] == 10.0

    def test_nxdomain_output(self, capsys):
        steps = [
            RecursionStep(
                step_number=1,
                description="Query root",
                server_ip="198.41.0.4",
                server_name="a.root-servers.net",
                query_name="nope.example.com",
                query_type="A",
                rtt_ms=10.0,
                response=_msg(
                    rcode=dns.rcode.NXDOMAIN,
                    aa=True,
                    authority=[(
                        "example.com.", dns.rdatatype.SOA, 900,
                        "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400",
                    )],
                ),
            ),
        ]

        with patch("dnscurse._cli.resolve", return_value=steps):
            rc = main(["nope.example.com"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "NXDOMAIN" in out

    def test_error_step_output(self, capsys):
        steps = [
            RecursionStep(
                step_number=1,
                description="Query root",
                server_ip="198.41.0.4",
                server_name="a.root-servers.net",
                query_name="example.com",
                query_type="A",
                error="Network is unreachable",
            ),
        ]

        with patch("dnscurse._cli.resolve", return_value=steps):
            rc = main(["example.com"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "Network is unreachable" in out

    def test_no_steps_returns_1(self, capsys):
        with patch("dnscurse._cli.resolve", return_value=[]):
            rc = main(["example.com"])

        assert rc == 1
        out = capsys.readouterr().out
        assert "No resolution steps" in out


@pytest.mark.cli
class TestCLICompactOutput:
    """Tests for the compact tree output mode (-c)."""

    def test_compact_flag_produces_tree(self, capsys):
        steps = _three_step_resolution()

        with patch("dnscurse._cli.resolve", return_value=steps):
            rc = main(["-c", "example.com"])

        assert rc == 0
        out = capsys.readouterr().out
        # Tree output should contain the zone delegation markers
        assert "a.root-servers.net" in out
        assert "a.gtld-servers.net" in out
        assert "93.184.216.34" in out


@pytest.mark.cli
class TestCLIExitCodes:
    """Verify exit codes for various scenarios."""

    def test_success_returns_0(self):
        steps = _three_step_resolution()
        with patch("dnscurse._cli.resolve", return_value=steps):
            assert main(["example.com"]) == 0

    def test_no_steps_returns_1(self):
        with patch("dnscurse._cli.resolve", return_value=[]):
            assert main(["example.com"]) == 1
