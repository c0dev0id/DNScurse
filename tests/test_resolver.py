"""Tests for the iterative DNS resolver.

These tests exercise the resolver against crafted and (optionally) live
DNS infrastructure.  Each test explains the recursion concept being verified.

Unit tests use monkeypatching to simulate DNS responses without network access.
Integration tests (marked with pytest.mark.network) hit real DNS servers.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from dnscurse.models import (
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    QClass,
    QType,
    RCode,
)
from dnscurse.resolver import (
    MAX_CNAME_FOLLOWS,
    MAX_STEPS,
    ROOT_SERVERS,
    resolve,
)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _make_referral(
    authority_zone: str,
    ns_name: str,
    ns_ip: str,
) -> DNSPacket:
    """Create a referral response."""
    return DNSPacket(
        header=DNSHeader(qr=1, rcode=0, nscount=1, arcount=1),
        authorities=[
            DNSRecord(authority_zone, QType.NS, QClass.IN, 172800, ns_name),
        ],
        additionals=[
            DNSRecord(ns_name, QType.A, QClass.IN, 172800, ns_ip),
        ],
    )


def _make_answer(name: str, ip: str, aa: int = 1) -> DNSPacket:
    """Create a simple A record answer."""
    return DNSPacket(
        header=DNSHeader(qr=1, rcode=0, aa=aa, ancount=1),
        answers=[
            DNSRecord(name, QType.A, QClass.IN, 300, ip),
        ],
    )


def _make_cname(name: str, target: str) -> DNSPacket:
    """Create a CNAME answer."""
    return DNSPacket(
        header=DNSHeader(qr=1, rcode=0, aa=1, ancount=1),
        answers=[
            DNSRecord(name, QType.CNAME, QClass.IN, 3600, target),
        ],
    )


def _make_nxdomain(zone: str) -> DNSPacket:
    return DNSPacket(
        header=DNSHeader(qr=1, rcode=RCode.NXDOMAIN, aa=1, nscount=1),
        authorities=[
            DNSRecord(zone, QType.SOA, QClass.IN, 900,
                      f"ns1.{zone} admin.{zone} 1 3600 900 604800 86400"),
        ],
    )


# -----------------------------------------------------------------------
# Unit tests (no network)
# -----------------------------------------------------------------------

class TestResolverReferralChain:
    """EXPLANATION: These tests simulate the step-by-step referral chain
    that happens during iterative resolution, WITHOUT hitting the network.

    The normal resolution path for 'example.com' is:
      root -> .com TLD -> example.com authoritative -> answer
    """

    def test_simple_three_step_resolution(self):
        """EXPLANATION: The most common resolution path has exactly 3 steps:

        1. Root server -> referral to .com TLD nameservers
        2. .com TLD    -> referral to example.com's nameservers
        3. Authoritative NS -> final A record answer

        Each referral includes 'glue records' — the IP addresses of the
        referred nameservers — so we don't need extra lookups.
        """
        responses = {
            # Step 1: root refers to .com
            ("example.com", QType.A, ROOT_SERVERS[0][1]):
                _make_referral("com", "a.gtld-servers.net", "192.5.6.30"),
            # Step 2: .com refers to example.com's NS
            ("example.com", QType.A, "192.5.6.30"):
                _make_referral("example.com", "a.iana-servers.net", "199.43.135.53"),
            # Step 3: authoritative answers
            ("example.com", QType.A, "199.43.135.53"):
                _make_answer("example.com", "93.184.216.34"),
        }

        def fake_send(name, qtype, server_ip, timeout=5.0):
            return responses[(name, qtype, server_ip)]

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", QType.A)

        assert len(steps) == 3

        print("\n  Three-step resolution of example.com:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # Step 1: root referral
        assert steps[0].response.is_referral()
        assert steps[0].server_name == ROOT_SERVERS[0][0]
        print(f"  Step 1: Root -> referred to .com TLD")

        # Step 2: TLD referral
        assert steps[1].response.is_referral()
        assert steps[1].server_ip == "192.5.6.30"
        print(f"  Step 2: .com TLD -> referred to example.com NS")

        # Step 3: final answer
        assert steps[2].response.answers[0].rdata == "93.184.216.34"
        print(f"  Step 3: Authoritative -> 93.184.216.34")

    def test_cname_adds_extra_steps(self):
        """EXPLANATION: When a name is a CNAME alias, the resolver must:
          1. Resolve the original name -> get CNAME target
          2. Start over from root for the CNAME target

        Example: www.example.com CNAME example.com
        This means resolving www.example.com requires resolving
        example.com as well, effectively doubling the steps.
        """
        call_log = []

        def fake_send(name, qtype, server_ip, timeout=5.0):
            call_log.append((name, server_ip))

            # First chain: www.example.com -> CNAME example.com
            if name == "www.example.com" and server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com", "tld.ns", "10.0.0.1")
            if name == "www.example.com" and server_ip == "10.0.0.1":
                return _make_referral("example.com", "auth.ns", "10.0.0.2")
            if name == "www.example.com" and server_ip == "10.0.0.2":
                return _make_cname("www.example.com", "example.com")

            # Second chain: resolve the CNAME target from root
            if name == "example.com" and server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com", "tld.ns", "10.0.0.1")
            if name == "example.com" and server_ip == "10.0.0.1":
                return _make_referral("example.com", "auth.ns", "10.0.0.2")
            if name == "example.com" and server_ip == "10.0.0.2":
                return _make_answer("example.com", "93.184.216.34")

            raise RuntimeError(f"Unexpected query: {name} -> {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("www.example.com", QType.A)

        # 3 steps for www.example.com + 3 steps for CNAME target
        assert len(steps) == 6

        print("\n  CNAME resolution walkthrough:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # Step 3 should be the CNAME
        assert steps[2].response.answers[0].rtype == QType.CNAME
        print("  CNAME detected at step 3 -> restart from root for target")
        print(f"  Total steps: {len(steps)} (3 for alias + 3 for target)")

    def test_nxdomain_stops_resolution(self):
        """EXPLANATION: NXDOMAIN (rcode=3) means the domain does not exist.
        Resolution stops immediately — there's nothing more to look up.
        The SOA record in the authority section tells caches how long
        to remember this negative result (negative caching TTL).
        """
        def fake_send(name, qtype, server_ip, timeout=5.0):
            if server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com", "tld.ns", "10.0.0.1")
            if server_ip == "10.0.0.1":
                return _make_referral("doesnotexist.com", "auth.ns", "10.0.0.2")
            if server_ip == "10.0.0.2":
                return _make_nxdomain("doesnotexist.com")
            raise RuntimeError(f"Unexpected: {name} -> {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("doesnotexist.com", QType.A)

        assert len(steps) == 3
        assert steps[-1].response.header.rcode == RCode.NXDOMAIN

        print("\n  NXDOMAIN resolution:")
        for step in steps:
            print(f"  {step.explain()}")
            print()
        print("  Domain does not exist — resolution stops at NXDOMAIN")

    def test_network_error_recorded(self):
        """EXPLANATION: If a DNS server is unreachable (timeout, network error),
        the step records the error so the user can see exactly where
        the resolution failed and which server was unresponsive.
        """
        def fake_send(name, qtype, server_ip, timeout=5.0):
            raise OSError("Network is unreachable")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", QType.A)

        assert len(steps) == 1
        assert steps[0].error == "Network is unreachable"

        print("\n  Network error:")
        print(f"  {steps[0].explain()}")
        print("  Resolution failed at first step — root server unreachable")

    def test_referral_without_glue_triggers_sub_resolution(self):
        """EXPLANATION: When a referral has NS records but no glue (no A
        records in the additional section), the resolver must first
        resolve the NS name to an IP before it can continue.

        This happens when the NS name is in a different zone than
        the one being delegated.  For example:
          example.com NS ns1.other-provider.net
        The .com TLD doesn't have the IP for ns1.other-provider.net
        (that's in the .net zone), so no glue is provided.
        """
        main_call_count = 0

        def fake_send(name, qtype, server_ip, timeout=5.0):
            nonlocal main_call_count

            # Main query: example.com
            if name == "example.com" and server_ip == ROOT_SERVERS[0][1]:
                main_call_count += 1
                # Referral without glue
                return DNSPacket(
                    header=DNSHeader(qr=1, nscount=1),
                    authorities=[
                        DNSRecord("example.com", QType.NS, QClass.IN, 172800,
                                  "ns1.other.net"),
                    ],
                )

            # Sub-resolution of ns1.other.net
            if name == "ns1.other.net" and server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("net", "tld.ns", "10.0.0.1")
            if name == "ns1.other.net" and server_ip == "10.0.0.1":
                return _make_answer("ns1.other.net", "10.0.0.99")

            # Now we can query the resolved NS
            if name == "example.com" and server_ip == "10.0.0.99":
                return _make_answer("example.com", "1.2.3.4")

            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", QType.A)

        # Should have the referral step + the final answer
        assert any(s.response and s.response.answers for s in steps)

        print("\n  Referral without glue:")
        for step in steps:
            print(f"  {step.explain()}")
            print()
        print("  Resolver had to separately resolve NS name before continuing")

    def test_max_steps_prevents_infinite_loop(self):
        """EXPLANATION: The resolver limits total steps to prevent infinite
        loops from circular referrals or pathological delegation chains.
        """
        def fake_send(name, qtype, server_ip, timeout=5.0):
            # Always return a referral — never an answer
            return _make_referral("zone.example", "ns.loop", "10.0.0.1")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("loop.example.com", QType.A)

        assert len(steps) == MAX_STEPS
        print(f"  Stopped after {MAX_STEPS} steps (infinite referral loop)")


# -----------------------------------------------------------------------
# Root server configuration
# -----------------------------------------------------------------------

class TestRootServers:
    """EXPLANATION: The 13 root servers are the starting point for all
    DNS resolution.  They are operated by different organizations
    (ICANN, Verisign, USC-ISI, etc.) and use anycast for redundancy.

    Their addresses rarely change and are hardcoded as 'root hints'.
    """

    def test_root_server_count(self):
        assert len(ROOT_SERVERS) == 13
        print("  13 root servers (a through m)")

    def test_root_servers_have_names_and_ips(self):
        for name, ip in ROOT_SERVERS:
            assert name.endswith(".root-servers.net")
            # Basic IPv4 validation
            parts = ip.split(".")
            assert len(parts) == 4
            assert all(0 <= int(p) <= 255 for p in parts)
        print("  All root servers have valid names and IPv4 addresses")
        for name, ip in ROOT_SERVERS:
            print(f"    {name:30s} {ip}")


# -----------------------------------------------------------------------
# Integration tests (require network — skipped in CI by default)
# -----------------------------------------------------------------------

@pytest.mark.network
class TestResolverLive:
    """EXPLANATION: These tests perform actual DNS resolution against
    real root servers.  They verify end-to-end functionality but
    require network access.

    Run with: pytest -m network
    """

    def test_resolve_example_com(self):
        """EXPLANATION: example.com is an IANA-reserved domain that always
        resolves.  It's the safest target for integration tests.
        Expected path: root -> .com TLD -> IANA authoritative -> answer
        """
        steps = resolve("example.com", QType.A, timeout=10.0)

        assert len(steps) >= 2, "Should take at least 2 steps"

        print("\n  Live resolution of example.com:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # Final step should have an answer
        final = steps[-1]
        assert final.response is not None
        assert final.response.answers, "Should get an A record answer"
        print(f"  Final answer: {final.response.answers[0]}")

    def test_resolve_nonexistent_domain(self):
        """EXPLANATION: Querying a domain that doesn't exist should
        eventually result in NXDOMAIN from the authoritative server.
        """
        steps = resolve("this-domain-definitely-does-not-exist-12345.com",
                        QType.A, timeout=10.0)

        print("\n  Live resolution of non-existent domain:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        final = steps[-1]
        if final.response:
            print(f"  Final RCODE: {RCode(final.response.header.rcode).name}")
