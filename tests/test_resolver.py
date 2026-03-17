"""Tests for the iterative DNS resolver.

These tests exercise the resolver against crafted and (optionally) live
DNS infrastructure.  Each test explains the recursion concept being verified.

Unit tests use monkeypatching to simulate DNS responses without network access.
Integration tests (marked with pytest.mark.network) hit real DNS servers.
"""

from __future__ import annotations

from unittest.mock import patch

import dns.rcode
import dns.rdatatype
import pytest

from dnscurse.models import is_referral
from dnscurse.resolver import (
    MAX_CNAME_FOLLOWS,
    MAX_STEPS,
    ROOT_SERVERS,
    resolve,
)

from .conftest import _msg

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_referral(zone: str, ns_name: str, ns_ip: str) -> dns.message.Message:
    """Create a referral response."""
    return _msg(
        authority=[(zone, dns.rdatatype.NS, 172800, ns_name)],
        additional=[(ns_name, dns.rdatatype.A, 172800, ns_ip)],
    )


def _make_answer(name: str, ip: str) -> dns.message.Message:
    """Create a simple A record answer."""
    return _msg(aa=True, answer=[(name, dns.rdatatype.A, 300, ip)])


def _make_cname(name: str, target: str) -> dns.message.Message:
    """Create a CNAME answer."""
    return _msg(aa=True, answer=[(name, dns.rdatatype.CNAME, 3600, target)])


def _make_nxdomain(zone: str) -> dns.message.Message:
    return _msg(
        rcode=dns.rcode.NXDOMAIN,
        aa=True,
        authority=[(
            zone, dns.rdatatype.SOA, 900,
            f"ns1.{zone} admin.{zone} 1 3600 900 604800 86400",
        )],
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
            ("example.com", dns.rdatatype.A, ROOT_SERVERS[0][1]):
                _make_referral("com.", "a.gtld-servers.net.", "192.5.6.30"),
            ("example.com", dns.rdatatype.A, "192.5.6.30"):
                _make_referral("example.com.", "a.iana-servers.net.", "199.43.135.53"),
            ("example.com", dns.rdatatype.A, "199.43.135.53"):
                _make_answer("example.com.", "93.184.216.34"),
        }

        def fake_send(name, rdtype, server_ip, timeout=5.0):
            return responses[(name, rdtype, server_ip)]

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

        assert len(steps) == 3

        print("\n  Three-step resolution of example.com:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        assert is_referral(steps[0].response)
        assert steps[0].server_name == ROOT_SERVERS[0][0]
        print("  Step 1: Root -> referred to .com TLD")

        assert is_referral(steps[1].response)
        assert steps[1].server_ip == "192.5.6.30"
        print("  Step 2: .com TLD -> referred to example.com NS")

        assert steps[2].response.answer
        print("  Step 3: Authoritative -> answer")

    def test_cname_adds_extra_steps(self):
        """EXPLANATION: When a name is a CNAME alias, the resolver must:
          1. Resolve the original name -> get CNAME target
          2. Start over from root for the CNAME target

        Example: www.example.com CNAME example.com
        This means resolving www.example.com requires resolving
        example.com as well, effectively doubling the steps.
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            # First chain: www.example.com -> CNAME example.com
            if name == "www.example.com" and server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com.", "tld.ns.", "10.0.0.1")
            if name == "www.example.com" and server_ip == "10.0.0.1":
                return _make_referral("example.com.", "auth.ns.", "10.0.0.2")
            if name == "www.example.com" and server_ip == "10.0.0.2":
                return _make_cname("www.example.com.", "example.com.")

            # Second chain: resolve the CNAME target from root
            if name == "example.com." and server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com.", "tld.ns.", "10.0.0.1")
            if name == "example.com." and server_ip == "10.0.0.1":
                return _make_referral("example.com.", "auth.ns.", "10.0.0.2")
            if name == "example.com." and server_ip == "10.0.0.2":
                return _make_answer("example.com.", "93.184.216.34")

            raise RuntimeError(f"Unexpected query: {name} -> {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("www.example.com", dns.rdatatype.A)

        # 3 steps for www.example.com + 3 steps for CNAME target
        assert len(steps) == 6

        print("\n  CNAME resolution walkthrough:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # Step 3 should be the CNAME
        assert any(
            rrset.rdtype == dns.rdatatype.CNAME
            for rrset in steps[2].response.answer
        )
        print("  CNAME detected at step 3 -> restart from root for target")
        print(f"  Total steps: {len(steps)} (3 for alias + 3 for target)")

    def test_nxdomain_stops_resolution(self):
        """EXPLANATION: NXDOMAIN (rcode=3) means the domain does not exist.
        Resolution stops immediately — there's nothing more to look up.
        The SOA record in the authority section tells caches how long
        to remember this negative result (negative caching TTL).
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            if server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com.", "tld.ns.", "10.0.0.1")
            if server_ip == "10.0.0.1":
                return _make_referral("doesnotexist.com.", "auth.ns.", "10.0.0.2")
            if server_ip == "10.0.0.2":
                return _make_nxdomain("doesnotexist.com.")
            raise RuntimeError(f"Unexpected: {name} -> {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("doesnotexist.com", dns.rdatatype.A)

        assert len(steps) == 3
        assert steps[-1].response.rcode() == dns.rcode.NXDOMAIN

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
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            raise OSError("Network is unreachable")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

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
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            # Main query: example.com — referral without glue
            if name == "example.com" and server_ip == ROOT_SERVERS[0][1]:
                return _msg(
                    authority=[("example.com.", dns.rdatatype.NS, 172800, "ns1.other.net.")],
                )

            # Sub-resolution of ns1.other.net
            if name == "ns1.other.net." and server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("net.", "tld.ns.", "10.0.0.1")
            if name == "ns1.other.net." and server_ip == "10.0.0.1":
                return _make_answer("ns1.other.net.", "10.0.0.99")

            # Now we can query the resolved NS
            if name == "example.com" and server_ip == "10.0.0.99":
                return _make_answer("example.com.", "1.2.3.4")

            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

        assert any(s.response and s.response.answer for s in steps)

        print("\n  Referral without glue:")
        for step in steps:
            print(f"  {step.explain()}")
            print()
        print("  Resolver had to separately resolve NS name before continuing")

    def test_cname_loop_is_bounded(self):
        """EXPLANATION: A CNAME loop (A -> B -> A -> B -> ...) must not
        cause infinite resolution. The resolver tracks how many CNAME
        redirects have been followed and stops at MAX_CNAME_FOLLOWS.

        Each CNAME follow restarts resolution from root, so the total
        step count is MAX_CNAME_FOLLOWS * steps_per_chain.
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            # Both names resolve to a CNAME pointing at each other
            if server_ip == ROOT_SERVERS[0][1]:
                return _make_referral("com.", "tld.ns.", "10.0.0.1")
            if server_ip == "10.0.0.1":
                return _make_referral("example.com.", "auth.ns.", "10.0.0.2")
            if server_ip == "10.0.0.2":
                if name in ("loop-a.example.com", "loop-a.example.com."):
                    return _make_cname("loop-a.example.com.", "loop-b.example.com.")
                return _make_cname("loop-b.example.com.", "loop-a.example.com.")
            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("loop-a.example.com", dns.rdatatype.A)

        # Each follow takes 3 steps (root + TLD + auth); stops after MAX_CNAME_FOLLOWS
        assert len(steps) == (MAX_CNAME_FOLLOWS + 1) * 3
        print(f"\n  CNAME loop stopped after {MAX_CNAME_FOLLOWS} follows "
              f"({len(steps)} total steps)")

    def test_max_steps_prevents_infinite_loop(self):
        """EXPLANATION: The resolver limits total steps to prevent infinite
        loops from circular referrals or pathological delegation chains.
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            return _make_referral("zone.example.", "ns.loop.", "10.0.0.1")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("loop.example.com", dns.rdatatype.A)

        assert len(steps) == MAX_STEPS
        print(f"  Stopped after {MAX_STEPS} steps (infinite referral loop)")


# -----------------------------------------------------------------------
# SERVFAIL / REFUSED sibling failover
# -----------------------------------------------------------------------

class TestSiblingFailover:
    """EXPLANATION: RFC 1034 Section 5.3.3 says when a server fails, the
    resolver should "mark it as bad and select a new server." When a
    referral provides multiple NS records with glue, we should try the
    next sibling NS if the first returns SERVFAIL or REFUSED, rather
    than giving up immediately.
    """

    def test_servfail_tries_sibling_ns(self):
        """EXPLANATION: When a referred NS returns SERVFAIL, the resolver
        tries the next NS from the same referral. This is critical for
        resilience — one broken nameserver shouldn't prevent resolution
        if siblings are healthy.

        Scenario:
          1. Root -> referral to .com with two NS: ns1 (10.0.0.1) and ns2 (10.0.0.2)
          2. ns1 returns SERVFAIL
          3. Resolver retries with ns2
          4. ns2 -> referral to example.com NS
          5. Authoritative -> answer
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            if server_ip == ROOT_SERVERS[0][1]:
                return _msg(
                    authority=[
                        ("com.", dns.rdatatype.NS, 172800, "ns1.com."),
                        ("com.", dns.rdatatype.NS, 172800, "ns2.com."),
                    ],
                    additional=[
                        ("ns1.com.", dns.rdatatype.A, 172800, "10.0.0.1"),
                        ("ns2.com.", dns.rdatatype.A, 172800, "10.0.0.2"),
                    ],
                )
            if server_ip == "10.0.0.1":
                return _msg(rcode=dns.rcode.SERVFAIL)
            if server_ip == "10.0.0.2":
                return _make_referral("example.com.", "ns.example.com.", "10.0.0.3")
            if server_ip == "10.0.0.3":
                return _make_answer("example.com.", "1.2.3.4")
            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

        print("\n  SERVFAIL sibling failover:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # Step 1: root referral, Step 2: ns1 SERVFAIL, Step 3: ns2 referral, Step 4: answer
        assert len(steps) == 4
        assert steps[1].response.rcode() == dns.rcode.SERVFAIL
        assert steps[1].server_ip == "10.0.0.1"
        assert steps[2].server_ip == "10.0.0.2"
        assert steps[3].response.answer
        print("  ns1 returned SERVFAIL -> tried ns2 -> success")

    def test_refused_tries_sibling_ns(self):
        """EXPLANATION: REFUSED (rcode=5) is a policy refusal — the server
        exists but won't answer our query. Like SERVFAIL, we should try
        sibling NS from the referral before giving up.
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            if server_ip == ROOT_SERVERS[0][1]:
                return _msg(
                    authority=[
                        ("com.", dns.rdatatype.NS, 172800, "ns1.com."),
                        ("com.", dns.rdatatype.NS, 172800, "ns2.com."),
                    ],
                    additional=[
                        ("ns1.com.", dns.rdatatype.A, 172800, "10.0.0.1"),
                        ("ns2.com.", dns.rdatatype.A, 172800, "10.0.0.2"),
                    ],
                )
            if server_ip == "10.0.0.1":
                return _msg(rcode=dns.rcode.REFUSED)
            if server_ip == "10.0.0.2":
                return _make_answer("example.com.", "1.2.3.4")
            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

        assert len(steps) == 3
        assert steps[1].response.rcode() == dns.rcode.REFUSED
        assert steps[2].response.answer
        print("\n  REFUSED -> tried sibling -> got answer")

    def test_all_siblings_fail_then_stops(self):
        """EXPLANATION: If ALL sibling NS from a referral return SERVFAIL,
        resolution stops. The last failing response is the final step.
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            if server_ip == ROOT_SERVERS[0][1]:
                return _msg(
                    authority=[
                        ("com.", dns.rdatatype.NS, 172800, "ns1.com."),
                        ("com.", dns.rdatatype.NS, 172800, "ns2.com."),
                        ("com.", dns.rdatatype.NS, 172800, "ns3.com."),
                    ],
                    additional=[
                        ("ns1.com.", dns.rdatatype.A, 172800, "10.0.0.1"),
                        ("ns2.com.", dns.rdatatype.A, 172800, "10.0.0.2"),
                        ("ns3.com.", dns.rdatatype.A, 172800, "10.0.0.3"),
                    ],
                )
            # All three siblings fail
            return _msg(rcode=dns.rcode.SERVFAIL)

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

        print("\n  All siblings SERVFAIL:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # 1 root + 3 SERVFAIL attempts
        assert len(steps) == 4
        assert all(
            steps[i].response.rcode() == dns.rcode.SERVFAIL
            for i in range(1, 4)
        )
        print("  All 3 siblings returned SERVFAIL -> resolution stopped")

    def test_nxdomain_does_not_try_siblings(self):
        """EXPLANATION: NXDOMAIN is authoritative — the domain does not
        exist. Trying a sibling NS won't change this, so we stop
        immediately without failover.
        """
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            if server_ip == ROOT_SERVERS[0][1]:
                return _msg(
                    authority=[
                        ("com.", dns.rdatatype.NS, 172800, "ns1.com."),
                        ("com.", dns.rdatatype.NS, 172800, "ns2.com."),
                    ],
                    additional=[
                        ("ns1.com.", dns.rdatatype.A, 172800, "10.0.0.1"),
                        ("ns2.com.", dns.rdatatype.A, 172800, "10.0.0.2"),
                    ],
                )
            if server_ip == "10.0.0.1":
                return _make_nxdomain("com.")
            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("nope.com", dns.rdatatype.A)

        # Should NOT try ns2 — NXDOMAIN is definitive
        assert len(steps) == 2
        assert steps[1].response.rcode() == dns.rcode.NXDOMAIN
        print("\n  NXDOMAIN — no sibling failover (authoritative negative)")

    def test_network_error_tries_sibling_ns(self):
        """EXPLANATION: Network failures (timeout, unreachable) should also
        trigger sibling failover. RFC 1034 Section 5.3.3 treats network
        errors the same as server failures for server selection.
        """
        call_count = 0

        def fake_send(name, rdtype, server_ip, timeout=5.0):
            nonlocal call_count
            call_count += 1
            if server_ip == ROOT_SERVERS[0][1]:
                return _msg(
                    authority=[
                        ("com.", dns.rdatatype.NS, 172800, "ns1.com."),
                        ("com.", dns.rdatatype.NS, 172800, "ns2.com."),
                    ],
                    additional=[
                        ("ns1.com.", dns.rdatatype.A, 172800, "10.0.0.1"),
                        ("ns2.com.", dns.rdatatype.A, 172800, "10.0.0.2"),
                    ],
                )
            if server_ip == "10.0.0.1":
                raise OSError("Connection timed out")
            if server_ip == "10.0.0.2":
                return _make_answer("example.com.", "1.2.3.4")
            raise RuntimeError(f"Unexpected: {name} @ {server_ip}")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", dns.rdatatype.A)

        print("\n  Network error sibling failover:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        assert len(steps) == 3
        assert steps[1].error == "Connection timed out"
        assert steps[2].response.answer
        print("  ns1 timed out -> tried ns2 -> got answer")


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
            parts = ip.split(".")
            assert len(parts) == 4
            assert all(0 <= int(p) <= 255 for p in parts)
        print("  All root servers have valid names and IPv4 addresses")
        for name, ip in ROOT_SERVERS:
            print(f"    {name:30s} {ip}")


# -----------------------------------------------------------------------
# Public API surface
# -----------------------------------------------------------------------

class TestPublicAPI:
    """Tests for the library-facing public API (top-level imports, string
    record types) so other projects can use DNScurse as a dependency."""

    def test_resolve_accepts_string_rdtype(self):
        """resolve() accepts a string like 'A' instead of dns.rdatatype.A."""
        responses = {
            ("example.com", dns.rdatatype.A, ROOT_SERVERS[0][1]):
                _make_referral("com.", "a.gtld-servers.net.", "192.5.6.30"),
            ("example.com", dns.rdatatype.A, "192.5.6.30"):
                _make_answer("example.com.", "93.184.216.34"),
        }

        def fake_send(name, rdtype, server_ip, timeout=5.0):
            return responses[(name, rdtype, server_ip)]

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", "A")  # string, not int

        assert len(steps) == 2
        assert steps[-1].response.answer

    def test_resolve_accepts_string_rdtype_aaaa(self):
        """String record type 'AAAA' also works."""
        def fake_send(name, rdtype, server_ip, timeout=5.0):
            assert rdtype == dns.rdatatype.AAAA
            return _make_answer("example.com.", "2606:2800:21f:cb07:6820:80da:af6b:8b2c")

        with patch("dnscurse.resolver.send_query", side_effect=fake_send):
            steps = resolve("example.com", "AAAA")

        assert len(steps) == 1

    def test_top_level_imports(self):
        """Core API is importable from the package root."""
        from dnscurse import (  # noqa: F401
            DEFAULT_TIMEOUT,
            ROOT_SERVERS,
            RecursionStep,
            get_cname_target,
            is_referral,
            resolve,
            send_query,
        )

        assert callable(resolve)
        assert callable(send_query)
        assert callable(is_referral)
        assert callable(get_cname_target)
        assert len(ROOT_SERVERS) == 13
        assert DEFAULT_TIMEOUT > 0


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
        steps = resolve("example.com", dns.rdatatype.A, timeout=10.0)

        assert len(steps) >= 2, "Should take at least 2 steps"

        print("\n  Live resolution of example.com:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        final = steps[-1]
        assert final.response is not None
        assert final.response.answer, "Should get an A record answer"
        print(f"  Final answer found in {len(steps)} steps")

    def test_resolve_nonexistent_domain(self):
        """EXPLANATION: Querying a domain that doesn't exist should
        eventually result in NXDOMAIN from the authoritative server.
        """
        steps = resolve("this-domain-definitely-does-not-exist-12345.com",
                        dns.rdatatype.A, timeout=10.0)

        print("\n  Live resolution of non-existent domain:")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        final = steps[-1]
        if final.response:
            rcode_text = dns.rcode.to_text(final.response.rcode())
            print(f"  Final RCODE: {rcode_text}")
