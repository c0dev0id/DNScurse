"""Tests for DNS models and recursion step explanations.

These tests verify the model layer and demonstrate how recursion steps
are built and explained. Test output serves as educational documentation
of the DNS resolution process.
"""

from __future__ import annotations

import dns.rdatatype

from dnscurse.models import (
    RecursionStep,
    format_rrset,
    get_cname_target,
    get_delegated_zone,
    get_referral_ns_ips,
    get_referral_ns_names,
    is_referral,
)

from .conftest import _msg

# -----------------------------------------------------------------------
# Referral detection
# -----------------------------------------------------------------------

class TestReferralDetection:
    """EXPLANATION: Detecting referrals is critical for iterative resolution.
    A referral means the server doesn't have the final answer but knows
    which nameservers are responsible for the next zone in the hierarchy.

    Anatomy of a referral:
      - 0 answers
      - NS records in the authority section (pointing to child zone NS)
      - A/AAAA records in the additional section (glue records with NS IPs)
    """

    def test_referral_detected(self):
        msg = _msg(
            authority=[("com.", dns.rdatatype.NS, 172800, "a.gtld-servers.net.")],
            additional=[("a.gtld-servers.net.", dns.rdatatype.A, 172800, "192.5.6.30")],
        )
        assert is_referral(msg)
        ips = get_referral_ns_ips(msg)
        assert ips == ["192.5.6.30"]
        print("  Referral: com -> a.gtld-servers.net (192.5.6.30)")

    def test_answer_is_not_referral(self):
        msg = _msg(
            aa=True,
            answer=[("example.com.", dns.rdatatype.A, 300, "93.184.216.34")],
        )
        assert not is_referral(msg)
        print("  Packet with answers is NOT a referral")

    def test_referral_without_glue(self):
        """EXPLANATION: Sometimes referrals come without glue records.
        This happens when the NS names are in a different zone.
        The resolver must then separately resolve the NS name to an IP
        before it can continue — adding extra recursion steps.
        """
        msg = _msg(
            authority=[("example.com.", dns.rdatatype.NS, 172800, "ns1.other-provider.net.")],
        )
        assert is_referral(msg)
        assert get_referral_ns_ips(msg) == []
        print("  Referral without glue — NS must be resolved separately")

    def test_get_referral_ns_names(self):
        msg = _msg(
            authority=[
                ("com.", dns.rdatatype.NS, 172800, "a.gtld-servers.net."),
                ("com.", dns.rdatatype.NS, 172800, "b.gtld-servers.net."),
            ],
        )
        names = get_referral_ns_names(msg)
        assert "a.gtld-servers.net." in names
        assert "b.gtld-servers.net." in names
        print(f"  NS names: {names}")


# -----------------------------------------------------------------------
# CNAME handling
# -----------------------------------------------------------------------

class TestCNAMEHandling:
    """EXPLANATION: CNAMEs (Canonical Name records) are aliases.
    When you query 'www.example.com' and get a CNAME pointing to
    'example.com', the resolver must restart resolution for 'example.com'.

    This is why resolving a CNAME can double the number of recursion steps.
    """

    def test_cname_detected(self):
        msg = _msg(
            aa=True,
            answer=[("www.example.com.", dns.rdatatype.CNAME, 3600, "example.com.")],
        )
        target = get_cname_target(msg, "www.example.com")
        assert target is not None
        assert "example.com" in target
        print(f"  CNAME: www.example.com -> {target}")

    def test_cname_case_insensitive(self):
        """EXPLANATION: DNS names are case-insensitive per RFC 1035 2.3.3.
        dnspython handles this natively via dns.name.Name comparison.
        """
        msg = _msg(
            aa=True,
            answer=[("WWW.EXAMPLE.COM.", dns.rdatatype.CNAME, 3600, "example.com.")],
        )
        assert get_cname_target(msg, "www.example.com") is not None
        print("  CNAME lookup is case-insensitive")

    def test_no_cname(self):
        msg = _msg(
            aa=True,
            answer=[("example.com.", dns.rdatatype.A, 300, "93.184.216.34")],
        )
        assert get_cname_target(msg, "example.com") is None
        print("  A record — no CNAME chain to follow")


# -----------------------------------------------------------------------
# format_rrset
# -----------------------------------------------------------------------

class TestFormatRRset:
    def test_a_record(self):
        """EXPLANATION: Record string format matches dig-style output:
        NAME  TTL  TYPE  RDATA
        """
        msg = _msg(answer=[("example.com.", dns.rdatatype.A, 3600, "93.184.216.34")])
        lines = format_rrset(msg.answer[0])
        assert len(lines) == 1
        assert "example.com" in lines[0]
        assert "3600" in lines[0]
        assert "93.184.216.34" in lines[0]
        print(f"  Record: {lines[0]}")

    def test_multiple_records(self):
        """EXPLANATION: A domain can have multiple A records (round-robin DNS).
        """
        msg = _msg(answer=[
            ("example.com.", dns.rdatatype.A, 300, "1.2.3.4"),
            ("example.com.", dns.rdatatype.A, 300, "5.6.7.8"),
        ])
        lines = format_rrset(msg.answer[0])
        assert len(lines) == 2
        print("  Multiple A records (round-robin):")
        for line in lines:
            print(f"    {line}")


# -----------------------------------------------------------------------
# RecursionStep explanation
# -----------------------------------------------------------------------

class TestRecursionStepExplanation:
    """EXPLANATION: RecursionStep.explain() produces human-readable output
    that shows exactly what happened at each point in the resolution.
    This is the core educational feature of DNScurse.
    """

    def test_root_query_step(self):
        """EXPLANATION: Step 1 of any resolution — querying a root server.

        The DNS root servers know which nameservers handle each TLD
        (.com, .org, .net, etc.).  There are 13 root server addresses
        (a through m.root-servers.net) operated by different organizations.
        """
        step = RecursionStep(
            step_number=1,
            description="Query root server for example.com",
            server_ip="198.41.0.4",
            server_name="a.root-servers.net",
            query_name="example.com",
            query_type="A",
            response=_msg(
                authority=[("com.", dns.rdatatype.NS, 172800, "a.gtld-servers.net.")],
                additional=[("a.gtld-servers.net.", dns.rdatatype.A, 172800, "192.5.6.30")],
            ),
        )
        text = step.explain()
        assert "Step 1" in text
        assert "a.root-servers.net" in text
        assert "a.gtld-servers.net" in text
        assert "192.5.6.30" in text
        print(text)

    def test_tld_referral_step(self):
        """EXPLANATION: Step 2 — the TLD server (.com) refers us to the
        domain's authoritative nameservers.

        The .com TLD servers (gtld-servers.net) know which nameservers
        are registered for each .com domain.
        """
        step = RecursionStep(
            step_number=2,
            description="Follow referral — query a.gtld-servers.net for example.com",
            server_ip="192.5.6.30",
            server_name="a.gtld-servers.net",
            query_name="example.com",
            query_type="A",
            response=_msg(
                authority=[("example.com.", dns.rdatatype.NS, 172800, "a.iana-servers.net.")],
                additional=[("a.iana-servers.net.", dns.rdatatype.A, 172800, "199.43.135.53")],
            ),
        )
        text = step.explain()
        assert "Step 2" in text
        assert "a.iana-servers.net" in text
        print(text)

    def test_final_answer_step(self):
        """EXPLANATION: Step 3 — the authoritative nameserver gives us the
        final answer.  This is the IP address of the domain.

        At this point, the recursion is complete.  A typical .com domain
        resolution takes 3 steps: root -> TLD -> authoritative.
        """
        step = RecursionStep(
            step_number=3,
            description="Follow referral — query a.iana-servers.net for example.com",
            server_ip="199.43.135.53",
            server_name="a.iana-servers.net",
            query_name="example.com",
            query_type="A",
            response=_msg(
                aa=True,
                answer=[("example.com.", dns.rdatatype.A, 3600, "93.184.216.34")],
            ),
        )
        text = step.explain()
        assert "Step 3" in text
        assert "93.184.216.34" in text
        print(text)

    def test_error_step(self):
        """EXPLANATION: Network errors (timeouts, unreachable servers)
        are recorded as failed steps so the user can see exactly
        where resolution broke down.
        """
        step = RecursionStep(
            step_number=1,
            description="Query root server for example.com",
            server_ip="198.41.0.4",
            server_name="a.root-servers.net",
            query_name="example.com",
            query_type="A",
            error="timed out",
        )
        text = step.explain()
        assert "timed out" in text
        print(text)

    def test_nxdomain_step(self):
        """EXPLANATION: NXDOMAIN at the authoritative server means the
        domain genuinely does not exist. The SOA record in the authority
        section tells caches how long to remember this negative result.
        """
        step = RecursionStep(
            step_number=3,
            description="Follow referral — query ns.example.com for nope.example.com",
            server_ip="93.184.216.34",
            server_name="ns.example.com",
            query_name="nope.example.com",
            query_type="A",
            response=_msg(
                rcode=dns.rcode.NXDOMAIN,
                aa=True,
                authority=[(
                    "example.com.", dns.rdatatype.SOA, 900,
                    "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400",
                )],
            ),
        )
        text = step.explain()
        assert "NXDOMAIN" in text
        assert "SOA" in text
        print(text)

    def test_full_resolution_walkthrough(self):
        """EXPLANATION: This test simulates a complete 3-step resolution
        of 'example.com' and prints the full walkthrough, demonstrating
        the entire iterative resolution process:

        STEP 1 - Root Server (198.41.0.4 / a.root-servers.net)
          We ask: 'Where is example.com?'
          Root says: 'I don't know, but .com is handled by a.gtld-servers.net
                      at 192.5.6.30'
          This is a REFERRAL with glue records.

        STEP 2 - TLD Server (192.5.6.30 / a.gtld-servers.net)
          We ask: 'Where is example.com?'
          TLD says: 'I don't know, but example.com is handled by
                     a.iana-servers.net at 199.43.135.53'
          Another REFERRAL, getting closer.

        STEP 3 - Authoritative Server (199.43.135.53 / a.iana-servers.net)
          We ask: 'Where is example.com?'
          Server says: 'example.com is at 93.184.216.34'
          This is the FINAL ANSWER. AA (Authoritative Answer) flag is set.
        """
        steps = [
            RecursionStep(
                step_number=1,
                description="Query root server for example.com",
                server_ip="198.41.0.4",
                server_name="a.root-servers.net",
                query_name="example.com",
                query_type="A",
                response=_msg(
                    authority=[
                        ("com.", dns.rdatatype.NS, 172800, "a.gtld-servers.net."),
                        ("com.", dns.rdatatype.NS, 172800, "b.gtld-servers.net."),
                    ],
                    additional=[
                        ("a.gtld-servers.net.", dns.rdatatype.A, 172800, "192.5.6.30"),
                        ("b.gtld-servers.net.", dns.rdatatype.A, 172800, "192.33.14.30"),
                    ],
                ),
            ),
            RecursionStep(
                step_number=2,
                description="Follow referral — query a.gtld-servers.net for example.com",
                server_ip="192.5.6.30",
                server_name="a.gtld-servers.net",
                query_name="example.com",
                query_type="A",
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
                response=_msg(
                    aa=True,
                    answer=[("example.com.", dns.rdatatype.A, 3600, "93.184.216.34")],
                ),
            ),
        ]

        print("\n  ╔══════════════════════════════════════════════════╗")
        print("  ║  FULL DNS RESOLUTION WALKTHROUGH: example.com   ║")
        print("  ╚══════════════════════════════════════════════════╝\n")
        for step in steps:
            print(f"  {step.explain()}")
            print()

        # Verify the chain
        assert is_referral(steps[0].response)
        assert is_referral(steps[1].response)
        assert not is_referral(steps[2].response)
        assert steps[2].response.answer
        print("  Resolution complete: example.com -> 93.184.216.34")
        print("  Total steps: 3 (root -> TLD -> authoritative)")


# -----------------------------------------------------------------------
# get_delegated_zone
# -----------------------------------------------------------------------

class TestGetDelegatedZone:
    """EXPLANATION: get_delegated_zone() answers "which DNS zone does this
    step cover?".  For referrals the zone is the NS rrset owner name in the
    authority section — that is the zone being delegated to the next tier.
    For final answers (or NXDOMAIN) the zone is the query name itself.
    """

    def _step(self, **kwargs) -> RecursionStep:
        defaults = dict(
            step_number=1,
            description="test",
            server_ip="1.2.3.4",
            server_name="ns.example",
            query_name="www.example.com.",
            query_type="A",
        )
        defaults.update(kwargs)
        return RecursionStep(**defaults)

    def test_referral_returns_ns_owner_zone(self):
        """EXPLANATION: For a referral step, the delegated zone comes from
        the owner name of the NS rrset in the authority section — not from
        the query name.  A root server returning 'com. NS a.gtld-servers.net.'
        means the zone 'com.' is being handed off to the TLD servers.
        """
        step = self._step(
            response=_msg(
                authority=[("com.", dns.rdatatype.NS, 172800, "a.gtld-servers.net.")],
                additional=[("a.gtld-servers.net.", dns.rdatatype.A, 172800, "192.5.6.30")],
            ),
        )
        assert get_delegated_zone(step) == "com."
        print("  Referral: delegated zone is 'com.'")

    def test_answer_returns_query_name(self):
        step = self._step(
            response=_msg(
                aa=True,
                answer=[("www.example.com.", dns.rdatatype.A, 300, "93.184.216.34")],
            ),
        )
        assert get_delegated_zone(step) == "www.example.com."
        print("  Answer: delegated zone is query name")

    def test_nxdomain_returns_query_name(self):
        step = self._step(
            query_name="nope.example.com.",
            response=_msg(
                rcode=dns.rcode.NXDOMAIN,
                aa=True,
                authority=[(
                    "example.com.", dns.rdatatype.SOA, 900,
                    "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400",
                )],
            ),
        )
        assert get_delegated_zone(step) == "nope.example.com."
        print("  NXDOMAIN: delegated zone is query name")

    def test_error_returns_none(self):
        step = self._step(error="timed out")
        assert get_delegated_zone(step) is None
        print("  Error step: delegated zone is None")
