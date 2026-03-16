"""Tests for DNS data models and recursion step explanations.

These tests verify the model layer and — importantly — demonstrate how
recursion steps are built and explained so the test output serves as
educational documentation of the DNS resolution process.
"""

from __future__ import annotations

from dnscurse.models import (
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    QClass,
    QType,
    RCode,
    RecursionStep,
)


# -----------------------------------------------------------------------
# QType / enums
# -----------------------------------------------------------------------

class TestQType:
    def test_known_types(self):
        """EXPLANATION: DNS defines numeric type codes for record types.
        The most common ones used in recursion:
          A=1 (IPv4), NS=2 (nameserver), CNAME=5 (alias),
          SOA=6 (zone authority), AAAA=28 (IPv6)
        """
        assert QType.A == 1
        assert QType.NS == 2
        assert QType.CNAME == 5
        assert QType.SOA == 6
        assert QType.AAAA == 28
        print("  A=1  NS=2  CNAME=5  SOA=6  AAAA=28")

    def test_unknown_type(self):
        """EXPLANATION: DNS has many record types. When we encounter one
        we don't explicitly handle, we return the raw integer rather
        than crashing.
        """
        result = QType.from_int(999)
        assert result == 999
        assert not isinstance(result, QType)
        print("  Unknown type 999 returned as raw int")


class TestRCode:
    def test_common_rcodes(self):
        """EXPLANATION: RCODE tells us the result of a query:
          0 = NOERROR  (success, even if no records found)
          2 = SERVFAIL (server couldn't process the query)
          3 = NXDOMAIN (domain name does not exist)
          5 = REFUSED  (server refuses to answer)
        """
        assert RCode.NOERROR == 0
        assert RCode.SERVFAIL == 2
        assert RCode.NXDOMAIN == 3
        assert RCode.REFUSED == 5
        print("  NOERROR=0  SERVFAIL=2  NXDOMAIN=3  REFUSED=5")


# -----------------------------------------------------------------------
# DNSRecord
# -----------------------------------------------------------------------

class TestDNSRecord:
    def test_type_name_known(self):
        r = DNSRecord(name="example.com", rtype=QType.A,
                      rclass=QClass.IN, ttl=300, rdata="93.184.216.34")
        assert r.type_name() == "A"
        print(f"  {r}")

    def test_type_name_unknown(self):
        r = DNSRecord(name="example.com", rtype=65,
                      rclass=QClass.IN, ttl=300, rdata="...")
        assert r.type_name() == "TYPE65"
        print(f"  Unknown type renders as: {r.type_name()}")

    def test_str_format(self):
        """EXPLANATION: Record string format matches dig-style output:
        NAME  TTL  TYPE  RDATA
        """
        r = DNSRecord(name="example.com", rtype=QType.A,
                      rclass=QClass.IN, ttl=3600, rdata="93.184.216.34")
        s = str(r)
        assert "example.com" in s
        assert "3600" in s
        assert "A" in s
        assert "93.184.216.34" in s
        print(f"  Record: {s}")


# -----------------------------------------------------------------------
# DNSPacket — referral detection
# -----------------------------------------------------------------------

class TestDNSPacketReferral:
    """EXPLANATION: Detecting referrals is critical for iterative resolution.
    A referral means the server doesn't have the final answer but knows
    which nameservers are responsible for the next zone in the hierarchy.

    Anatomy of a referral:
      - 0 answers
      - NS records in the authority section (pointing to child zone NS)
      - A/AAAA records in the additional section (glue records with NS IPs)
    """

    def test_referral_detected(self):
        pkt = DNSPacket(
            header=DNSHeader(qr=1, nscount=1, arcount=1),
            authorities=[
                DNSRecord("com", QType.NS, QClass.IN, 172800,
                          "a.gtld-servers.net"),
            ],
            additionals=[
                DNSRecord("a.gtld-servers.net", QType.A, QClass.IN, 172800,
                          "192.5.6.30"),
            ],
        )
        assert pkt.is_referral()
        ips = pkt.get_referral_ns_ips()
        assert ips == ["192.5.6.30"]
        print("  Referral: com -> a.gtld-servers.net (192.5.6.30)")

    def test_answer_is_not_referral(self):
        pkt = DNSPacket(
            header=DNSHeader(qr=1, ancount=1),
            answers=[
                DNSRecord("example.com", QType.A, QClass.IN, 300,
                          "93.184.216.34"),
            ],
        )
        assert not pkt.is_referral()
        print("  Packet with answers is NOT a referral")

    def test_referral_without_glue(self):
        """EXPLANATION: Sometimes referrals come without glue records.
        This happens when the NS names are in a different zone.
        The resolver must then separately resolve the NS name to an IP
        before it can continue — adding extra recursion steps.
        """
        pkt = DNSPacket(
            header=DNSHeader(qr=1, nscount=1),
            authorities=[
                DNSRecord("example.com", QType.NS, QClass.IN, 172800,
                          "ns1.other-provider.net"),
            ],
        )
        assert pkt.is_referral()
        assert pkt.get_referral_ns_ips() == []
        print("  Referral without glue — NS must be resolved separately")


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
        pkt = DNSPacket(
            header=DNSHeader(qr=1, ancount=1),
            answers=[
                DNSRecord("www.example.com", QType.CNAME, QClass.IN, 3600,
                          "example.com"),
            ],
        )
        target = pkt.get_cname_target("www.example.com")
        assert target == "example.com"
        print(f"  CNAME: www.example.com -> {target}")

    def test_cname_case_insensitive(self):
        pkt = DNSPacket(
            header=DNSHeader(qr=1, ancount=1),
            answers=[
                DNSRecord("WWW.EXAMPLE.COM", QType.CNAME, QClass.IN, 3600,
                          "example.com"),
            ],
        )
        assert pkt.get_cname_target("www.example.com") == "example.com"
        print("  CNAME lookup is case-insensitive")

    def test_no_cname(self):
        pkt = DNSPacket(
            header=DNSHeader(qr=1, ancount=1),
            answers=[
                DNSRecord("example.com", QType.A, QClass.IN, 300,
                          "93.184.216.34"),
            ],
        )
        assert pkt.get_cname_target("example.com") is None
        print("  A record — no CNAME chain to follow")


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
            response=DNSPacket(
                header=DNSHeader(qr=1, nscount=1, arcount=1),
                authorities=[
                    DNSRecord("com", QType.NS, QClass.IN, 172800,
                              "a.gtld-servers.net"),
                ],
                additionals=[
                    DNSRecord("a.gtld-servers.net", QType.A, QClass.IN,
                              172800, "192.5.6.30"),
                ],
            ),
        )
        text = step.explain()
        assert "Step 1" in text
        assert "root server" in text.lower() or "a.root-servers.net" in text
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
            response=DNSPacket(
                header=DNSHeader(qr=1, nscount=1, arcount=1),
                authorities=[
                    DNSRecord("example.com", QType.NS, QClass.IN, 172800,
                              "a.iana-servers.net"),
                ],
                additionals=[
                    DNSRecord("a.iana-servers.net", QType.A, QClass.IN,
                              172800, "199.43.135.53"),
                ],
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
            response=DNSPacket(
                header=DNSHeader(qr=1, aa=1, ancount=1),
                answers=[
                    DNSRecord("example.com", QType.A, QClass.IN, 3600,
                              "93.184.216.34"),
                ],
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
            response=DNSPacket(
                header=DNSHeader(qr=1, aa=1, rcode=3, nscount=1),
                authorities=[
                    DNSRecord("example.com", QType.SOA, QClass.IN, 900,
                              "ns1.example.com admin.example.com 2024010101 3600 900 604800 86400"),
                ],
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
                response=DNSPacket(
                    header=DNSHeader(qr=1, nscount=2, arcount=2),
                    authorities=[
                        DNSRecord("com", QType.NS, QClass.IN, 172800,
                                  "a.gtld-servers.net"),
                        DNSRecord("com", QType.NS, QClass.IN, 172800,
                                  "b.gtld-servers.net"),
                    ],
                    additionals=[
                        DNSRecord("a.gtld-servers.net", QType.A, QClass.IN,
                                  172800, "192.5.6.30"),
                        DNSRecord("b.gtld-servers.net", QType.A, QClass.IN,
                                  172800, "192.33.14.30"),
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
                response=DNSPacket(
                    header=DNSHeader(qr=1, nscount=1, arcount=1),
                    authorities=[
                        DNSRecord("example.com", QType.NS, QClass.IN,
                                  172800, "a.iana-servers.net"),
                    ],
                    additionals=[
                        DNSRecord("a.iana-servers.net", QType.A, QClass.IN,
                                  172800, "199.43.135.53"),
                    ],
                ),
            ),
            RecursionStep(
                step_number=3,
                description="Follow referral — query a.iana-servers.net for example.com",
                server_ip="199.43.135.53",
                server_name="a.iana-servers.net",
                query_name="example.com",
                query_type="A",
                response=DNSPacket(
                    header=DNSHeader(qr=1, aa=1, ancount=1),
                    answers=[
                        DNSRecord("example.com", QType.A, QClass.IN, 3600,
                                  "93.184.216.34"),
                    ],
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
        assert steps[0].response.is_referral()
        assert steps[1].response.is_referral()
        assert not steps[2].response.is_referral()
        assert steps[2].response.answers[0].rdata == "93.184.216.34"
        print("  Resolution complete: example.com -> 93.184.216.34")
        print("  Total steps: 3 (root -> TLD -> authoritative)")
