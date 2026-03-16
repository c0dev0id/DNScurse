"""Tests for DNS wire format encoding and decoding.

These tests verify that DNScurse correctly implements RFC 1035 wire format
without using any DNS libraries. Each test explains what the bytes mean
so the test output doubles as documentation of the DNS wire protocol.
"""

from __future__ import annotations

import struct

import pytest

from dnscurse.models import DNSHeader, QClass, QType
from dnscurse.wire import (
    build_query,
    decode_header,
    decode_name,
    decode_packet,
    decode_question,
    decode_record,
    encode_header,
    encode_name,
)


# -----------------------------------------------------------------------
# Name encoding
# -----------------------------------------------------------------------

class TestEncodeName:
    """RFC 1035 Section 4.1.2: Domain names are encoded as a sequence of
    labels.  Each label is a length octet followed by that number of
    octets.  The sequence is terminated by a zero-length label (the root).

    Example:  example.com  ->  \\x07example\\x03com\\x00
              ^7 bytes^     ^3 bytes^   ^root^
    """

    def test_simple_domain(self):
        """EXPLANATION: 'example.com' has two labels:
          - \\x07 (length 7) followed by 'example'
          - \\x03 (length 3) followed by 'com'
          - \\x00 terminates the name (root label)
        """
        result = encode_name("example.com")
        assert result == b"\x07example\x03com\x00"
        print(f"  Encoded 'example.com' -> {result.hex(' ')}")
        print(f"  Breakdown: 07='e x a m p l e'  03='c o m'  00=root")

    def test_subdomain(self):
        """EXPLANATION: 'www.example.com' has three labels.
        Each label is prefixed by its length byte.
        """
        result = encode_name("www.example.com")
        assert result == b"\x03www\x07example\x03com\x00"
        print(f"  Encoded 'www.example.com' -> {result.hex(' ')}")

    def test_trailing_dot(self):
        """EXPLANATION: A trailing dot (FQDN notation) is stripped before
        encoding.  'example.com.' and 'example.com' produce identical wire
        format because the root is always implicit.
        """
        assert encode_name("example.com.") == encode_name("example.com")
        print("  Trailing dot produces identical encoding")

    def test_single_label(self):
        """EXPLANATION: A single label like 'localhost' has just one
        length-prefixed segment plus the root terminator.
        """
        result = encode_name("localhost")
        assert result == b"\x09localhost\x00"
        print(f"  Encoded 'localhost' -> {result.hex(' ')}")

    def test_label_too_long(self):
        """EXPLANATION: RFC 1035 limits each label to 63 octets.
        The two high bits of the length byte are reserved for compression
        pointers, so a label length must fit in 6 bits (0-63).
        """
        with pytest.raises(ValueError, match="Label too long"):
            encode_name("a" * 64 + ".com")
        print("  Label > 63 chars correctly rejected")


# -----------------------------------------------------------------------
# Header encoding/decoding
# -----------------------------------------------------------------------

class TestHeader:
    """RFC 1035 Section 4.1.1: The DNS header is 12 bytes containing:
      - ID (16 bits): matches queries to responses
      - Flags (16 bits): QR, OPCODE, AA, TC, RD, RA, Z, RCODE
      - QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT (16 bits each)
    """

    def test_encode_query_header(self):
        """EXPLANATION: A standard iterative query has:
          - QR=0 (this is a query, not a response)
          - RD=0 (no recursion desired — we do it ourselves)
          - QDCOUNT=1 (one question)
          - All other counts = 0
        """
        h = DNSHeader(id=0x1234, rd=0, qdcount=1)
        raw = encode_header(h)
        assert len(raw) == 12
        # ID
        assert struct.unpack("!H", raw[0:2])[0] == 0x1234
        # Flags: all zero (QR=0, RD=0)
        assert struct.unpack("!H", raw[2:4])[0] == 0x0000
        # QDCOUNT = 1
        assert struct.unpack("!H", raw[4:6])[0] == 1
        print(f"  Header bytes: {raw.hex(' ')}")
        print(f"  ID=0x1234  Flags=0x0000  QD=1  AN=0  NS=0  AR=0")

    def test_roundtrip(self):
        """EXPLANATION: Encoding then decoding a header must reproduce
        every field exactly — this validates our bit manipulation.
        """
        original = DNSHeader(
            id=0xABCD, qr=1, opcode=0, aa=1, tc=0,
            rd=1, ra=1, z=0, rcode=0,
            qdcount=1, ancount=2, nscount=3, arcount=4,
        )
        raw = encode_header(original)
        decoded = decode_header(raw)
        assert decoded.id == original.id
        assert decoded.qr == original.qr
        assert decoded.aa == original.aa
        assert decoded.rd == original.rd
        assert decoded.ra == original.ra
        assert decoded.rcode == original.rcode
        assert decoded.qdcount == original.qdcount
        assert decoded.ancount == original.ancount
        assert decoded.nscount == original.nscount
        assert decoded.arcount == original.arcount
        print(f"  Round-trip OK: ID=0x{original.id:04X} QR={original.qr} "
              f"AA={original.aa} RD={original.rd} RA={original.ra}")


# -----------------------------------------------------------------------
# Name decoding & compression pointers
# -----------------------------------------------------------------------

class TestDecodeName:
    """RFC 1035 Section 4.1.4: To reduce packet size, domain names can use
    compression pointers.  A pointer is a 2-byte sequence where the top
    two bits are both 1 (0xC0 mask), and the remaining 14 bits give an
    offset into the packet where the name (or suffix) continues.

    This is how a response can refer to 'example.com' in an answer record
    without repeating all the label bytes — it points back to the question
    section.
    """

    def test_simple_name(self):
        """EXPLANATION: A name with no compression is just labels + root.
        """
        data = b"\x07example\x03com\x00"
        name, offset = decode_name(data, 0)
        assert name == "example.com"
        assert offset == len(data)
        print(f"  Decoded: {data.hex(' ')} -> '{name}'")

    def test_compression_pointer(self):
        """EXPLANATION: Compression example:
          Offset 0: \\x07example\\x03com\\x00   (full 'example.com')
          Offset 13: \\x03www\\xC0\\x00          (www + pointer to offset 0)

        The pointer \\xC0\\x00 means 'continue reading the name at byte 0',
        which gives us 'example.com'.  So the full decoded name at offset
        13 is 'www.example.com'.

        This saves bytes in DNS responses where the same domain suffix
        appears in multiple records.
        """
        # Build: "example.com" at offset 0, then "www" + pointer to 0
        full_name = b"\x07example\x03com\x00"
        compressed = b"\x03www\xc0\x00"
        data = full_name + compressed

        # Decode the compressed name starting after the full name
        name, offset = decode_name(data, len(full_name))
        assert name == "www.example.com"
        print(f"  Data: {data.hex(' ')}")
        print(f"  Pointer at offset {len(full_name)+4}: "
              f"0xC000 -> jump to offset 0 -> 'example.com'")
        print(f"  Result: 'www.example.com'")

    def test_pointer_loop_protection(self):
        """EXPLANATION: A malicious packet could create a pointer loop
        (A -> B -> A).  Our decoder limits jumps to prevent infinite loops.
        """
        # Create a pointer that points to itself
        data = b"\xc0\x00"
        with pytest.raises(ValueError, match="Too many"):
            decode_name(data, 0)
        print("  Pointer loop correctly detected and rejected")


# -----------------------------------------------------------------------
# Full query construction
# -----------------------------------------------------------------------

class TestBuildQuery:
    """Tests that build_query produces a valid DNS query packet.

    A DNS query packet contains:
      1. 12-byte header (ID, flags, counts)
      2. Question section (encoded name + QTYPE + QCLASS)
    """

    def test_a_record_query(self):
        """EXPLANATION: Building an A record query for 'example.com':
          - Header: random ID, QR=0, RD=0, QDCOUNT=1
          - Question: \\x07example\\x03com\\x00 + TYPE=1(A) + CLASS=1(IN)
        """
        pkt = build_query("example.com", QType.A)

        # Header is 12 bytes
        header = decode_header(pkt)
        assert header.qr == 0, "Must be a query (QR=0)"
        assert header.rd == 0, "Iterative mode (RD=0)"
        assert header.qdcount == 1

        # Question section follows
        q, end = decode_question(pkt, 12)
        assert q.name == "example.com"
        assert q.qtype == QType.A
        assert q.qclass == QClass.IN

        print(f"  Packet ({len(pkt)} bytes): {pkt.hex(' ')}")
        print(f"  Header: ID=0x{header.id:04X} QR=0 RD=0 QDCOUNT=1")
        print(f"  Question: {q.name} type=A class=IN")

    def test_aaaa_query(self):
        """EXPLANATION: AAAA queries (IPv6) use QTYPE=28.
        Same structure as A queries, just different type field.
        """
        pkt = build_query("example.com", QType.AAAA)
        q, _ = decode_question(pkt, 12)
        assert q.qtype == QType.AAAA
        print(f"  AAAA query type field = {q.qtype} (0x001C)")


# -----------------------------------------------------------------------
# Full packet decoding with real-world-like bytes
# -----------------------------------------------------------------------

class TestDecodePacket:
    """Tests that decode_packet correctly parses DNS response packets.

    These tests use hand-crafted byte sequences that mimic real DNS
    responses.  Each test explains what the bytes represent.
    """

    def _build_response_bytes(
        self,
        *,
        id_: int = 0x1234,
        rcode: int = 0,
        aa: int = 0,
        questions: list[tuple[str, int]] | None = None,
        answers: list[tuple[str, int, int, bytes]] | None = None,
        authorities: list[tuple[str, int, int, bytes]] | None = None,
        additionals: list[tuple[str, int, int, bytes]] | None = None,
    ) -> bytes:
        """Helper: construct raw DNS response bytes."""
        questions = questions or []
        answers = answers or []
        authorities = authorities or []
        additionals = additionals or []

        flags = (1 << 15) | (aa << 10) | rcode  # QR=1
        header = struct.pack(
            "!HHHHHH",
            id_, flags,
            len(questions), len(answers), len(authorities), len(additionals),
        )

        body = b""
        for name, qtype in questions:
            body += encode_name(name) + struct.pack("!HH", qtype, QClass.IN)
        for name, rtype, ttl, rdata in answers + authorities + additionals:
            body += encode_name(name) + struct.pack(
                "!HHIH", rtype, QClass.IN, ttl, len(rdata),
            ) + rdata

        return header + body

    def test_a_record_response(self):
        """EXPLANATION: A simple A record response for 'example.com':
          - Header: QR=1 (response), AA=1 (authoritative), RCODE=0
          - Answer: example.com  A  93.184.216.34
            RDATA is 4 bytes: 93=0x5D, 184=0xB8, 216=0xD8, 34=0x22
        """
        ip_bytes = bytes([93, 184, 216, 34])
        data = self._build_response_bytes(
            aa=1,
            questions=[("example.com", QType.A)],
            answers=[("example.com", QType.A, 3600, ip_bytes)],
        )

        pkt = decode_packet(data)
        assert pkt.header.qr == 1
        assert pkt.header.aa == 1
        assert len(pkt.answers) == 1
        assert pkt.answers[0].rdata == "93.184.216.34"
        assert pkt.answers[0].rtype == QType.A

        print(f"  Response: {pkt.answers[0]}")
        print(f"  RDATA bytes: {ip_bytes.hex(' ')} -> 93.184.216.34")

    def test_ns_referral_response(self):
        """EXPLANATION: When a server doesn't have the answer, it returns
        a referral — NS records in the authority section pointing to
        nameservers closer to the answer, plus 'glue' A records in the
        additional section so we know the IP of those nameservers.

        This is how iterative resolution works:
          1. Ask root server for 'www.example.com'
          2. Root says: 'I don't know, but com is handled by a.gtld-servers.net'
             (NS record in authority + A record in additional = glue)
          3. We then ask a.gtld-servers.net, and so on.
        """
        ns_name_bytes = encode_name("a.gtld-servers.net")
        glue_ip = bytes([192, 5, 6, 30])

        data = self._build_response_bytes(
            questions=[("example.com", QType.A)],
            authorities=[("com", QType.NS, 172800, ns_name_bytes)],
            additionals=[("a.gtld-servers.net", QType.A, 172800, glue_ip)],
        )

        pkt = decode_packet(data)
        assert pkt.is_referral(), "Should be detected as a referral"
        assert pkt.authorities[0].rdata == "a.gtld-servers.net"
        assert pkt.additionals[0].rdata == "192.5.6.30"

        glue_ips = pkt.get_referral_ns_ips()
        assert "192.5.6.30" in glue_ips

        print("  Referral response:")
        print(f"    Authority: {pkt.authorities[0]}")
        print(f"    Glue:      {pkt.additionals[0]}")
        print(f"    -> Next step: query 192.5.6.30 for example.com")

    def test_cname_response(self):
        """EXPLANATION: A CNAME response means 'the name you asked about
        is actually an alias for another name'.

        Example: www.example.com CNAME example.com
        The resolver must then resolve the CNAME target (example.com)
        to get the actual IP address.  This adds extra recursion steps.
        """
        target_bytes = encode_name("example.com")
        data = self._build_response_bytes(
            aa=1,
            questions=[("www.example.com", QType.A)],
            answers=[("www.example.com", QType.CNAME, 3600, target_bytes)],
        )

        pkt = decode_packet(data)
        assert pkt.answers[0].rtype == QType.CNAME
        assert pkt.answers[0].rdata == "example.com"

        target = pkt.get_cname_target("www.example.com")
        assert target == "example.com"

        print(f"  CNAME: www.example.com -> {target}")
        print(f"  Resolver must now resolve 'example.com' from root")

    def test_nxdomain_response(self):
        """EXPLANATION: RCODE=3 (NXDOMAIN) means the domain does not exist.
        The authority section usually contains a SOA record indicating
        which zone is authoritative for the negative answer.
        """
        # SOA RDATA: mname + rname + serial + refresh + retry + expire + min
        soa_rdata = (
            encode_name("ns1.example.com")
            + encode_name("admin.example.com")
            + struct.pack("!IIIII", 2024010101, 3600, 900, 604800, 86400)
        )

        data = self._build_response_bytes(
            rcode=3,  # NXDOMAIN
            aa=1,
            questions=[("nope.example.com", QType.A)],
            authorities=[("example.com", QType.SOA, 900, soa_rdata)],
        )

        pkt = decode_packet(data)
        assert pkt.header.rcode == 3
        assert pkt.authorities[0].rtype == QType.SOA
        assert not pkt.is_referral()

        print(f"  RCODE: {pkt.header.rcode} (NXDOMAIN)")
        print(f"  SOA: {pkt.authorities[0]}")
        print(f"  This domain does not exist.")

    def test_aaaa_record_response(self):
        """EXPLANATION: AAAA records contain 16 bytes of IPv6 address.
        The wire format is a raw 128-bit address that we format as
        colon-separated hex groups.
        """
        # 2606:2800:0220:0001:0248:1893:25c8:1946
        ipv6_bytes = bytes([
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
        ])

        data = self._build_response_bytes(
            aa=1,
            questions=[("example.com", QType.AAAA)],
            answers=[("example.com", QType.AAAA, 3600, ipv6_bytes)],
        )

        pkt = decode_packet(data)
        assert pkt.answers[0].rtype == QType.AAAA
        assert "2606" in pkt.answers[0].rdata
        print(f"  AAAA: {pkt.answers[0]}")

    def test_multiple_answers(self):
        """EXPLANATION: A domain can have multiple A records (round-robin DNS).
        The resolver returns all of them, and the client picks one.
        """
        data = self._build_response_bytes(
            aa=1,
            questions=[("example.com", QType.A)],
            answers=[
                ("example.com", QType.A, 300, bytes([1, 2, 3, 4])),
                ("example.com", QType.A, 300, bytes([5, 6, 7, 8])),
            ],
        )

        pkt = decode_packet(data)
        assert len(pkt.answers) == 2
        assert pkt.answers[0].rdata == "1.2.3.4"
        assert pkt.answers[1].rdata == "5.6.7.8"
        print("  Multiple A records (round-robin):")
        for a in pkt.answers:
            print(f"    {a}")


# -----------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------

class TestWireEdgeCases:

    def test_packet_too_short(self):
        """EXPLANATION: DNS header is always 12 bytes. Anything shorter
        is malformed.
        """
        with pytest.raises(ValueError, match="too short"):
            decode_header(b"\x00" * 5)
        print("  Short packet correctly rejected")

    def test_truncated_question(self):
        """EXPLANATION: If the question section is cut off mid-stream,
        the decoder must raise rather than read garbage.
        """
        header = struct.pack("!HHHHHH", 0x1234, 0, 1, 0, 0, 0)
        # Name but no QTYPE/QCLASS
        data = header + b"\x03www\x00"
        with pytest.raises(ValueError, match="truncated"):
            decode_packet(data)
        print("  Truncated question section correctly detected")

    def test_mx_record_decoding(self):
        """EXPLANATION: MX records have a 16-bit preference value followed
        by a domain name.  Lower preference = higher priority.
        """
        mx_rdata = struct.pack("!H", 10) + encode_name("mail.example.com")
        header = struct.pack("!HHHHHH", 0x1234, 0x8000, 0, 1, 0, 0)
        body = (
            encode_name("example.com")
            + struct.pack("!HHIH", QType.MX, QClass.IN, 3600, len(mx_rdata))
            + mx_rdata
        )
        pkt = decode_packet(header + body)
        assert "10 mail.example.com" in pkt.answers[0].rdata
        print(f"  MX: {pkt.answers[0]}")

    def test_txt_record_decoding(self):
        """EXPLANATION: TXT records contain one or more character strings.
        Each string is preceded by a length byte. Commonly used for SPF,
        DKIM, and verification records.
        """
        txt = b"v=spf1 include:example.com ~all"
        txt_rdata = bytes([len(txt)]) + txt
        header = struct.pack("!HHHHHH", 0x1234, 0x8000, 0, 1, 0, 0)
        body = (
            encode_name("example.com")
            + struct.pack("!HHIH", QType.TXT, QClass.IN, 3600, len(txt_rdata))
            + txt_rdata
        )
        pkt = decode_packet(header + body)
        assert "v=spf1" in pkt.answers[0].rdata
        print(f"  TXT: {pkt.answers[0]}")
