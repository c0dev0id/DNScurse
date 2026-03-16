"""DNS wire format encoding and decoding (RFC 1035).

All packet construction and parsing is manual — no DNS libraries.
"""

from __future__ import annotations

import random
import struct

from .models import (
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    QClass,
    QType,
)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format labels.

    Example: "example.com" -> b'\\x07example\\x03com\\x00'
    """
    parts = []
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"Label too long ({len(encoded)} > 63): {label}")
        parts.append(bytes([len(encoded)]) + encoded)
    parts.append(b"\x00")
    return b"".join(parts)


def encode_header(h: DNSHeader) -> bytes:
    """Encode a 12-byte DNS header."""
    flags = (
        (h.qr << 15)
        | (h.opcode << 11)
        | (h.aa << 10)
        | (h.tc << 9)
        | (h.rd << 8)
        | (h.ra << 7)
        | (h.z << 4)
        | h.rcode
    )
    return struct.pack(
        "!HHHHHH",
        h.id, flags, h.qdcount, h.ancount, h.nscount, h.arcount,
    )


def build_query(name: str, qtype: int, rd: int = 0) -> bytes:
    """Build a complete DNS query packet.

    Args:
        name: Domain name to query.
        qtype: Query type (e.g. QType.A).
        rd: Recursion Desired flag. 0 for iterative queries.
    """
    header = DNSHeader(
        id=random.randint(0, 0xFFFF),
        rd=rd,
        qdcount=1,
    )
    question = struct.pack("!HH", qtype, QClass.IN)
    return encode_header(header) + encode_name(name) + question


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def decode_header(data: bytes) -> DNSHeader:
    """Decode the 12-byte DNS header from raw packet data."""
    if len(data) < 12:
        raise ValueError(f"Packet too short for header: {len(data)} bytes")

    (id_, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
        "!HHHHHH", data[:12],
    )
    return DNSHeader(
        id=id_,
        qr=(flags >> 15) & 1,
        opcode=(flags >> 11) & 0xF,
        aa=(flags >> 10) & 1,
        tc=(flags >> 9) & 1,
        rd=(flags >> 8) & 1,
        ra=(flags >> 7) & 1,
        z=(flags >> 4) & 0x7,
        rcode=flags & 0xF,
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
    )


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format, handling label compression.

    Returns (name_string, new_offset).
    Compression pointers (0xC0 prefix) are followed to their target.
    """
    labels: list[str] = []
    original_offset = None
    jumps = 0
    max_jumps = 20  # guard against pointer loops

    while True:
        if offset >= len(data):
            raise ValueError(f"Name decode: offset {offset} beyond packet")

        length = data[offset]

        if length == 0:
            # End of name
            if original_offset is None:
                offset += 1
            break

        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if original_offset is None:
                original_offset = offset + 2
            offset = pointer
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("Too many compression pointer jumps")
            continue

        # Normal label
        offset += 1
        if offset + length > len(data):
            raise ValueError("Label extends beyond packet")
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length

    final_offset = original_offset if original_offset is not None else offset
    return ".".join(labels), final_offset


def decode_question(data: bytes, offset: int) -> tuple[DNSQuestion, int]:
    """Decode one question section entry."""
    name, offset = decode_name(data, offset)
    if offset + 4 > len(data):
        raise ValueError("Question section truncated")
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return DNSQuestion(name=name, qtype=qtype, qclass=qclass), offset + 4


def _decode_rdata(rtype: int, data: bytes, offset: int, rdlength: int) -> str:
    """Decode RDATA based on record type into human-readable string."""
    end = offset + rdlength

    if rtype == QType.A:
        if rdlength != 4:
            return data[offset:end].hex()
        return ".".join(str(b) for b in data[offset:end])

    if rtype == QType.AAAA:
        if rdlength != 16:
            return data[offset:end].hex()
        words = struct.unpack("!8H", data[offset:end])
        return ":".join(f"{w:x}" for w in words)

    if rtype in (QType.NS, QType.CNAME, QType.PTR):
        name, _ = decode_name(data, offset)
        return name

    if rtype == QType.MX:
        if rdlength < 4:
            return data[offset:end].hex()
        preference = struct.unpack("!H", data[offset:offset + 2])[0]
        exchange, _ = decode_name(data, offset + 2)
        return f"{preference} {exchange}"

    if rtype == QType.SOA:
        mname, pos = decode_name(data, offset)
        rname, pos = decode_name(data, pos)
        if pos + 20 > end:
            return f"{mname} {rname}"
        serial, refresh, retry, expire, minimum = struct.unpack(
            "!IIIII", data[pos:pos + 20],
        )
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"

    if rtype == QType.TXT:
        texts = []
        pos = offset
        while pos < end:
            txt_len = data[pos]
            pos += 1
            texts.append(data[pos:pos + txt_len].decode("ascii", errors="replace"))
            pos += txt_len
        return " ".join(f'"{t}"' for t in texts)

    # Unknown type — hex dump
    return data[offset:end].hex()


def decode_record(data: bytes, offset: int) -> tuple[DNSRecord, int]:
    """Decode one resource record."""
    name, offset = decode_name(data, offset)
    if offset + 10 > len(data):
        raise ValueError("Resource record truncated")

    rtype, rclass, ttl, rdlength = struct.unpack(
        "!HHIH", data[offset:offset + 10],
    )
    offset += 10

    if offset + rdlength > len(data):
        raise ValueError("RDATA extends beyond packet")

    rdata = _decode_rdata(rtype, data, offset, rdlength)

    return DNSRecord(
        name=name,
        rtype=rtype,
        rclass=rclass,
        ttl=ttl,
        rdata=rdata,
    ), offset + rdlength


def decode_packet(data: bytes) -> DNSPacket:
    """Decode a complete DNS response packet."""
    header = decode_header(data)
    offset = 12

    questions = []
    for _ in range(header.qdcount):
        q, offset = decode_question(data, offset)
        questions.append(q)

    answers = []
    for _ in range(header.ancount):
        r, offset = decode_record(data, offset)
        answers.append(r)

    authorities = []
    for _ in range(header.nscount):
        r, offset = decode_record(data, offset)
        authorities.append(r)

    additionals = []
    for _ in range(header.arcount):
        r, offset = decode_record(data, offset)
        additionals.append(r)

    return DNSPacket(
        header=header,
        questions=questions,
        answers=answers,
        authorities=authorities,
        additionals=additionals,
    )
