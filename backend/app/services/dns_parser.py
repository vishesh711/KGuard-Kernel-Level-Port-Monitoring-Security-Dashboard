"""
DNS message parsing (RFC 1035), for the payload samples the eBPF agent
sends. Everything here comes from untrusted packets: names are length- and
loop-checked, and a malformed message raises DNSParseError.
"""

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
          99: "SPF", 255: "ANY"}

MAX_POINTERS = 32  # compression pointers followed per name


class DNSParseError(ValueError):
    pass


@dataclass
class DNSMessage:
    id: int
    is_response: bool
    opcode: int
    rcode: int
    questions: List[Tuple[str, int]]  # (name, qtype)
    answer_types: List[int] = field(default_factory=list)
    answer_count: int = 0

    @property
    def qname(self) -> Optional[str]:
        return self.questions[0][0] if self.questions else None

    @property
    def qtype(self) -> Optional[int]:
        return self.questions[0][1] if self.questions else None


def qtype_name(qtype: Optional[int]) -> str:
    if qtype is None:
        return "?"
    return QTYPES.get(qtype, f"TYPE{qtype}")


def _read_name(data: bytes, pos: int) -> Tuple[str, int]:
    """Read a (possibly compressed) name at pos; returns (name, position after it)"""
    labels: List[str] = []
    end = None
    jumps = 0
    length = 0
    while True:
        if pos >= len(data):
            raise DNSParseError("name runs past the message")
        n = data[pos]
        if n & 0xC0 == 0xC0:  # pointer
            if pos + 1 >= len(data):
                raise DNSParseError("truncated pointer")
            jumps += 1
            if jumps > MAX_POINTERS:
                raise DNSParseError("compression loop")
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            continue
        if n & 0xC0:
            raise DNSParseError("unsupported label type")
        pos += 1
        if n == 0:
            break
        if pos + n > len(data):
            raise DNSParseError("label runs past the message")
        label = data[pos:pos + n]
        pos += n
        length += n + 1
        if length > 255:
            raise DNSParseError("name too long")
        # Keep binary labels readable (iodine's raw encoding uses bytes > 127)
        labels.append(label.decode("latin-1").lower())
    return ".".join(labels), (end if end is not None else pos)


def parse_dns(data: bytes) -> DNSMessage:
    if len(data) < 12:
        raise DNSParseError("shorter than a DNS header")
    msg_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    msg = DNSMessage(id=msg_id, is_response=bool(flags & 0x8000), opcode=(flags >> 11) & 0xF,
                     rcode=flags & 0xF, questions=[], answer_count=ancount)
    pos = 12
    for _ in range(min(qdcount, 16)):
        name, pos = _read_name(data, pos)
        if pos + 4 > len(data):
            raise DNSParseError("truncated question")
        qtype, _qclass = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        msg.questions.append((name, qtype))
    for _ in range(min(ancount, 64)):
        try:
            _name, pos = _read_name(data, pos)
            rtype, _cls, _ttl, rdlength = struct.unpack("!HHIH", data[pos:pos + 10])
        except (DNSParseError, struct.error):
            break  # answers are optional detail; a truncated sample still has its question
        msg.answer_types.append(rtype)
        pos += 10 + rdlength
    return msg


# ---- names ----

# Second-level labels under country codes that act as public suffixes (co.uk, com.au, ...)
SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "mil"}


def base_domain(name: str) -> str:
    """
    The registered domain a name belongs to (example.co.uk for a.b.example.co.uk).
    A compact approximation of the Public Suffix List: the last two labels, or
    three when the second-last is a generic second level under a 2-letter TLD.
    """
    labels = [label for label in name.rstrip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain(name: str) -> str:
    base = base_domain(name)
    name = name.rstrip(".")
    return name[: -len(base)].rstrip(".") if name.endswith(base) else ""


def entropy(text: str) -> float:
    """Shannon entropy in bits per character"""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
