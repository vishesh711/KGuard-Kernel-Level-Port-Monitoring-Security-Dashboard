"""
TLS ClientHello parsing and client fingerprints (JA3, JA4).

A ClientHello is sent in clear text at the start of every TLS connection
(up to TLS 1.3; with Encrypted Client Hello only the outer one is visible).
Which cipher suites, extensions, groups and signature algorithms a client
offers, and in what order, depends on its TLS library and settings, so it
identifies the client software (curl/OpenSSL, Chrome/BoringSSL, Python,
malware toolkits...) independently of the destination.

JA3 (Salesforce, 2017):
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
  decimal values joined by "-", GREASE values removed, in the order sent;
  the fingerprint is the MD5 of that string. Browsers that shuffle their
  extension order (Chrome since version 110) get a new JA3 per connection.

JA4 (FoxIO, 2023), e.g. t13d1516h2_8daaf6152771_02713d6af862:
  a  protocol (t = TCP), highest TLS version offered, d/i (SNI present or
     not), number of ciphers and of extensions (2 digits each, no GREASE),
     first and last character of the first ALPN value ("00" if none)
  b  first 12 hex chars of SHA-256 of the sorted cipher list (4-digit hex)
  c  first 12 hex chars of SHA-256 of the sorted extension list without
     SNI and ALPN, then "_" and the signature algorithms in the order sent
  Sorting makes JA4 stable against extension shuffling.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

VERSION_NAMES = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
                 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


class TLSParseError(ValueError):
    pass


def is_grease(value: int) -> bool:
    """RFC 8701 reserved values: 0x0a0a, 0x1a1a, ..., 0xfafa"""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: List[int]
    extensions: List[int]  # in the order sent, GREASE included
    groups: List[int] = field(default_factory=list)
    point_formats: List[int] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)
    alpn: List[str] = field(default_factory=list)
    sni: Optional[str] = None

    @property
    def tls_version(self) -> int:
        """Highest version offered (supported_versions, else the legacy field)"""
        offered = [v for v in self.supported_versions if not is_grease(v)]
        return max(offered) if offered else self.legacy_version

    # ---- JA3 ----
    @property
    def ja3_string(self) -> str:
        def join(values):
            return "-".join(str(v) for v in values if not is_grease(v))
        return ",".join([str(self.legacy_version), join(self.ciphers), join(self.extensions),
                         join(self.groups), "-".join(str(v) for v in self.point_formats)])

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string.encode()).hexdigest()

    # ---- JA4 ----
    def _ja4_parts(self, protocol: str = "t"):
        ciphers = [c for c in self.ciphers if not is_grease(c)]
        extensions = [e for e in self.extensions if not is_grease(e)]
        alpn = self.alpn[0] if self.alpn else ""
        if not alpn:
            alpn_code = "00"
        elif alpn[0].isascii() and alpn[0].isalnum() and alpn[-1].isascii() and alpn[-1].isalnum():
            alpn_code = alpn[0] + alpn[-1]
        else:
            raw = alpn.encode("latin-1").hex()
            alpn_code = raw[0] + raw[-1]
        a = (f"{protocol}{VERSION_NAMES.get(self.tls_version, '00')}{'d' if self.sni else 'i'}"
             f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn_code}")
        cipher_list = ",".join(f"{c:04x}" for c in sorted(ciphers))
        ext_list = ",".join(f"{e:04x}" for e in sorted(extensions)
                            if e not in (EXT_SERVER_NAME, EXT_ALPN))
        sigs = ",".join(f"{s:04x}" for s in self.signature_algorithms if not is_grease(s))
        c_raw = f"{ext_list}_{sigs}" if sigs else ext_list
        return a, cipher_list, c_raw

    @property
    def ja4(self) -> str:
        a, cipher_list, c_raw = self._ja4_parts()

        def digest(text):
            return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"
        return f"{a}_{digest(cipher_list)}_{digest(c_raw)}"

    @property
    def ja4_r(self) -> str:
        """JA4 before hashing (FoxIO's "ja4_r"), for inspection"""
        a, cipher_list, c_raw = self._ja4_parts()
        return f"{a}_{cipher_list}_{c_raw}"

    @property
    def version_name(self) -> str:
        return {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0",
                0x0300: "SSL 3.0"}.get(self.tls_version, f"0x{self.tls_version:04x}")


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise TLSParseError("truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector(self, length_bytes: int) -> bytes:
        n = self.u8() if length_bytes == 1 else self.u16()
        return self.take(n)

    @property
    def left(self) -> int:
        return len(self.data) - self.pos


def _u16_list(data: bytes) -> List[int]:
    return [v for (v,) in struct.iter_unpack("!H", data[: len(data) // 2 * 2])]


def record_length(data: bytes) -> Optional[int]:
    """Total length of the TLS record starting data, or None if it is not a ClientHello record"""
    if len(data) < 6 or data[0] != 22 or data[1] != 3 or data[5] != 1:
        return None
    return 5 + struct.unpack("!H", data[3:5])[0]


def parse_client_hello(data: bytes) -> ClientHello:
    """Parse a TLS record holding a ClientHello (as sent on the wire)"""
    r = _Reader(data)
    if r.u8() != 22:
        raise TLSParseError("not a handshake record")
    r.u16()  # record version
    record = _Reader(r.vector(2))
    if record.u8() != 1:
        raise TLSParseError("not a ClientHello")
    body = _Reader(record.take(min(record.u24(), record.left)))

    legacy_version = body.u16()
    body.take(32)  # random
    body.vector(1)  # session id
    ciphers = _u16_list(body.vector(2))
    body.vector(1)  # compression methods
    hello = ClientHello(legacy_version=legacy_version, ciphers=ciphers, extensions=[])
    if not body.left:
        return hello

    exts = _Reader(body.vector(2))
    while exts.left >= 4:
        ext_type = exts.u16()
        ext = exts.vector(2)
        hello.extensions.append(ext_type)
        try:
            _parse_extension(hello, ext_type, ext)
        except TLSParseError:
            pass  # a malformed extension body does not hide the others
    return hello


def _parse_extension(hello: ClientHello, ext_type: int, ext: bytes) -> None:
    r = _Reader(ext)
    if ext_type == EXT_SERVER_NAME and ext:
        names = _Reader(r.vector(2))
        while names.left >= 3:
            name_type = names.u8()
            name = names.vector(2)
            if name_type == 0:
                hello.sni = name.decode("ascii", errors="replace")[:255]
                break
    elif ext_type == EXT_SUPPORTED_GROUPS:
        hello.groups = _u16_list(r.vector(2))
    elif ext_type == EXT_EC_POINT_FORMATS:
        hello.point_formats = list(r.vector(1))
    elif ext_type == EXT_SIGNATURE_ALGORITHMS:
        hello.signature_algorithms = _u16_list(r.vector(2))
    elif ext_type == EXT_SUPPORTED_VERSIONS:
        hello.supported_versions = _u16_list(r.vector(1))
    elif ext_type == EXT_ALPN:
        protocols = _Reader(r.vector(2))
        while protocols.left:
            hello.alpn.append(protocols.vector(1).decode("latin-1"))
