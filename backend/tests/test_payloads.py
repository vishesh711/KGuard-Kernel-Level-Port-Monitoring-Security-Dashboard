"""Phase 5 payload analysis: TLS fingerprints (JA3/JA4, SNI) and DNS tunnelling"""

import base64
import hashlib
import json
import random
import struct
import time
from pathlib import Path

import pytest

from app.models.payload import DnsQuery, TlsHandshake
from app.models.security_alert import AlertType, SecurityAlert
from app.services.dns_parser import DNSParseError, base_domain, entropy, parse_dns, subdomain
from app.services.payloads import load_blocklist, payload_service
from app.services.tls_parser import TLSParseError, is_grease, parse_client_hello, record_length

from .test_agents import enroll, enrollment, send  # noqa: F401  (enrollment is a fixture)

FIXTURES = Path(__file__).parent / "fixtures" / "tls"
EXPECTED = json.loads((FIXTURES / "expected.json").read_text())["cases"]


def hello(name: str) -> bytes:
    return (FIXTURES / f"{name}.bin").read_bytes()


# ---- TLS: real ClientHellos, checked against Wireshark 4.2.2 ----

@pytest.mark.parametrize("case", EXPECTED, ids=[c["name"] for c in EXPECTED])
def test_ja3_matches_wireshark(case):
    parsed = parse_client_hello(hello(case["name"]))
    assert parsed.ja3_string == case["wireshark_ja3_string"]
    assert parsed.ja3 == case["wireshark_ja3"]
    assert parsed.sni == case["sni"]
    assert parsed.alpn[0] == case["alpn"]


def wireshark_style_ja4(parsed) -> str:
    """JA4 as Wireshark 4.2.2 computes it: GREASE kept in the signature algorithms"""
    a, ciphers, rest = parsed.ja4_r.split("_", 2)
    exts = rest.split("_")[0]
    sigs = ",".join(f"{v:04x}" for v in parsed.signature_algorithms)
    c = f"{exts}_{sigs}" if sigs else exts
    def h(text):
        return hashlib.sha256(text.encode()).hexdigest()[:12]
    return f"{a}_{h(ciphers)}_{h(c)}"


@pytest.mark.parametrize("case", EXPECTED, ids=[c["name"] for c in EXPECTED])
def test_ja4_matches_wireshark(case):
    parsed = parse_client_hello(hello(case["name"]))
    assert wireshark_style_ja4(parsed) == case["wireshark_ja4"]
    if not any(is_grease(s) for s in parsed.signature_algorithms):
        assert parsed.ja4 == case["wireshark_ja4"]  # curl, requests: identical


def test_known_clients():
    curl, requests_ = parse_client_hello(hello("curl")), parse_client_hello(hello("python-requests"))
    assert curl.ja4 == "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6"
    assert requests_.ja4 == "t13d1812h1_85036bcba153_b26ce05bbdd6"
    assert curl.version_name == "TLS 1.3"


def test_chrome_ja4_is_stable_while_ja3_changes():
    """Chrome shuffles its extensions (new JA3 each time) and picks random GREASE values"""
    first, second = parse_client_hello(hello("chrome-1")), parse_client_hello(hello("chrome-2"))
    assert first.ja3 != second.ja3
    assert first.ja4 == second.ja4 == "t13d1517h2_8daaf6152771_344585cda68d"
    # A resumed session adds pre_shared_key (41): a different, but also stable, JA4
    resumed = [parse_client_hello(hello(n)) for n in ("chrome-1-resumed", "chrome-2-resumed")]
    assert resumed[0].ja4 == resumed[1].ja4 != first.ja4
    assert 41 in resumed[0].extensions


def test_grease_values():
    assert all(is_grease(v) for v in (0x0A0A, 0x1A1A, 0xFAFA))
    assert not any(is_grease(v) for v in (0x0A1A, 0x1301, 0x0000))


def test_malformed_hellos_are_rejected():
    data = hello("curl")
    assert record_length(data) == len(data)
    assert record_length(b"GET / HTTP/1.1\r\n") is None
    with pytest.raises(TLSParseError):
        parse_client_hello(data[:60])
    with pytest.raises(TLSParseError):
        parse_client_hello(b"\x17\x03\x03\x00\x05hello")
    for _ in range(200):  # random corruption never crashes the parser
        corrupt = bytearray(data)
        for _ in range(5):
            corrupt[random.randrange(5, len(corrupt))] = random.randrange(256)
        try:
            parse_client_hello(bytes(corrupt))
        except TLSParseError:
            pass


# ---- DNS parsing ----

def dns_query(name: str, qtype: int = 1, msg_id: int = 0x1234, response: bool = False) -> bytes:
    flags = 0x8180 if response else 0x0100
    labels = b"".join(bytes([len(p)]) + p.encode("latin-1") for p in name.split(".")) + b"\0"
    header = struct.pack("!HHHHHH", msg_id, flags, 1, 1 if response else 0, 0, 0)
    return header + labels + struct.pack("!HH", qtype, 1)


def test_parse_query_and_compressed_answer():
    msg = parse_dns(dns_query("www.Example.com", qtype=28))
    assert (msg.qname, msg.qtype, msg.is_response) == ("www.example.com", 28, False)
    # Response whose answer name is a pointer back to the question (offset 12)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    msg = parse_dns(dns_query("example.com", response=True) + answer)
    assert msg.is_response and msg.answer_types == [1] and msg.rcode == 0


def test_hostile_dns_messages():
    with pytest.raises(DNSParseError):
        parse_dns(b"\x00" * 5)
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    with pytest.raises(DNSParseError):
        parse_dns(loop)
    too_long = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + (b"\x3f" + b"a" * 63) * 5 + b"\0\0\1\0\1"
    with pytest.raises(DNSParseError):
        parse_dns(too_long)


def test_registered_domains():
    assert base_domain("a.b.example.com") == "example.com"
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert base_domain("x.y.t.lab") == "t.lab"
    assert subdomain("paab3.t.lab") == "paab3"
    assert subdomain("example.com") == ""
    assert entropy("aaaa") == 0 and round(entropy("abcd"), 2) == 2.0


# ---- ingest through the agent API ----

def sample(kind, data, src="10.1.0.5", sport=40000, dst="10.1.0.1", dport=443, seq=1000, direction="out",
           comm="curl", pid=4321, ts=None):
    return {"type": "payload", "kind": kind, "timestamp": ts or time.time_ns(), "family": 4, "src_ip": src,
            "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": "TCP" if kind == "tls" else "UDP",
            "direction": direction, "netns": 1, "ifindex": 2, "tcp_seq": seq, "orig_len": len(data),
            "pid": pid, "comm": comm, "data": base64.b64encode(data).decode()}


@pytest.fixture
def agent(client, enrollment):  # noqa: F811
    return enroll(client, "edge-1").json()


def test_split_client_hello_is_reassembled(client, agent, db):
    data = hello("chrome-1")
    first, rest = data[:1000], data[1000:]
    # Continuation first, then a duplicate of it, then the first segment
    batch = [sample("tls", rest, seq=2000, comm="chrome"), sample("tls", rest, seq=2000, comm="chrome"),
             sample("tls", first, seq=1000, comm="chrome")]
    reply = send(client, agent["token"], [], payloads=batch).json()
    assert reply["payloads_accepted"] == 3
    (row,) = db.query(TlsHandshake).all()
    assert (row.sni, row.alpn, row.tls_version) == ("test.lab", "h2", "TLS 1.3")
    assert row.ja4 == "t13d1517h2_8daaf6152771_344585cda68d"
    assert (row.process_name, row.pid, row.direction) == ("chrome", 4321, "out")
    assert row.host_id == agent["agent_id"]

    groups = client.get("/api/tls/fingerprints").json()
    assert groups[0]["ja4"] == row.ja4 and groups[0]["processes"] == {"chrome": 1}


def test_loopback_duplicates_are_stored_once(client, agent, db):
    data = hello("curl")
    batch = [sample("tls", data, direction="out"), sample("tls", data, direction="in", comm="nginx")]
    send(client, agent["token"], [], payloads=batch)
    assert db.query(TlsHandshake).count() == 1
    assert client.get("/api/tls/handshakes?ja3=" + parse_client_hello(data).ja3).json()["total"] == 1


def test_invalid_samples_are_skipped(client, agent, db):
    assert send(client, agent["token"], [], payloads=["not an object"]).status_code == 422
    bad = [{"kind": "tls", "data": "!!!"}, sample("dns", b"\x00\x01"), {"kind": "smtp"},
           sample("tls", b"x" * 2000)]  # longer than the eBPF program ever sends
    reply = send(client, agent["token"], [], payloads=bad).json()
    assert reply["payloads_accepted"] == 1  # the short DNS message decodes but does not parse
    assert db.query(DnsQuery).count() == 0


def test_dns_queries_and_responses_are_stored(client, agent, db):
    batch = [sample("dns", dns_query("www.example.com"), dport=53, sport=5353, comm="firefox"),
             sample("dns", dns_query("www.example.com", response=True), src="10.1.0.1", sport=53,
                    dst="10.1.0.5", dport=5353, direction="in", pid=-1, comm="")]
    send(client, agent["token"], [], payloads=batch)
    query, response = db.query(DnsQuery).order_by(DnsQuery.id).all()
    assert (query.client_ip, query.server_ip, query.domain, query.qtype_name) == \
        ("10.1.0.5", "10.1.0.1", "example.com", "A")
    assert query.process_name == "firefox"
    assert response.is_response and response.client_ip == "10.1.0.5" and response.answer_count == 1
    assert client.get("/api/dns/queries").json()["total"] == 1  # responses hidden by default


def iodine_names(n, domain="t.lab"):
    rng = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyz012345"
    for i in range(n):
        data = "".join(rng.choice(alphabet) for _ in range(110))
        yield f"p{i:04x}{data[:57]}.{data[57:]}.{domain}"


def test_iodine_like_traffic_is_a_dns_tunnel(client, agent, db):
    batch = [sample("dns", dns_query(name, qtype=10, msg_id=i), dport=53, sport=30000 + i, comm="iodine")
             for i, name in enumerate(iodine_names(40))]
    send(client, agent["token"], [], payloads=batch)
    (alert,) = db.query(SecurityAlert).filter(SecurityAlert.alert_type == AlertType.DNS_TUNNELING).all()
    meta = alert.alert_metadata
    assert alert.title == "DNS Tunnel Suspected: 10.1.0.5 via t.lab"
    assert meta["record_types"] == {"NULL": 20}  # alerted at the 20th query
    assert meta["score"] >= 0.9 and meta["unique_ratio"] == 1.0

    domains = client.get("/api/dns/domains").json()
    assert domains[0]["domain"] == "t.lab" and domains[0]["score"] >= 0.9


def test_ordinary_lookups_are_not_a_tunnel(client, agent, db):
    names = ["www.google.com", "fonts.googleapis.com", "fonts.gstatic.com", "www.gstatic.com",
             "apis.google.com",
             "r4---sn-4g5e6nsz.googlevideo.com", "r3---sn-ab5l6nrz.googlevideo.com", "i.ytimg.com",
             "www.youtube.com", "yt3.ggpht.com"] * 6
    # IPv6 reverse lookups: long and unique, but allowlisted
    names += [".".join(f"{random.randrange(16):x}" for _ in range(32)) + ".ip6.arpa" for _ in range(40)]
    batch = [sample("dns", dns_query(n, qtype=12 if n.endswith("arpa") else 1, msg_id=i), dport=53,
                    sport=20000 + i) for i, n in enumerate(names)]
    send(client, agent["token"], [], payloads=batch)
    assert db.query(SecurityAlert).count() == 0


def test_long_but_repeated_names_are_not_a_tunnel(client, agent, db):
    names = [f"internal-my-service-loadbalancer-{i}.us-east-1.elb.amazonaws.com" for i in range(4)] * 10
    batch = [sample("dns", dns_query(n, msg_id=i), dport=53, sport=20000 + i) for i, n in enumerate(names)]
    send(client, agent["token"], [], payloads=batch)
    assert db.query(SecurityAlert).count() == 0


def test_blocklisted_tls_fingerprint(client, agent, db, tmp_path):
    ja3 = parse_client_hello(hello("python-requests")).ja3
    listing = tmp_path / "ja3.csv"
    listing.write_text("# ja3_md5,Firstseen,Lastseen,Listingreason\n"
                       f"{ja3},2024-01-01,2024-02-01,Test Loader C&C\n")
    payload_service.blocklist = load_blocklist(str(listing))
    send(client, agent["token"], [], payloads=[sample("tls", hello("python-requests"), comm="python3")])
    (alert,) = db.query(SecurityAlert).filter(SecurityAlert.alert_type == AlertType.MALICIOUS_TLS).all()
    assert "Test Loader C&C" in alert.title
    assert "python3 on 10.1.0.5" in alert.description
    assert db.query(TlsHandshake).one().known_bad.startswith("2024-01-01")
