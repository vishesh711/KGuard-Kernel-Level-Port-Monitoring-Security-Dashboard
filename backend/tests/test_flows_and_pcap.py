"""Phase 5: IPFIX flow export (N5.10) and packet capture on alert (N5.11)"""

import ipaddress
import socket
import struct
import time
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.services import packet_capture as pc
from app.services.flow_export import (
    END_ACTIVE,
    END_FIN,
    END_IDLE,
    MAX_MESSAGE,
    TEMPLATE_V4,
    TEMPLATE_V6,
    FlowExporter,
    parse_collectors,
)

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


# ---- an independent IPFIX decoder (RFC 7011), to check what goes on the wire ----

def decode(message: bytes, templates: dict) -> dict:
    version, length, export_time, sequence, domain = struct.unpack_from("!HHIII", message)
    assert version == 10 and length == len(message)
    records, pos = [], 16
    while pos < length:
        set_id, set_len = struct.unpack_from("!HH", message, pos)
        body, pos = message[pos + 4:pos + set_len], pos + set_len
        if set_id == 2:
            off = 0
            while off < len(body):
                tid, count = struct.unpack_from("!HH", body, off)
                off += 4
                templates[tid] = [struct.unpack_from("!HH", body, off + 4 * i) for i in range(count)]
                off += 4 * count
        else:
            fields = templates[set_id]
            size = sum(length for _ie, length in fields)
            for start in range(0, len(body) - size + 1, size):
                record, off = {}, start
                for ie, flen in fields:
                    raw = body[off:off + flen]
                    record[ie] = (str(ipaddress.ip_address(raw)) if ie in (8, 12, 27, 28)
                                  else int.from_bytes(raw, "big"))
                    off += flen
                records.append(record)
    return {"time": export_time, "sequence": sequence, "domain": domain, "records": records}


def event(src="10.0.0.5", dst="10.0.0.1", sport=40000, dport=443, protocol="TCP", flags=ACK, t=0,
          ip_len=52, direction="in", ifindex=2, host_id=None, netns=0xF0000000):
    return SimpleNamespace(netns=netns, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                           protocol=protocol,
                           flags=flags, timestamp=1_700_000_000_000_000_000 + int(t * 1e9), ip_len=ip_len,
                           direction=direction, ifindex=ifindex, host_id=host_id)


@pytest.fixture
def exporter():
    x = FlowExporter(["127.0.0.1:4739"])
    x.sent = []
    x._send = x.sent.append
    return x


def exported(x):
    templates = {}
    return [decode(m, templates) for m in x.sent]


def test_tcp_connection_becomes_one_flow_ended_by_fin(exporter):
    events = [event(flags=SYN, ip_len=60), event(flags=ACK, t=0.01),
              event(flags=PSH | ACK, t=0.02, ip_len=1500), event(flags=FIN | ACK, t=0.03)]
    exporter.observe(events, now=100.0)
    assert exporter.tick(now=101.0) == 0  # FIN grace period
    assert exporter.tick(now=102.5) == 1
    (msg,) = exported(exporter)
    (r,) = msg["records"]
    assert (r[8], r[12], r[7], r[11], r[4]) == ("10.0.0.5", "10.0.0.1", 40000, 443, 6)
    assert (r[2], r[1], r[6], r[136], r[61]) == (4, 1664, SYN | ACK | PSH | FIN, END_FIN, 0)
    assert r[153] - r[152] == 30  # milliseconds
    assert msg["sequence"] == 0 and msg["domain"] == 0


def test_idle_and_active_timeouts(exporter):
    exporter.observe([event(protocol="UDP", flags=0, dport=53, t=0)], now=100.0)
    exporter.observe([event(sport=1, dport=2, t=0), event(sport=1, dport=2, t=61)], now=100.0)
    assert exporter.tick(now=101.0) == 1  # the 61-second flow
    assert exporter.tick(now=116.0) == 1  # the idle UDP flow
    reasons = [r[136] for m in exported(exporter) for r in m["records"]]
    assert reasons == [END_ACTIVE, END_IDLE]


def test_loopback_packets_are_counted_once(exporter):
    out = event(src="127.0.0.1", dst="127.0.0.1", direction="out", ifindex=1)
    back = event(src="127.0.0.1", dst="127.0.0.1", direction="in", ifindex=1)
    exporter.observe([out, back], now=100.0)
    exporter.flush()
    (r,) = exported(exporter)[0]["records"]
    assert r[2] == 1 and r[61] == 1


def test_each_network_namespace_is_its_own_observation_domain(exporter):
    """A packet from a container is seen leaving its namespace and arriving in the host's"""
    leaving = event(src="10.200.0.2", dst="10.200.0.1", direction="out", netns=4026532177)
    arriving = event(src="10.200.0.2", dst="10.200.0.1", direction="in")
    exporter.observe([leaving, arriving], now=100.0)
    exporter.flush()
    by_domain = {m["domain"]: m["records"] for m in exported(exporter)}
    assert set(by_domain) == {0, 4026532177}
    assert [r[2] for r in by_domain[0]] == [1] and [r[2] for r in by_domain[4026532177]] == [1]


def test_ipv6_agents_and_sequence_numbers(exporter):
    exporter.observe([event(src="2001:db8::1", dst="2001:db8::2", host_id=7, direction="out")] +
                     [event(sport=10000 + i) for i in range(60)], now=100.0)
    exporter.flush()
    msgs = exported(exporter)
    assert all(len(m) <= MAX_MESSAGE for m in exporter.sent)
    local = [m for m in msgs if m["domain"] == 0]
    assert len(local) >= 2  # 60 records do not fit in one 1400-byte message
    assert [m["sequence"] for m in local] == [0] + [sum(len(m["records"]) for m in local[:i])
                                                    for i in range(1, len(local))]
    assert sum(len(m["records"]) for m in local) == 60
    (agent,) = [m for m in msgs if m["domain"] == 7]
    assert agent["records"][0][27] == "2001:db8::1" and agent["records"][0][61] == 1


def test_templates_are_refreshed(exporter):
    first = exporter.messages(0, [], now=100.0)  # nothing to send: no message
    assert first == []
    from app.services.flow_export import encode_record
    rec = encode_record((None, "10.0.0.1", "10.0.0.2", 1, 2, "TCP"),
                        SimpleNamespace(family=4, direction=0, ifindex=1, first_ns=0, last_ns=0, packets=1,
                                        octets=40, tcp_flags=0), END_IDLE)
    with_templates = exporter.messages(0, [rec], now=100.0)[0]
    without = exporter.messages(0, [rec], now=110.0)[0]
    refreshed = exporter.messages(0, [rec], now=131.0)[0]
    assert struct.unpack_from("!H", with_templates, 16)[0] == 2
    assert struct.unpack_from("!H", without, 16)[0] == TEMPLATE_V4
    assert struct.unpack_from("!H", refreshed, 16)[0] == 2
    templates = {}
    decode(with_templates, templates)
    assert set(templates) == {TEMPLATE_V4, TEMPLATE_V6}
    assert len(templates[TEMPLATE_V4]) == len(templates[TEMPLATE_V6]) == 13


def test_records_reach_a_real_collector():
    collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    collector.bind(("127.0.0.1", 0))
    collector.settimeout(2)
    x = FlowExporter([f"127.0.0.1:{collector.getsockname()[1]}"])
    x.observe([event()], now=100.0)
    x.flush()
    data, _ = collector.recvfrom(2048)
    assert decode(data, {})["records"][0][11] == 443
    assert x.get_stats()["messages_sent"] == 1


def test_collector_parsing_and_off_by_default():
    assert parse_collectors(["10.0.0.9:4739", "[2001:db8::9]:2055", "collector", "2001:db8::7",
                             "bad:port", "host:70000"]) == \
        [("10.0.0.9", 4739), ("2001:db8::9", 2055), ("collector", 4739), ("2001:db8::7", 4739)]
    x = FlowExporter([])
    x.observe([event()])
    assert not x.enabled and not x.flows


# ---- packet capture: TPACKET_V3 blocks, selection, pcap files ----

def ipv4_tcp(src, dst, sport, dport, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, SYN, 1024, 0, 0) + payload
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + tcp


def tpacket_block(packets):
    """A block as the kernel lays it out: block descriptor, then tpacket3_hdr + sockaddr_ll + data each"""
    body, offset = b"", 48
    entries = []
    for i, (sec, nsec, data, ifindex, pkttype) in enumerate(packets):
        mac = pc.SLL_OFFSET + 32
        size = (mac + len(data) + 15) & ~15
        last = i == len(packets) - 1
        hdr = pc.PACKET_HEADER.pack(0 if last else size, sec, nsec, len(data), len(data) + 100, 1, mac, mac)
        hdr = hdr.ljust(pc.SLL_OFFSET, b"\0") + pc.SOCKADDR_LL.pack(17, 0x0800, ifindex, 1, pkttype, 6)
        entries.append((hdr.ljust(mac, b"\0") + data).ljust(size, b"\0"))
    body = b"".join(entries)
    header = pc.BLOCK_HEADER.pack(3, 0, pc.TP_STATUS_USER, len(packets), offset, 48 + len(body))
    return header.ljust(48, b"\0") + body


def test_block_walk_skips_loopback_duplicates():
    now = int(time.time())
    block = tpacket_block([
        (now, 1, ipv4_tcp("10.0.0.5", "10.0.0.1", 40000, 22), 2, 0),
        (now, 2, ipv4_tcp("127.0.0.1", "127.0.0.1", 40001, 80), 1, pc.PACKET_OUTGOING),
        (now, 3, ipv4_tcp("127.0.0.1", "127.0.0.1", 40001, 80), 1, 0),
    ])
    packets = list(pc.iter_block(block))
    assert [p[1] for p in packets] == [1, 3]
    assert packets[0][3] == len(packets[0][2]) + 100  # original length kept
    assert pc.addresses(packets[0][2]) == ("10.0.0.5", "10.0.0.1", 40000, 22)


def test_iter_block_survives_garbage():
    block = bytearray(tpacket_block([(1, 1, ipv4_tcp("1.1.1.1", "2.2.2.2", 1, 2), 2, 0)]))
    block[48:52] = struct.pack("=I", 10**6)  # next_offset far outside the block
    struct.pack_into("=I", block, 12, 5)  # claims 5 packets
    assert len(list(pc.iter_block(bytes(block)))) == 1


def test_selection_and_pcap_file(tmp_path):
    now = time.time()
    sec = int(now)
    block = tpacket_block([
        (sec - 100, 0, ipv4_tcp("10.9.9.9", "10.0.0.1", 1, 22), 2, 0),  # too old
        (sec - 5, 0, ipv4_tcp("10.9.9.9", "10.0.0.1", 2, 22), 2, 0),
        (sec - 4, 0, ipv4_tcp("10.0.0.1", "10.9.9.9", 22, 2), 2, 0),     # the reply
        (sec - 3, 0, ipv4_tcp("10.8.8.8", "10.0.0.1", 3, 443), 2, 0),    # someone else
    ])
    chosen = pc.select_packets([(now, block)], {"10.9.9.9"}, None, now - 30, now)
    assert len(chosen) == 2
    flood = pc.select_packets([(now, block)], {"10.0.0.1"}, 443, now - 30, now)
    assert len(flood) == 1

    path = tmp_path / "x.pcap"
    pc.write_pcap(path, chosen, 256)
    data = path.read_bytes()
    magic, major, minor, _tz, _sig, snaplen, linktype = struct.unpack_from("<IHHiIII", data)
    assert (magic, major, minor, snaplen, linktype) == (0xA1B23C4D, 2, 4, 256, 101)
    sec0, _nsec, incl, orig = struct.unpack_from("<IIII", data, 24)
    assert sec0 == sec - 5 and incl == 40 and orig == 140


def test_alert_gets_its_capture(db, tmp_path, client):
    capture = pc.PacketCapture()
    capture.directory = tmp_path
    alert = SecurityAlert(timestamp=datetime.utcnow(), alert_type=AlertType.PORT_SCAN,
                          severity=AlertSeverity.HIGH, title="scan", description="d", src_ip="10.9.9.9")
    db.add(alert)
    db.commit()
    now = time.time()
    capture._keep(tpacket_block([(int(now) - 2, 0, ipv4_tcp("10.9.9.9", "10.0.0.1", 2, 22), 2, 0)]), now=now)

    info = {"id": alert.id, "severity": "HIGH", "src_ip": "10.9.9.9", "host_id": None}
    assert not capture.wants(info)  # not running
    capture.thread = object()
    assert capture.wants(info)
    assert not capture.wants({**info, "severity": "MEDIUM"})
    assert not capture.wants({**info, "host_id": 3})  # an agent's traffic is not visible here

    path = capture.save(info, now=now)
    assert path and path.name == f"alert-{alert.id}.pcap"
    db.refresh(alert)
    assert alert.alert_metadata["pcap"]["packets"] == 1

    pc.packet_capture.directory = tmp_path
    response = client.get(f"/api/alerts/{alert.id}/pcap")
    assert response.status_code == 200 and response.content[:4] == struct.pack("<I", 0xA1B23C4D)
    assert client.get("/api/alerts/999999/pcap").status_code == 404


def test_old_blocks_are_dropped():
    capture = pc.PacketCapture()
    capture.seconds, capture.post_seconds, capture.budget = 10, 0, 10_000
    capture._keep(b"x" * 4000, now=100.0)
    capture._keep(b"y" * 4000, now=105.0)
    capture._keep(b"z" * 4000, now=112.0)  # first block now too old
    assert [b[:1] for _t, b in capture.blocks] == [b"y", b"z"]
    capture._keep(b"w" * 4000, now=113.0)  # over the byte budget
    assert [b[:1] for _t, b in capture.blocks] == [b"z", b"w"]
