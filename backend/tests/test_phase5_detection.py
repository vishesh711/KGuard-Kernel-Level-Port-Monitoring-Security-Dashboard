"""Phase 5 detection: scan types, noise, brute force, SYN floods, baseline"""

import random
import time
from datetime import datetime, timedelta

import pytest

from app.models.network_event import NetworkEvent
from app.models.security_alert import AlertType, SecurityAlert
from app.services.anomaly_detector import anomaly_detector
from app.services.baseline import TrafficBaseline, traffic_baseline
from app.services.kernel_alerts import kernel_alerts
from app.services.kguard_device import build_fake_device
from app.services.probes import classify_probe

from .test_device import v2_event

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# What each nmap scan type looks like (observed on Linux 6.8, see probes.py)
NMAP = {
    "syn": ("TCP", SYN, "new"),
    "fin": ("TCP", FIN, "invalid"),
    "null": ("TCP", 0, "invalid"),
    "xmas": ("TCP", FIN | PSH | URG, "invalid"),
    "ack": ("TCP", ACK, "new"),
    "maimon": ("TCP", FIN | ACK, "invalid"),
    "udp": ("UDP", 0, "new"),
}


@pytest.mark.parametrize("kind", NMAP)
def test_classify_nmap_probes(kind):
    protocol, flags, ct = NMAP[kind]
    assert classify_probe(protocol, flags, ct, 80) == kind


def test_normal_tcp_is_not_a_probe():
    assert classify_probe("TCP", SYN | ACK, "established", 80) is None
    assert classify_probe("TCP", ACK, "established", 80) is None
    assert classify_probe("TCP", ACK | PSH, "established", 443) is None
    assert classify_probe("TCP", FIN | ACK, "established", 443) is None
    assert classify_probe("TCP", RST, "invalid", 80) is None
    assert classify_probe("ICMP", 0, "related", 0) is None


def test_ack_without_conntrack_uses_the_port():
    # eBPF engine: no conntrack. ACKs to this host's ephemeral ports are replies
    assert classify_probe("TCP", ACK, "none", 40000) is None
    assert classify_probe("TCP", ACK, "none", 22) == "ack"


def scan_events(kind, src="198.51.100.66", ports=range(1000, 1025)):
    protocol, flags, ct = NMAP[kind]
    return [v2_event(src_ip=src, dst_port=p, protocol=protocol, flags=flags, ct_state=ct,
                     direction="in")
            for p in ports]


def alerts(db):
    return db.query(SecurityAlert).order_by(SecurityAlert.id).all()


@pytest.mark.parametrize("kind,label", [
    ("syn", "SYN"), ("fin", "FIN"), ("null", "NULL"), ("xmas", "Xmas"),
    ("ack", "ACK"), ("maimon", "Maimon"), ("udp", "UDP"),
])
def test_each_scan_type_is_labelled(fake_device, collect, db, kind, label):
    build_fake_device(fake_device, [scan_events(kind)])
    collect()
    found = [a for a in alerts(db) if a.alert_type == AlertType.PORT_SCAN]
    assert len(found) == 1
    assert found[0].title == f"{label} Scan Detected from 198.51.100.66"
    assert found[0].alert_metadata["scan_type"] == kind
    assert found[0].alert_metadata["unique_ports"] == 25


def test_stealth_scans_are_detected_even_when_the_kernel_handles_syn(fake_device, collect, db):
    anomaly_detector.kernel_detection = True
    build_fake_device(fake_device, [scan_events("syn") + scan_events("fin", ports=range(2000, 2025))])
    collect()
    assert [a.alert_metadata["scan_type"] for a in alerts(db)] == ["fin"]


def test_two_scan_types_from_one_source_give_two_alerts(fake_device, collect, db):
    build_fake_device(fake_device, [scan_events("xmas")])
    collect()
    build_fake_device(fake_device, [scan_events("null", ports=range(3000, 3025))])
    collect()
    assert sorted(a.alert_metadata["scan_type"] for a in alerts(db)) == ["null", "xmas"]


def test_web_traffic_raises_no_alerts(fake_device, collect, db):
    events = []
    for i in range(200):  # 200 visitors, each opening a connection to 443 or 80
        src = f"203.0.113.{i % 250 + 1}" if i < 100 else f"198.51.100.{i % 250 + 1}"
        port = 443 if i % 3 else 80
        events.append(v2_event(src_ip=src, src_port=40000 + i, dst_port=port, flags=SYN, ct_state="new"))
        events.append(v2_event(src_ip=src, src_port=40000 + i, dst_port=port, flags=ACK,
                               ct_state="established"))
    build_fake_device(fake_device, [events])
    collect()
    assert alerts(db) == []


def test_trusted_sources_are_never_alerted(fake_device, collect, db, monkeypatch):
    import ipaddress
    monkeypatch.setattr(anomaly_detector, "trusted_networks", [ipaddress.ip_network("198.51.100.0/24")])
    build_fake_device(fake_device, [scan_events("syn") + scan_events("fin", ports=range(2000, 2025))])
    collect()
    assert alerts(db) == []


def brute(count, port=22, src="203.0.113.45"):
    return [v2_event(src_ip=src, src_port=50000 + i, dst_port=port, flags=SYN, ct_state="new")
            for i in range(count)]


def test_brute_force(fake_device, collect, db):
    build_fake_device(fake_device, [brute(12)])
    collect()
    brute_alerts = [a for a in alerts(db) if a.alert_type == AlertType.BRUTE_FORCE]
    assert len(brute_alerts) == 1
    assert brute_alerts[0].dst_port == 22
    assert brute_alerts[0].alert_metadata["connections"] == 12


def test_few_logins_are_not_brute_force(fake_device, collect, db):
    build_fake_device(fake_device, [brute(9)])
    collect()
    assert not [a for a in alerts(db) if a.alert_type == AlertType.BRUTE_FORCE]


def test_slow_brute_force_over_minutes(fake_device, collect, db):
    """SSH takes several passwords per connection: hydra opens only ~9 connections a minute"""
    t0 = time.time_ns()
    slow = [v2_event(src_ip="198.51.100.40", src_port=41000 + i, dst_port=22, flags=SYN, ct_state="new",
                     timestamp=t0 + int(i * 12.5e9)) for i in range(12)]  # 12 in 150 s
    build_fake_device(fake_device, [slow])
    collect()
    (alert,) = [a for a in alerts(db) if a.alert_type == AlertType.BRUTE_FORCE]
    assert alert.alert_metadata["connections"] == 12


def test_logins_spread_over_longer_than_the_window_are_not_brute_force(fake_device, collect, db):
    t0 = time.time_ns()
    sparse = [v2_event(src_ip="198.51.100.41", src_port=41000 + i, dst_port=22, flags=SYN, ct_state="new",
                       timestamp=t0 + i * 35 * 10**9) for i in range(12)]  # 12 in 6.4 minutes
    build_fake_device(fake_device, [sparse])
    collect()
    assert not [a for a in alerts(db) if a.alert_type == AlertType.BRUTE_FORCE]


def random_sources(count, rng):
    return [f"10.{rng.randrange(1, 255)}.{rng.randrange(256)}.{rng.randrange(1, 255)}" for _ in range(count)]


def test_syn_flood_from_random_sources(fake_device, collect, db):
    rng = random.Random(1)
    events = [v2_event(src_ip=ip, src_port=rng.randrange(1024, 65535), dst_ip="10.0.0.1",
                       dst_port=8080, flags=SYN, ct_state="new")
              for ip in random_sources(300, rng)]
    build_fake_device(fake_device, [events])
    collect()
    floods = [a for a in alerts(db) if a.alert_type == AlertType.SYN_FLOOD]
    assert len(floods) == 1
    flood = floods[0]
    assert (flood.dst_ip, flood.dst_port) == ("10.0.0.1", 8080)
    assert flood.alert_metadata["half_open"] == 300
    assert flood.alert_metadata["distinct_sources"] == 300
    assert "syn_cookies" in flood.alert_metadata
    # Per-source rules see one SYN each: no scan or rate alerts
    assert {a.alert_type for a in alerts(db)} == {AlertType.SYN_FLOOD}


def test_completed_handshakes_are_not_a_flood(fake_device, collect, db):
    rng = random.Random(2)
    events = []
    for ip in random_sources(300, rng):
        sport = rng.randrange(1024, 65535)
        events.append(v2_event(src_ip=ip, src_port=sport, dst_port=8080, flags=SYN, ct_state="new"))
        events.append(v2_event(src_ip=ip, src_port=sport, dst_port=8080, flags=ACK, ct_state="established"))
    build_fake_device(fake_device, [events])
    collect()
    assert not [a for a in alerts(db) if a.alert_type == AlertType.SYN_FLOOD]


def test_baseline_learns_then_flags_a_spike():
    b = TrafficBaseline(alpha=0.1, warmup=10, sigma=6, ratio=5, min_count=100)
    rng = random.Random(3)
    now = datetime(2026, 1, 1)
    for minute in range(30):
        assert b.observe((None, 8080), 20 + rng.randrange(-4, 5), now + timedelta(minutes=minute)) is None
    spike = b.observe((None, 8080), 600, now + timedelta(minutes=30))
    assert spike and spike["count"] == 600 and 15 < spike["mean"] < 25
    # The spike was not learned, and the cooldown stops repeats
    assert b.stats[(None, 8080)].mean < 25
    assert b.observe((None, 8080), 600, now + timedelta(minutes=31)) is None


def test_baseline_needs_warmup_and_a_real_volume():
    b = TrafficBaseline(alpha=0.1, warmup=10, sigma=6, ratio=5, min_count=100)
    now = datetime(2026, 1, 1)
    assert b.observe((1, 22), 5000, now) is None  # first sample: still learning
    for minute in range(1, 20):
        b.observe((1, 22), 1, now + timedelta(minutes=minute))
    assert b.observe((1, 22), 50, now + timedelta(minutes=20)) is None  # 50x, but under min_count


def syn_rows(count, port, created_at):
    return [NetworkEvent(timestamp=time.time_ns(), src_ip=f"10.9.{i // 250}.{i % 250 + 1}", dst_ip="10.0.0.1",
                         src_port=40000, dst_port=port, protocol="TCP", flags=SYN, direction="in",
                         created_at=created_at)
            for i in range(count)]


def test_baseline_tick_raises_unusual_traffic(client, db):
    now = datetime.utcnow()
    for minutes_ago in range(12, 0, -1):  # twelve normal minutes: ~5 attempts each
        t = now - timedelta(minutes=minutes_ago)
        db.add_all(syn_rows(5, 9443, t - timedelta(seconds=30)))
        db.commit()
        assert client.portal.call(traffic_baseline.tick, t) == []

    db.add_all(syn_rows(400, 9443, now - timedelta(seconds=10)))
    db.commit()
    raised = client.portal.call(traffic_baseline.tick, now)
    assert len(raised) == 1
    alert = db.query(SecurityAlert).one()
    assert alert.alert_type == AlertType.UNUSUAL_TRAFFIC
    assert alert.dst_port == 9443
    assert alert.alert_metadata["count"] == 400
    assert alert.alert_metadata["mean"] == pytest.approx(5, abs=0.5)


def test_a_new_port_is_learned_not_flagged(client, db):
    db.add_all(syn_rows(400, 7000, datetime.utcnow() - timedelta(seconds=10)))
    db.commit()
    assert client.portal.call(traffic_baseline.tick) == []


def test_kernel_scan_alert_is_labelled_from_events(client, fake_device, collect, db):
    build_fake_device(fake_device, [scan_events("udp", src="203.0.113.88")])
    anomaly_detector.kernel_detection = True  # this server's kernel reports SYN/UDP scans
    collect()
    alert = client.portal.call(kernel_alerts.handle, {
        "type": "scan", "action": "none", "src_ip": "203.0.113.88", "netns": 1,
        "ports": 25, "attempts": 25, "timestamp": time.time_ns()})
    assert alert.title == "UDP Scan Detected from 203.0.113.88"
    assert alert.alert_metadata["scan_type"] == "udp"
