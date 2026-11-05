"""Anomaly detection wired into collection (B1.3)"""

import time

from app.models.network_event import NetworkEvent
from app.models.security_alert import AlertType, SecurityAlert

from .conftest import TCP_ACK, TCP_SYN, make_event


def alert_types(db):
    return sorted(a.alert_type.value for a in db.query(SecurityAlert).all())


def test_port_scan_raises_alert_and_marks_events(fake_kernel, collect, db):
    scan = [make_event(src_ip="203.0.113.9", dst_port=1000 + p) for p in range(15)]
    fake_kernel.write(scan)
    collect()

    alerts = db.query(SecurityAlert).all()
    assert [a.alert_type for a in alerts] == [AlertType.PORT_SCAN]
    alert = alerts[0]
    assert alert.src_ip == "203.0.113.9"
    assert alert.alert_metadata["unique_ports"] == 15
    assert alert.alert_metadata["detection_method"] == "sliding_window_distinct_ports"
    assert len(alert.related_event_ids) == 15

    suspicious = db.query(NetworkEvent).filter(NetworkEvent.is_suspicious.is_(True)).count()
    assert suspicious == 15
    assert {e.event_type for e in db.query(NetworkEvent).all()} == {"port_scan"}


def test_scan_spread_across_collection_cycles_is_detected(fake_kernel, collect, db):
    fake_kernel.write([make_event(src_ip="198.51.100.7", dst_port=2000 + p) for p in range(6)])
    collect()
    assert alert_types(db) == []

    fake_kernel.write([make_event(src_ip="198.51.100.7", dst_port=3000 + p) for p in range(6)])
    collect()
    assert alert_types(db) == ["PORT_SCAN"]


def test_attempts_outside_the_window_are_forgotten(fake_kernel, collect, db):
    old = time.time_ns() - 120 * 10**9
    fake_kernel.write(
        [make_event(src_ip="198.51.100.8", dst_port=2000 + p, timestamp=old) for p in range(6)]
    )
    collect()
    fake_kernel.write([make_event(src_ip="198.51.100.8", dst_port=3000 + p) for p in range(6)])
    collect()
    assert alert_types(db) == []


def test_established_traffic_is_not_a_scan(fake_kernel, collect, db):
    # A busy server replying from many ports: ACK packets, not connection attempts
    fake_kernel.write(
        [make_event(src_ip="192.0.2.50", dst_port=1000 + p, flags=TCP_ACK) for p in range(50)]
    )
    collect()
    assert alert_types(db) == []


def test_suspicious_port_alert_and_cooldown(fake_kernel, collect, db):
    fake_kernel.write([make_event(src_ip="192.0.2.10", dst_port=22, flags=TCP_SYN)])
    collect()
    fake_kernel.write([make_event(src_ip="192.0.2.10", dst_port=22, flags=TCP_SYN)])
    collect()

    alerts = db.query(SecurityAlert).all()
    assert [a.alert_type for a in alerts] == [AlertType.SUSPICIOUS_PORT]
    assert alerts[0].dst_port == 22
    assert alerts[0].alert_metadata["port"] == 22


def test_scanner_does_not_also_get_one_alert_per_sensitive_port(fake_kernel, collect, db):
    ports = [22, 23, 80, 443, 3389, 5432, 3306] + [1000 + p for p in range(10)]
    fake_kernel.write([make_event(src_ip="203.0.113.20", dst_port=p) for p in ports])
    collect()
    assert alert_types(db) == ["PORT_SCAN"]


def test_high_frequency_connections(fake_kernel, collect, db):
    fake_kernel.write(
        [make_event(src_ip="198.51.100.30", src_port=30000 + i, dst_port=8080) for i in range(150)]
    )
    collect()
    assert alert_types(db) == ["HIGH_FREQUENCY"]
    alert = db.query(SecurityAlert).one()
    assert alert.alert_metadata["attempts_per_minute"] > 100


def test_udp_counts_as_attempts(fake_kernel, collect, db):
    fake_kernel.write(
        [make_event(src_ip="198.51.100.40", protocol="UDP", flags=0, dst_port=5000 + p)
         for p in range(12)]
    )
    collect()
    assert alert_types(db) == ["PORT_SCAN"]


def test_icmp_is_ignored(fake_kernel, collect, db):
    fake_kernel.write(
        [make_event(src_ip="198.51.100.41", protocol="ICMP", flags=0, src_port=0, dst_port=0)
         for _ in range(500)]
    )
    collect()
    assert alert_types(db) == []
