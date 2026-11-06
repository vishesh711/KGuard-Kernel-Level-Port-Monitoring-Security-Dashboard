"""In-kernel guard alerts (Phase 3): decoding, storing, and handing detection to the kernel"""

import time

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.services.anomaly_detector import anomaly_detector
from app.services.kernel_alerts import alert_from_kernel, kernel_alerts
from app.services.kguard_device import build_fake_device
from app.services.kguard_netlink import (
    KGUARD_CMD_ALERT,
    decode_alert,
    encode_alert,
    genl_split,
    iter_messages,
)

from .conftest import TCP_SYN
from .test_device import v2_event


def kernel_alert(**fields):
    base = {"type": "scan", "action": "none", "src_ip": "203.0.113.50", "netns": 4026531840,
            "ports": 25, "attempts": 30, "timestamp": time.time_ns()}
    base.update(fields)
    return base


def test_netlink_alert_round_trip():
    for alert in (kernel_alert(), kernel_alert(type="syn_rate", action="dropped", src_ip="2001:db8::9")):
        messages = list(iter_messages(encode_alert(alert) + encode_alert(alert)))
        assert len(messages) == 2
        cmd, payload = genl_split(messages[0][1])
        assert cmd == KGUARD_CMD_ALERT
        assert decode_alert(payload) == alert


def test_scan_alert_mapping():
    monitor = alert_from_kernel(kernel_alert())
    assert monitor.alert_type == AlertType.PORT_SCAN
    assert monitor.severity == AlertSeverity.MEDIUM
    assert "No action was taken" in monitor.description
    assert monitor.alert_metadata["source"] == "kernel"
    assert monitor.alert_metadata["unique_ports"] == 25

    blocked = alert_from_kernel(kernel_alert(action="blocked"))
    assert blocked.severity == AlertSeverity.HIGH
    assert "blocked this source" in blocked.description


def test_syn_rate_alert_mapping():
    alert = alert_from_kernel(kernel_alert(type="syn_rate", action="dropped", ports=1, attempts=500))
    assert alert.alert_type == AlertType.HIGH_FREQUENCY
    assert alert.severity == AlertSeverity.HIGH
    assert alert.title == "Connection Flood from 203.0.113.50"
    assert "dropped the excess" in alert.description


def test_kernel_alert_is_stored_and_pushed_live(client, db):
    with client.websocket_connect("/ws") as ws:
        client.portal.call(kernel_alerts.handle, kernel_alert(action="blocked"))
        for _ in range(20):
            message = ws.receive_json()
            if message["type"] == "security_alert":
                break
        assert message["data"]["metadata"]["source"] == "kernel"
        assert message["data"]["metadata"]["action"] == "blocked"

    stored = db.query(SecurityAlert).one()
    assert stored.src_ip == "203.0.113.50"
    api = client.get("/api/alerts/").json()["items"][0]
    assert api["metadata"]["detection_method"] == "kernel_guard"


def test_backend_scan_rule_steps_aside_for_the_kernel(fake_device, collect, db):
    anomaly_detector.kernel_detection = True
    build_fake_device(fake_device, [[
        v2_event(src_ip="198.51.100.20", dst_port=1000 + p, flags=TCP_SYN, direction="in")
        for p in range(30)
    ]])
    collect()
    assert db.query(SecurityAlert).count() == 0


def test_kernel_scan_alert_suppresses_per_port_alerts(client, fake_device, collect, db):
    client.portal.call(kernel_alerts.handle, kernel_alert(src_ip="198.51.100.21"))
    build_fake_device(fake_device, [[
        v2_event(src_ip="198.51.100.21", dst_port=22, flags=TCP_SYN, direction="in"),
    ]])
    collect()
    types = [a.alert_type for a in db.query(SecurityAlert).all()]
    assert types == [AlertType.PORT_SCAN]


def test_no_module_means_backend_rules(client):
    kernel_alerts._last_attempt = 0
    client.portal.call(lambda: kernel_alerts.check())
    assert not kernel_alerts.active
    assert anomaly_detector.kernel_detection is False
    details = client.get("/api/health/kernel").json()["details"]
    assert details["kernel_detection"] is False


def test_kernel_alert_marks_the_sources_events(client, fake_device, collect, db):
    from app.models.network_event import NetworkEvent

    build_fake_device(fake_device, [[v2_event(src_ip="198.51.100.30", dst_port=1000 + p, flags=TCP_SYN)
                                     for p in range(5)]])
    collect()  # events stored before the alert arrives
    alert = client.portal.call(kernel_alerts.handle, kernel_alert(src_ip="198.51.100.30"))
    assert len(alert.related_event_ids) == 5

    build_fake_device(fake_device, [[v2_event(src_ip="198.51.100.30", dst_port=2000, flags=TCP_SYN),
                                     v2_event(src_ip="192.0.2.1", dst_port=443)]])
    collect()  # an event arriving after the alert, plus unrelated traffic

    rows = db.query(NetworkEvent).all()
    flagged = {(r.src_ip, r.dst_port) for r in rows if r.is_suspicious}
    assert len(flagged) == 6
    assert all(ip == "198.51.100.30" for ip, _ in flagged)
    assert {r.event_type for r in rows if r.is_suspicious} == {"port_scan"}
