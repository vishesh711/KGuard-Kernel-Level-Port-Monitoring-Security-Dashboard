"""S6.1: old data is deleted once a day"""

from datetime import datetime, timedelta

from app.config import settings
from app.models.network_event import NetworkEvent
from app.models.payload import DnsQuery
from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.models.system_metric import SystemMetric
from app.services import packet_capture as pc
from app.services.retention import RetentionJob

NOW = datetime(2026, 6, 1, 12, 0)


def event(days_old, port=80):
    return NetworkEvent(timestamp=1, created_at=NOW - timedelta(days=days_old), src_ip="10.0.0.5",
                        dst_ip="10.0.0.1", src_port=40000, dst_port=port, protocol="TCP")


def alert(days_old, resolved):
    return SecurityAlert(timestamp=NOW - timedelta(days=days_old), created_at=NOW - timedelta(days=days_old),
                         alert_type=AlertType.PORT_SCAN, severity=AlertSeverity.HIGH, title=f"{days_old}",
                         description="d", resolved=resolved)


def metric(value, days_old):
    return SystemMetric(metric_name="cpu", metric_category="system", value=value,
                        timestamp=NOW - timedelta(days=days_old))


def test_old_data_is_deleted_and_recent_data_kept(db, tmp_path, monkeypatch):
    db.add_all([event(10, 1), event(8, 2), event(6, 3), event(0, 4)])
    db.add_all([DnsQuery(timestamp=1, created_at=NOW - timedelta(days=9), client_ip="10.0.0.5",
                         server_ip="10.0.0.1", qname="old.example"),
                DnsQuery(timestamp=1, created_at=NOW, client_ip="10.0.0.5", server_ip="10.0.0.1",
                         qname="new.example")])
    db.add_all([metric(1.0, 40), metric(2.0, 2)])
    old_resolved, old_open, new_resolved = alert(100, True), alert(100, False), alert(10, True)
    db.add_all([old_resolved, old_open, new_resolved])
    db.commit()
    deleted_id, kept_ids = old_resolved.id, sorted([old_open.id, new_resolved.id])

    # The deleted alert's pcap goes with it
    monkeypatch.setattr(pc.packet_capture, "directory", tmp_path)
    (tmp_path / f"alert-{deleted_id}.pcap").write_bytes(b"x")

    result = RetentionJob().run(NOW)
    assert result == {"network_events": 2, "dns_queries": 1, "tls_handshakes": 0, "system_metrics": 1,
                      "security_alerts": 1}
    db.expire_all()
    assert sorted(e.dst_port for e in db.query(NetworkEvent)) == [3, 4]
    assert [q.qname for q in db.query(DnsQuery)] == ["new.example"]
    assert [m.value for m in db.query(SystemMetric)] == [2.0]
    assert sorted(a.id for a in db.query(SecurityAlert)) == kept_ids
    assert not (tmp_path / f"alert-{deleted_id}.pcap").exists()


def test_deletes_in_batches(db, monkeypatch):
    monkeypatch.setattr(settings, "retention_batch", 3)
    db.add_all([event(30, p) for p in range(10)])
    db.commit()
    assert RetentionJob().run(NOW)["network_events"] == 10
    assert db.query(NetworkEvent).count() == 0


def test_zero_keeps_data_forever(db, monkeypatch):
    monkeypatch.setattr(settings, "retention_events_days", 0)
    db.add(event(1000))
    db.commit()
    assert "network_events" not in RetentionJob().run(NOW)
    assert db.query(NetworkEvent).count() == 1


def test_runs_once_a_day():
    job = RetentionJob()
    start = job.started
    assert not job.due(start + timedelta(seconds=30))  # not while the service starts
    assert job.due(start + timedelta(seconds=61))
    job.last_run = start + timedelta(seconds=61)
    assert not job.due(job.last_run + timedelta(hours=23, minutes=59))
    assert job.due(job.last_run + timedelta(hours=24))
