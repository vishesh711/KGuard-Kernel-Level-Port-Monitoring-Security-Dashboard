"""Alerts API, including metadata in responses (B1.2)"""

from datetime import datetime, timedelta

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert


def add_alert(db, **overrides):
    alert = SecurityAlert.create_port_scan_alert("203.0.113.5", 25, [1, 2, 3])
    for key, value in overrides.items():
        setattr(alert, key, value)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def test_list_alerts_includes_metadata(client, db):
    add_alert(db)
    response = client.get("/api/alerts/")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["alert_type"] == "PORT_SCAN"
    assert item["severity"] == "HIGH"
    enrichment = item["metadata"].pop("enrichment")  # added to every alert (S6.3)
    assert item["metadata"] == {"event_count": 25, "detection_method": "frequency_analysis"}
    assert enrichment["mitre"][0]["id"] == "T1046"
    assert item["related_event_ids"] == [1, 2, 3]


def test_filter_alerts(client, db):
    add_alert(db)
    add_alert(db, alert_type=AlertType.SUSPICIOUS_PORT, severity=AlertSeverity.MEDIUM)
    body = client.get("/api/alerts/", params={"severity": "MEDIUM"}).json()
    assert body["total"] == 1
    assert body["items"][0]["alert_type"] == "SUSPICIOUS_PORT"


def test_get_single_alert(client, db):
    alert = add_alert(db)
    assert client.get(f"/api/alerts/{alert.id}").json()["id"] == alert.id
    assert client.get("/api/alerts/99999").status_code == 404


def test_acknowledge_then_resolve(client, db):
    alert = add_alert(db)

    response = client.post(
        f"/api/alerts/{alert.id}/acknowledge",
        json={"acknowledged_by": "analyst", "notes": "looking"},
    )
    assert response.status_code == 200
    again = client.post(f"/api/alerts/{alert.id}/acknowledge", json={"acknowledged_by": "x"})
    assert again.status_code == 400

    response = client.post(
        f"/api/alerts/{alert.id}/resolve",
        json={"resolved_by": "analyst", "resolution_notes": "blocked at firewall"},
    )
    assert response.status_code == 200

    item = client.get(f"/api/alerts/{alert.id}").json()
    assert item["acknowledged"] is True
    assert item["acknowledged_by"] == "test-admin"  # the logged-in user, not what the client claims
    assert item["resolved"] is True
    assert item["resolution_notes"] == "blocked at firewall"
    assert item["metadata"]["acknowledgment_notes"] == "looking"
    assert item["metadata"]["resolved_by"] == "test-admin"


def test_alert_stats(client, db):
    add_alert(db)
    add_alert(db, severity=AlertSeverity.CRITICAL)
    add_alert(db, timestamp=datetime.utcnow() - timedelta(hours=5))

    stats = client.get("/api/alerts/stats/summary").json()
    assert stats["total_alerts"] == 3
    assert stats["critical_alerts"] == 1
    assert stats["high_alerts"] == 2
    assert stats["unacknowledged_alerts"] == 3
    assert stats["alert_types_distribution"] == {"PORT_SCAN": 3}
    assert len(stats["alerts_per_hour"]) == 24
    assert sum(h["count"] for h in stats["alerts_per_hour"]) == 3
    assert stats["top_source_ips"] == [{"ip": "203.0.113.5", "count": 3}]


def test_active_summary(client, db):
    add_alert(db)
    add_alert(db, resolved=True)
    summary = client.get("/api/alerts/active/summary").json()
    assert summary["total_active"] == 1
    assert summary["severity_breakdown"]["HIGH"] == 1


def test_events_by_ids(client, fake_kernel, collect):
    """The alert detail page fetches an alert's related events by ID (U7.4)"""
    from .conftest import make_event

    fake_kernel.write([make_event(dst_port=p) for p in (1, 2, 3)])
    collect()
    all_ids = [e["id"] for e in client.get("/api/events/").json()["items"]]
    wanted = sorted(all_ids)[:2]
    got = client.get("/api/events/", params={"ids": ",".join(map(str, wanted))}).json()["items"]
    assert sorted(e["id"] for e in got) == wanted
    assert client.get("/api/events/", params={"ids": "1;DROP"}).status_code == 422
    assert client.get("/api/events/", params={"ids": ",".join(["1"] * 101)}).status_code == 422
