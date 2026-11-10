"""Remote agents (Phase 4): enrollment, ingest, per-host data and detection"""

import pytest

from app.config import settings
from app.models.agent import Agent
from app.models.network_event import NetworkEvent
from app.models.security_alert import SecurityAlert
from app.services.anomaly_detector import anomaly_detector

from .conftest import TCP_ACK, TCP_SYN, make_event


@pytest.fixture
def enrollment(monkeypatch):
    monkeypatch.setattr(settings, "agent_enrollment_key", "s3cret")


def enroll(client, name, key="s3cret"):
    return client.post("/api/agents/enroll", json={"name": name, "hostname": f"{name}.lan"},
                       headers={"X-Enrollment-Key": key})


def send(client, token, events, **extra):
    body = {"agent": {"engine": "ebpf", "version": "1.0.0", "hostname": "h"}, "events": events, **extra}
    return client.post("/api/agents/ingest", json=body, headers={"Authorization": f"Bearer {token}"})


def test_enrollment_is_off_without_a_key(client):
    response = enroll(client, "web-1")
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"]


def test_enrollment_checks_the_key(client, enrollment):
    assert enroll(client, "web-1", key="wrong").status_code == 403
    response = enroll(client, "web-1")
    assert response.status_code == 200
    assert response.json()["token"]


def test_agent_names_are_validated(client, enrollment):
    assert enroll(client, "bad name; rm").status_code == 422


def test_reenrolling_rotates_the_token(client, enrollment, db):
    old = enroll(client, "web-1").json()
    new = enroll(client, "web-1").json()
    assert old["agent_id"] == new["agent_id"]
    assert send(client, old["token"], []).status_code == 401
    assert send(client, new["token"], []).status_code == 200
    assert db.query(Agent).count() == 1


def test_ingest_requires_a_token(client):
    assert client.post("/api/agents/ingest", json={"events": []}).status_code == 401
    assert send(client, "not-a-token", []).status_code == 401


def test_ingest_stores_events_for_the_agent(client, enrollment, db):
    agent = enroll(client, "web-1").json()
    events = [make_event(src_port=40000 + i, flags=TCP_ACK) for i in range(10)] + [{"bogus": True}]
    response = send(client, agent["token"], events, kernel_dropped=3, queue_dropped=1)
    assert response.json() == {"accepted": 10, "rejected": 1, "payloads_accepted": 0}

    assert {r.host_id for r in db.query(NetworkEvent).all()} == {agent["agent_id"]}
    listed = client.get("/api/agents/").json()
    assert len(listed) == 1
    info = listed[0]
    assert info["name"] == "web-1" and info["engine"] == "ebpf" and info["online"] is True
    assert (info["events_received"], info["kernel_dropped"], info["queue_dropped"]) == (10, 3, 1)


def test_batch_size_limit(client, enrollment, monkeypatch):
    monkeypatch.setattr(settings, "max_ingest_events", 5)
    agent = enroll(client, "web-1").json()
    assert send(client, agent["token"], [make_event()] * 6).status_code == 413


def test_events_can_be_filtered_by_host(client, enrollment, fake_kernel, collect):
    agent = enroll(client, "web-1").json()
    send(client, agent["token"], [make_event(flags=TCP_ACK)] * 3)
    fake_kernel.write([make_event(flags=TCP_ACK)] * 2)
    collect()  # this server's own events
    assert client.get("/api/events/", params={"host_id": agent["agent_id"]}).json()["total"] == 3
    assert client.get("/api/events/", params={"host_id": 0}).json()["total"] == 2


def scan(dst_ports, src="203.0.113.99"):
    return [make_event(src_ip=src, dst_port=p, flags=TCP_SYN) for p in dst_ports]


def test_detection_is_per_host(client, enrollment, db):
    a = enroll(client, "web-1").json()
    b = enroll(client, "web-2").json()
    # 6 ports on each host: 12 in total, but below the threshold (10) per host
    send(client, a["token"], scan(range(1000, 1006)))
    send(client, b["token"], scan(range(2000, 2006)))
    assert db.query(SecurityAlert).count() == 0

    send(client, a["token"], scan(range(3000, 3006)))
    alert = db.query(SecurityAlert).one()
    assert alert.alert_type.value == "PORT_SCAN"
    assert alert.host_id == a["agent_id"]
    assert client.get("/api/alerts/").json()["items"][0]["host_id"] == a["agent_id"]


def test_remote_hosts_keep_backend_detection_when_local_kernel_detects(client, enrollment, db):
    anomaly_detector.kernel_detection = True  # this server's module handles its own traffic
    agent = enroll(client, "web-1").json()
    send(client, agent["token"], scan(range(1000, 1015)))
    assert [a.host_id for a in db.query(SecurityAlert).all()] == [agent["agent_id"]]


def test_agents_report_events_per_second(client, enrollment):
    """U7.5: each agent's rate over the last minute, separately"""
    import time

    tokens = {name: enroll(client, name).json()["token"] for name in ("web-1", "db-1")}
    now = time.time_ns()
    def events(n, start):
        return [{"timestamp": start + i, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "src_port": 40000 + i,
                 "dst_port": 443, "protocol": "TCP", "flags": 16} for i in range(n)]
    send(client, tokens["web-1"], events(120, now))
    send(client, tokens["db-1"], events(30, now))
    send(client, tokens["db-1"], events(500, now - 120 * 1_000_000_000))  # two minutes ago: not counted
    rates = {a["name"]: a["events_per_second"] for a in client.get("/api/agents/").json()}
    assert rates == {"web-1": 2.0, "db-1": 0.5}
