"""Prometheus metrics (S6.8)"""

import re

import pytest

from app.config import settings

from .conftest import make_event


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "m" * 32)
    return {"Authorization": "Bearer " + "m" * 32}


def value(text, name, **labels):
    """One sample's value from the exposition text"""
    want = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))  # Prometheus sorts labels
    pattern = rf"^{re.escape(name)}{{{re.escape(want)}}} (\S+)$" if labels else rf"^{re.escape(name)} (\S+)$"
    found = re.search(pattern, text, re.M)
    return float(found.group(1)) if found else None


def test_metrics_need_their_token(anon, client, monkeypatch):
    assert anon.get("/metrics").status_code == 404  # off without METRICS_TOKEN
    monkeypatch.setattr(settings, "metrics_token", "m" * 32)
    assert anon.get("/metrics").status_code == 401
    assert anon.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    # A dashboard login is not the metrics token
    assert client.get("/metrics").status_code == 401


def test_events_alerts_and_detection_time(anon, token, fake_kernel, collect):
    before = anon.get("/metrics", headers=token).text
    events_before = value(before, "kguard_events_total", host="local") or 0
    scans_before = value(before, "kguard_alerts_total", type="PORT_SCAN", severity="HIGH") or 0
    batches_before = value(before, "kguard_detection_seconds_count") or 0

    fake_kernel.write([make_event(src_ip="198.51.100.9", dst_port=1000 + p) for p in range(30)])
    collect()
    text = anon.get("/metrics", headers=token).text
    assert value(text, "kguard_events_total", host="local") == events_before + 30
    assert value(text, "kguard_alerts_total", type="PORT_SCAN", severity="HIGH") == scans_before + 1
    assert value(text, "kguard_detection_seconds_count") == batches_before + 1
    assert value(text, "kguard_kernel_events_dropped_total", host="local") == 0
    assert value(text, "kguard_detection_state", backend="memory") == 1 or \
        value(text, "kguard_detection_state", backend="redis") == 1


def test_agents_blocks_and_requests(anon, client, token, monkeypatch):
    monkeypatch.setattr(settings, "agent_enrollment_key", "s3cret")
    agent = client.post("/api/agents/enroll", json={"name": "web-1"}, headers={"X-Enrollment-Key": "s3cret"})
    auth = {"Authorization": f"Bearer {agent.json()['token']}"}
    client.post("/api/agents/ingest", json={"kernel_dropped": 7, "queue_dropped": 2, "events": []},
                headers=auth)
    client.post("/api/response/blocks", json={"cidr": "198.51.100.7", "reason": "t"})
    text = anon.get("/metrics", headers=token).text
    assert value(text, "kguard_kernel_events_dropped_total", host="web-1") == 7
    assert value(text, "kguard_agent_queue_dropped_total", agent="web-1") == 2
    assert value(text, "kguard_agent_online", agent="web-1") == 1
    assert value(text, "kguard_agent_blocklist_in_sync", agent="web-1") == 0  # has not synced
    assert value(text, "kguard_blocks_active") == 1
    assert value(text, "kguard_http_requests_total", method="POST", status="201") >= 1
    assert value(text, "kguard_http_request_seconds_count") >= 3
