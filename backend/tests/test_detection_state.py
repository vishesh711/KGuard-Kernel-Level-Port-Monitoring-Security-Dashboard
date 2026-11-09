"""Detection state in Redis (S6.2): survives restarts, shared by processes"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

from app.services.detection_state import DetectionState, MemoryState, RedisState

BACKEND = Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def redis_url():
    """KGUARD_TEST_REDIS_URL, or a throwaway redis-server"""
    if os.environ.get("KGUARD_TEST_REDIS_URL"):
        yield os.environ["KGUARD_TEST_REDIS_URL"]
        return
    if not shutil.which("redis-server"):
        pytest.skip("no redis-server and no KGUARD_TEST_REDIS_URL")
    port = free_port()
    proc = subprocess.Popen(["redis-server", "--port", str(port), "--save", "", "--appendonly", "no"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"redis://127.0.0.1:{port}/0"
    for _ in range(50):
        try:
            RedisState(url)
            break
        except Exception:
            time.sleep(0.1)
    yield url
    proc.terminate()
    proc.wait()


@pytest.fixture(params=["memory", "redis"])
def store(request, redis_url):
    if request.param == "memory":
        yield MemoryState()
    else:
        state = RedisState(redis_url)
        state.clear()
        yield state
        state.clear()


def probe(t, port, event_id=None):
    return {"time": t, "kind": "syn", "dst_ip": "10.0.0.1", "dst_port": port, "event_id": event_id,
            "os_guess": None}


def test_window_slides_and_is_capped(store):
    assert [p["dst_port"] for p in store.add("k", [probe(100, 1), probe(101, 2)], 60, 100)] == [1, 2]
    # 170 - 60 = 110: the first two fall out
    assert [p["dst_port"] for p in store.add("k", [probe(170, 3)], 60, 100)] == [3]
    window = store.add("k", [probe(171 + i, 10 + i) for i in range(10)], 60, 5)
    assert [p["dst_port"] for p in window] == [15, 16, 17, 18, 19]  # newest 5
    assert store.add("other", [], 60, 5) == []


def test_cooldowns(store):
    assert store.claim("scan_x", 60) is True
    assert store.claim("scan_x", 60) is False
    assert store.in_cooldown("scan_x") and not store.in_cooldown("scan_y")
    store.start("scan_y", 60)
    assert store.in_cooldown("scan_y")


def test_redis_cooldown_expires(redis_url):
    state = RedisState(redis_url)
    state.clear()
    assert state.claim("short", 1)
    time.sleep(1.2)
    assert state.claim("short", 1)


def test_unreachable_redis_falls_back_to_memory():
    state = DetectionState(f"redis://127.0.0.1:{free_port()}/0")
    assert state.status == "memory fallback" and state.last_error
    assert state.claim("a", 60) and not state.claim("a", 60)
    assert state.get_stats()["backend"] == "memory fallback"


def test_redis_failure_mid_run_falls_back(redis_url, monkeypatch):
    state = DetectionState(redis_url)
    assert state.status == "redis"

    def broken(*args):
        raise ConnectionError("gone")
    monkeypatch.setattr(state.redis, "claim", broken)
    assert state.claim("b", 60) is True  # answered from memory
    assert state.redis is None and "gone" in state.last_error


# --- real backend processes --------------------------------------------------

class Backend:
    def __init__(self, workdir, port, redis_url):
        self.port = port
        env = {**os.environ, "DATABASE_URL": f"sqlite:///{workdir}/kguard.db", "API_HOST": "127.0.0.1",
               "API_PORT": str(port), "DEBUG": "false", "REDIS_URL": redis_url,
               "AGENT_ENROLLMENT_KEY": "k" * 12, "PROC_KGUARD_PATH": "/nonexistent",
               "KGUARD_DEVICE_PATH": "/nonexistent", "KGUARD_MODULE_PATH": "/nonexistent",
               "ADMIN_USERNAME": "admin", "ADMIN_PASSWORD": "admin password"}
        self.proc = subprocess.Popen([sys.executable, "-m", "app"], cwd=BACKEND, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{port}"
        for _ in range(200):
            try:
                urllib.request.urlopen(f"{self.base}/api/health/", timeout=1)
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("backend did not start")

    def call(self, method, path, body=None, headers=None):
        request = urllib.request.Request(self.base + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json", **(headers or {})})
        with urllib.request.urlopen(request, timeout=30) as r:
            return json.loads(r.read())

    def stop(self):
        self.proc.send_signal(signal.SIGINT)
        self.proc.wait(timeout=60)


def syns(ports):
    now = time.time_ns()
    return [{"timestamp": now + i, "src_ip": "198.51.100.66", "dst_ip": "10.0.0.1", "src_port": 40000 + i,
             "dst_port": p, "protocol": "TCP", "flags": 0x02, "direction": "in"} for i, p in enumerate(ports)]


def scan_alerts(backend):
    token = backend.call("POST", "/api/auth/login", {"username": "admin", "password": "admin password"})
    items = backend.call("GET", "/api/alerts/?alert_type=PORT_SCAN", headers={
        "Authorization": f"Bearer {token['access_token']}"})["items"]
    return items


def split_scan_across_restart(redis_url):
    with tempfile.TemporaryDirectory() as workdir:
        port = free_port()
        first = Backend(workdir, port, redis_url)
        agent = first.call("POST", "/api/agents/enroll", {"name": "edge"}, {"X-Enrollment-Key": "k" * 12})
        auth = {"Authorization": f"Bearer {agent['token']}"}
        first.call("POST", "/api/agents/ingest", {"events": syns(range(1000, 1006))}, auth)
        first.stop()
        second = Backend(workdir, port, redis_url)
        try:
            second.call("POST", "/api/agents/ingest", {"events": syns(range(1006, 1012))}, auth)
            return scan_alerts(second)
        finally:
            second.stop()


def test_scan_spread_across_a_restart_is_detected(redis_url):
    """S6.2 done-when: 6 ports before the restart + 6 after = one 12-port scan (threshold 10)"""
    RedisState(redis_url).clear()
    alerts = split_scan_across_restart(redis_url)
    assert len(alerts) == 1
    assert alerts[0]["metadata"]["unique_ports"] == 12


def test_without_redis_the_restart_forgets():
    """The control: in memory, neither half is a scan on its own"""
    assert split_scan_across_restart("") == []


def test_two_backend_processes_agree(redis_url):
    """Each process sees half the scan; together they raise it exactly once"""
    RedisState(redis_url).clear()
    with tempfile.TemporaryDirectory() as workdir:
        a = Backend(workdir, free_port(), redis_url)
        b = Backend(workdir, free_port(), redis_url)
        try:
            agent = a.call("POST", "/api/agents/enroll", {"name": "edge"}, {"X-Enrollment-Key": "k" * 12})
            auth = {"Authorization": f"Bearer {agent['token']}"}
            a.call("POST", "/api/agents/ingest", {"events": syns(range(2000, 2006))}, auth)
            b.call("POST", "/api/agents/ingest", {"events": syns(range(2006, 2012))}, auth)
            a.call("POST", "/api/agents/ingest", {"events": syns(range(2012, 2020))}, auth)
            b.call("POST", "/api/agents/ingest", {"events": syns(range(2020, 2030))}, auth)
            alerts = scan_alerts(a)
            assert len(alerts) == 1  # the shared cooldown stopped a second one
            assert alerts[0]["metadata"]["unique_ports"] >= 12
        finally:
            a.stop()
            b.stop()
