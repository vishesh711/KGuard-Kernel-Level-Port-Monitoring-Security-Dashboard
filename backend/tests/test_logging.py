"""Structured JSON logging with request IDs and rotation (roadmap S6.9)"""

import io
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient

from app.logging_setup import (
    JsonFormatter,
    RequestContextMiddleware,
    RequestIdFilter,
    configure_logging,
    request_id_var,
)

BACKEND = Path(__file__).resolve().parent.parent


@pytest.fixture
def lines():
    """Capture what the root logger writes, formatted as JSON"""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        yield lambda: [json.loads(line) for line in stream.getvalue().splitlines()]
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


def small_app():
    app = FastAPI()
    log = logging.getLogger("test.handler")

    @app.get("/hello")
    def hello():
        log.info("inside handler", extra={"rows": 3})
        return {"request_id": request_id_var.get()}

    @app.get("/boom")
    def boom():
        raise RuntimeError("kaboom")

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        log.info("websocket message")
        await websocket.send_text("hi")
        await websocket.close()

    app.add_middleware(RequestContextMiddleware)
    return app


def test_formatter_writes_one_json_object():
    record = logging.LogRecord("kguard.x", logging.WARNING, __file__, 1,
                               "port %d is \"open\"\nnext", (22,), None)
    record.src_ip = "10.0.0.5"
    entry = json.loads(JsonFormatter().format(record))
    assert entry["level"] == "WARNING"
    assert entry["logger"] == "kguard.x"
    assert entry["message"] == 'port 22 is "open"\nnext'
    assert entry["src_ip"] == "10.0.0.5"
    assert entry["time"].endswith("Z")


def test_exceptions_stay_on_one_line():
    try:
        raise ValueError("bad value")
    except ValueError:
        record = logging.LogRecord("kguard", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
    text = JsonFormatter().format(record)
    assert "\n" not in text
    assert "ValueError: bad value" in json.loads(text)["exception"]


def test_every_request_gets_an_id(lines):
    client = TestClient(small_app())
    r1, r2 = client.get("/hello"), client.get("/hello")
    ids = [r1.headers["X-Request-ID"], r2.headers["X-Request-ID"]]
    assert ids[0] != ids[1] and all(len(i) == 32 for i in ids)
    assert r1.json()["request_id"] == ids[0]

    inside = [e for e in lines() if e["message"] == "inside handler"]
    assert [e["request_id"] for e in inside] == ids
    assert inside[0]["rows"] == 3

    access = [e for e in lines() if e["logger"] == "kguard.access"]
    assert [(e["request_id"], e["method"], e["path"], e["status"]) for e in access] == [
        (ids[0], "GET", "/hello", 200), (ids[1], "GET", "/hello", 200)]
    assert all(e["duration_ms"] >= 0 for e in access)


def test_client_request_id_is_kept_if_sensible():
    client = TestClient(small_app())
    kept = client.get("/hello", headers={"X-Request-ID": "trace-abc.123"})
    assert kept.headers["X-Request-ID"] == "trace-abc.123"
    for bad in ("has space", "x" * 65, "line\"break"):
        returned = client.get("/hello", headers={"X-Request-ID": bad}).headers["X-Request-ID"]
        assert returned != bad and len(returned) == 32


def test_ids_do_not_leak_outside_requests(lines):
    TestClient(small_app()).get("/hello")
    logging.getLogger("test.after").info("background work")
    assert "request_id" not in [e for e in lines() if e["message"] == "background work"][0]
    assert request_id_var.get() is None


def test_unhandled_error_is_logged_with_its_request_id(lines):
    client = TestClient(small_app(), raise_server_exceptions=False)
    response = client.get("/boom")
    assert response.status_code == 500
    request_id = response.headers["X-Request-ID"]
    assert response.json()["request_id"] == request_id
    assert response.json()["detail"] == "An unexpected error occurred"  # not in debug mode

    error = [e for e in lines() if e["level"] == "ERROR"][0]
    assert error["request_id"] == request_id
    assert "RuntimeError: kaboom" in error["exception"]
    access = [e for e in lines() if e["logger"] == "kguard.access"][0]
    assert (access["status"], access["request_id"]) == (500, request_id)


def test_websocket_lines_share_an_id(lines):
    with TestClient(small_app()).websocket_connect("/ws") as ws:
        assert ws.receive_text() == "hi"
    entries = [e for e in lines() if e["message"] in ("WebSocket /ws opened", "websocket message",
                                                      "WebSocket /ws closed")]
    assert len(entries) == 3
    assert len({e["request_id"] for e in entries}) == 1


def test_real_app_returns_request_ids(client):
    response = client.get("/api/health/", headers={"X-Request-ID": "from-test"})
    assert response.headers["X-Request-ID"] == "from-test"


def test_log_file_rotates_and_stays_json(tmp_path):
    log_file = tmp_path / "logs" / "kguard.log"
    configure_logging(level="INFO", fmt="json", log_file=str(log_file), max_bytes=2000, backup_count=3)
    try:
        log = logging.getLogger("test.rotation")
        for n in range(200):
            log.info(f"line {n}", extra={"n": n})
    finally:
        configure_logging(log_file="")  # back to stdout only (closes the file)
    files = sorted(log_file.parent.iterdir())
    assert [f.name for f in files] == ["kguard.log", "kguard.log.1", "kguard.log.2", "kguard.log.3"]
    for f in files:
        assert f.stat().st_size <= 2000
        for line in f.read_text().splitlines():
            assert json.loads(line)["logger"] == "test.rotation"
    newest = [json.loads(line)["n"] for line in log_file.read_text().splitlines()]
    assert newest[-1] == 199


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_every_line_of_a_real_server_run_is_json(tmp_path):
    """Start the backend as deployed (python -m app), use it, stop it, parse its whole output"""
    port = free_port()
    env = {**os.environ,
           "DATABASE_URL": f"sqlite:///{tmp_path}/kguard.db",
           "API_HOST": "127.0.0.1", "API_PORT": str(port), "DEBUG": "false",
           "PROC_KGUARD_PATH": str(tmp_path / "none"), "KGUARD_DEVICE_PATH": str(tmp_path / "none"),
           "KGUARD_MODULE_PATH": str(tmp_path / "none"), "LOG_FILE": str(tmp_path / "kguard.log"),
           "PYTHONWARNINGS": "always"}
    proc = subprocess.Popen([sys.executable, "-m", "app"], cwd=BACKEND, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{base}/api/health/", timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("backend did not start")
        request = urllib.request.Request(f"{base}/api/alerts/?size=1", headers={"X-Request-ID": "run-check"})
        urllib.request.urlopen(request, timeout=5)
        for path in ("/no/such/path", "/api/alerts/not-a-number"):
            try:
                urllib.request.urlopen(f"{base}{path}", timeout=5)
            except urllib.error.HTTPError:
                pass
    finally:
        proc.send_signal(signal.SIGINT)
        output, _ = proc.communicate(timeout=30)

    lines = output.splitlines()
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pytest.fail(f"not JSON: {line!r}")
    messages = [e["message"] for e in entries]
    assert any("Uvicorn running on" in m for m in messages)
    assert not any("color_message" in e for e in entries)
    assert any(m.startswith("Running upgrade") or m == "Database schema is up to date" for m in messages)
    assert any("Shutting down" in m for m in messages)
    assert {(e["path"], e["status"]) for e in entries if e["logger"] == "kguard.access"} >= {
        ("/api/health/", 200), ("/api/alerts/", 200), ("/no/such/path", 404),
        ("/api/alerts/not-a-number", 422)}
    assert [e["request_id"] for e in entries if e.get("path") == "/api/alerts/"] == ["run-check"]
    # The log file got the same lines
    assert len((tmp_path / "kguard.log").read_text().splitlines()) == len(lines)
