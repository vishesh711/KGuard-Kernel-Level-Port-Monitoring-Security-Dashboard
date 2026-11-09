"""Notifications (S6.7): Slack, Telegram and email, severity threshold, rate limits"""

import asyncio
import http.server
import json
import threading
import time

import pytest
from aiosmtpd.controller import Controller

from app.config import settings
from app.services.notifier import Notifier, notifier, summary

from .conftest import make_event


class Recorder(http.server.BaseHTTPRequestHandler):
    """Stands in for Slack's webhook and Telegram's Bot API"""
    requests = []
    replies = []  # (status, headers) to answer with, in order; then 200

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Recorder.requests.append((self.path, body))
        status, headers = Recorder.replies.pop(0) if Recorder.replies else (200, {})
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"ok" if status == 200 else b"rate_limited")

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_apis():
    Recorder.requests, Recorder.replies = [], []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


class Mailbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append((envelope.mail_from, envelope.rcpt_tos, envelope.content.decode()))
        return "250 OK"


@pytest.fixture
def smtp():
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    box = Mailbox()
    controller = Controller(box, hostname="127.0.0.1", port=port)
    controller.start()
    yield box, port
    controller.stop()


@pytest.fixture
def channels(monkeypatch, fake_apis, smtp):
    box, port = smtp
    monkeypatch.setattr(settings, "slack_webhook_url", f"{fake_apis}/services/T000/B000/secret")
    monkeypatch.setattr(settings, "telegram_bot_token", "123:ABC")
    monkeypatch.setattr(settings, "telegram_chat_id", "-1001")
    monkeypatch.setattr(settings, "telegram_api_base", fake_apis)
    monkeypatch.setattr(settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(settings, "smtp_port", port)
    monkeypatch.setattr(settings, "smtp_starttls", False)
    monkeypatch.setattr(settings, "email_from", "kguard@example.com")
    monkeypatch.setattr(settings, "email_to", ["soc@example.com"])
    monkeypatch.setattr(settings, "dashboard_url", "https://kguard.example.com")
    return box


ALERT = {"id": 7, "alert_type": "PORT_SCAN", "severity": "HIGH",
         "title": "SYN Scan Detected from 5.188.10.7",
         "description": "5.188.10.7 sent SYN probes to 40 ports.",
         "src_ip": "5.188.10.7", "dst_ip": "10.0.0.1",
         "metadata": {"enrichment": {"mitre": [{"id": "T1046"}],
                                     "src": {"country": "NL", "asn": 64500, "as_org": "Example Hosting",
                                             "threat_lists": ["firehol_level1"]}}}}


def run(coro):
    return asyncio.run(coro)


def test_message_text():
    content = summary(ALERT)
    assert content["title"] == "🟠 [HIGH] SYN Scan Detected from 5.188.10.7"
    assert "from 5.188.10.7 to 10.0.0.1" in content["text"]
    assert "country NL, AS64500 Example Hosting · on firehol_level1 · ATT&CK T1046" in content["text"]


def test_alert_reaches_every_channel(channels):
    results = run(Notifier().deliver(ALERT))
    assert results == {"slack": "sent", "telegram": "sent", "email": "sent"}
    (slack_path, slack), (tg_path, tg) = Recorder.requests
    assert slack_path == "/services/T000/B000/secret"
    assert slack["blocks"][0]["text"]["text"] == "🟠 [HIGH] SYN Scan Detected from 5.188.10.7"
    assert "https://kguard.example.com/alerts?id=7" in slack["blocks"][1]["text"]["text"]
    assert tg_path == "/bot123:ABC/sendMessage" and tg["chat_id"] == "-1001"
    assert "T1046" in tg["text"]
    sender, rcpts, mail = channels.messages[0]
    assert (sender, rcpts) == ("kguard@example.com", ["soc@example.com"])
    assert "Subject: KGuard: =?utf-8?" in mail or "Subject: KGuard:" in mail


def test_severity_threshold(channels, monkeypatch):
    n = Notifier()

    async def go():
        n.start()
        n.on_alert({**ALERT, "severity": "MEDIUM"})
        n.on_alert(ALERT)
        await asyncio.sleep(0.5)
        await n.stop()
    run(go())
    assert len([r for r in Recorder.requests if r[0].startswith("/services")]) == 1


def test_rate_limit_holds_back_and_reports(channels, monkeypatch):
    monkeypatch.setattr(settings, "notify_max_per_hour", 2)
    n = Notifier()
    results = [run(n.deliver(ALERT)) for _ in range(4)]
    held = "held back (rate limit)"
    assert [r["slack"] for r in results] == ["sent", "sent", held, held]
    # An hour later the next one goes out and says how many were held back
    for c in n.channels:
        c.sent_times = type(c.sent_times)(t - 3700 for t in c.sent_times)
    assert run(n.deliver(ALERT))["slack"] == "sent"
    assert "(2 more alert(s) were held back" in Recorder.requests[-2][1]["text"]  # slack, then telegram
    assert n.get_stats()["channels"]["slack"]["held_back"] == 2


def test_retries_and_retry_after(channels):
    Recorder.replies = [(429, {"Retry-After": "1"}), (503, {})]
    n = Notifier()
    waits = []

    async def no_sleep(seconds):
        waits.append(seconds)
    n.sleep = no_sleep
    assert run(n.deliver(ALERT))["slack"] == "sent"
    assert waits == [1.0, 2.0]  # Retry-After, then backoff
    assert n.get_stats()["channels"]["slack"]["sent"] == 1


def test_permanent_errors_do_not_retry_and_never_show_the_url(channels):
    Recorder.replies = [(404, {})]
    n = Notifier()
    result = run(n.deliver(ALERT))["slack"]
    assert result.startswith("failed: HTTP 404")
    stats = json.dumps(n.get_stats())
    assert "secret" not in stats and "B000" not in stats and "123:ABC" not in stats


def test_unreachable_channel_fails_cleanly(channels, monkeypatch):
    monkeypatch.setattr(settings, "slack_webhook_url", "http://127.0.0.1:9/hook")
    n = Notifier()

    async def no_sleep(seconds):
        pass
    n.sleep = no_sleep
    results = run(n.deliver(ALERT))
    assert results["slack"].startswith("failed: cannot connect")
    assert results["telegram"] == "sent" and results["email"] == "sent"  # others unaffected


def test_detected_attack_is_notified(channels, fake_kernel, collect, client):
    """End to end: a scan the collector sees arrives in Slack"""
    fake_kernel.write([make_event(src_ip="198.51.100.9", dst_port=1000 + p) for p in range(30)])
    collect()
    deadline = time.time() + 10
    while time.time() < deadline and not any(p.startswith("/services") for p, _ in Recorder.requests):
        time.sleep(0.1)
    slack = [body for path, body in Recorder.requests if path.startswith("/services")]
    assert slack and "Scan Detected from 198.51.100.9" in slack[0]["text"]
    status = client.get("/api/notifications/status").json()
    assert status["channels"]["slack"]["configured"] is True
    assert "secret" not in json.dumps(status) and "123:ABC" not in json.dumps(status)


def test_test_endpoint(channels, client, viewer):
    assert viewer.post("/api/notifications/test").status_code == 403
    response = client.post("/api/notifications/test")
    assert response.json()["results"] == {"slack": "sent", "telegram": "sent", "email": "sent"}
    assert "Test notification from KGuard" in Recorder.requests[0][1]["text"]


def test_test_endpoint_without_channels(client):
    assert client.post("/api/notifications/test").status_code == 409


def test_nothing_configured_nothing_queued():
    notifier.on_alert(ALERT)
    assert notifier.get_stats()["queued"] == 0
