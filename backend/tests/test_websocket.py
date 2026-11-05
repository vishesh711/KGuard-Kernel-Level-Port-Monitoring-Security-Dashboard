"""Live updates over the WebSocket (B1.4)"""

from .conftest import make_event


def receive_until(ws, message_type, limit=20):
    for _ in range(limit):
        message = ws.receive_json()
        if message["type"] == message_type:
            return message
    raise AssertionError(f"no {message_type} message received")


def test_alert_and_events_are_pushed_live(client, fake_kernel, collect):
    with client.websocket_connect("/ws") as ws:
        assert receive_until(ws, "connection")["data"]["status"] == "connected"

        fake_kernel.write([make_event(src_ip="203.0.113.77", dst_port=1000 + p) for p in range(12)])
        collect()

        alert = receive_until(ws, "security_alert")["data"]
        assert alert["alert_type"] == "PORT_SCAN"
        assert alert["src_ip"] == "203.0.113.77"
        assert alert["title"]
        assert alert["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert alert["id"] is not None

        event = receive_until(ws, "network_event")["data"]
        assert event["src_ip"] == "203.0.113.77"


def test_ping_pong(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "ping"})
        assert receive_until(ws, "pong")["type"] == "pong"
