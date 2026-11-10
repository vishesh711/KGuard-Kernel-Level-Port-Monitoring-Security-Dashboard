# ruff: noqa: E501  (verbatim /proc/net rows)
"""Listening ports and connections (U7.2)"""

import socket

import pytest

from app.config import settings
from app.services.sockets import decode_address, parse_table, snapshot

from .test_agents import enroll

TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0 10 0
   1: 0500000A:A3F2 0100000A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 4343 1 0 20 4 30 10 -1
"""
TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5151 1 0 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5252 1 0 100 0 0 10 0
"""
UDP = """   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 6161 2 0 0
"""


def test_decode_addresses():
    assert decode_address("0100007F:1F90") == ("127.0.0.1", 8080)
    assert decode_address("00000000000000000000000001000000:0016") == ("::1", 22)
    assert decode_address("0000000000000000FFFF00000100007F:1F91") == ("127.0.0.1", 8081)  # v4-mapped
    assert decode_address("B80D0120000000000000000001000000:0050") == ("2001:db8::1", 80)


def test_parse_tables():
    tcp = parse_table(TCP, "tcp")
    assert [(r["local"], r["lport"], r["state"], r["uid"], r["inode"]) for r in tcp] == [
        ("127.0.0.1", 8080, "LISTEN", 1000, 4242), ("10.0.0.5", 41970, "ESTABLISHED", 0, 4343)]
    assert tcp[1]["remote"] == "10.0.0.1" and tcp[1]["rport"] == 443
    assert [r["family"] for r in parse_table(TCP6, "tcp6")] == [6, 6]
    assert parse_table(UDP, "udp")[0] | {} == {**parse_table(UDP, "udp")[0], "proto": "UDP", "lport": 53,
                                               "state": "LISTEN"}


def test_snapshot_from_a_fake_proc(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "tcp").write_text(TCP)
    (tmp_path / "net" / "udp").write_text(UDP)
    fd = tmp_path / "77" / "fd"
    fd.mkdir(parents=True)
    (tmp_path / "77" / "comm").write_text("nc\n")
    (fd / "3").symlink_to("socket:[4242]")
    snap = snapshot(str(tmp_path))
    by_port = {(x["proto"], x["lport"]): x for x in snap["listeners"]}
    assert by_port[("TCP", 8080)]["process"] == "nc" and by_port[("TCP", 8080)]["pid"] == 77
    assert ("UDP", 53) in by_port and by_port[("UDP", 53)]["process"] is None
    assert [c["state"] for c in snap["connections"]] == ["ESTABLISHED"]


def test_a_new_listener_on_this_machine_is_flagged(client, monkeypatch):
    """Real /proc: the baseline is taken at start-up; a listener opened afterwards is new"""
    from app.api.sockets import baseline_this_server

    monkeypatch.setattr(settings, "proc_root", "/proc")
    baseline_this_server()  # what the backend does at start-up (tables are wiped between tests)
    first = client.get("/api/sockets").json()
    assert first["host"] == "this server"
    assert not any(item["new"] for item in first["listeners"])

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    try:
        listeners = client.get("/api/sockets").json()["listeners"]
        mine = [x for x in listeners if x["lport"] == port and x["proto"] == "TCP"]
        assert mine and mine[0]["new"] is True
        assert mine[0]["pid"] is not None and mine[0]["process"]
        # An admin says it is expected
        assert client.post("/api/sockets/known", json={"host_id": 0, "proto": "TCP", "port": port,
                                                       "process": mine[0]["process"]}).status_code == 201
        again = client.get("/api/sockets").json()["listeners"]
        assert not [x for x in again if x["lport"] == port and x["new"]]
    finally:
        server.close()


def test_agents_report_their_sockets(client, monkeypatch, viewer):
    monkeypatch.setattr(settings, "agent_enrollment_key", "s3cret")
    token = enroll(client, "web-1").json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    agent_id = client.get("/api/agents/").json()[0]["id"]
    item = {"proto": "TCP", "family": 4, "local": "0.0.0.0", "lport": 22, "state": "LISTEN", "uid": 0,
            "inode": 11, "pid": 812, "process": "sshd", "user": "root"}
    assert client.get("/api/sockets", params={"host_id": agent_id}).json()["listeners"] == []
    assert client.post("/api/agents/sockets", json={"listeners": [item]}, headers=auth).status_code == 200
    # nc starts before anyone opens the page: still new (the baseline is the first report)
    nc = {**item, "lport": 4444, "pid": 999, "process": "nc", "user": "mallory"}
    client.post("/api/agents/sockets", json={"listeners": [item, nc]}, headers=auth)
    assert client.get("/api/sockets", params={"host_id": agent_id}).json()["host"] == "web-1"
    flagged = {x["lport"]: x["new"] for x in client.get("/api/sockets", params={"host_id": agent_id})
               .json()["listeners"]}
    assert flagged == {22: False, 4444: True}
    # Viewers read but cannot mark known; bad input and unknown agents are refused
    assert viewer.get("/api/sockets", params={"host_id": agent_id}).status_code == 200
    assert viewer.post("/api/sockets/known", json={"host_id": agent_id, "proto": "TCP", "port": 4444}
                       ).status_code == 403
    assert client.post("/api/agents/sockets", json={"listeners": [{**item, "proto": "SCTP"}]},
                       headers=auth).status_code == 422
    assert client.get("/api/sockets", params={"host_id": 999}).status_code == 404


@pytest.mark.parametrize("bad", ["/api/agents/sockets"])
def test_socket_reports_need_an_agent_token(anon, bad):
    assert anon.post(bad, json={}).status_code == 401
