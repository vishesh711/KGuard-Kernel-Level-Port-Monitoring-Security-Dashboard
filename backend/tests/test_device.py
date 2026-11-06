"""Zero-copy /dev/kguard source, kernel v2 fields and process names (Phase 2)"""

import os
import time

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, inspect

from app.models.network_event import NetworkEvent
from app.models.security_alert import SecurityAlert
from app.services.data_collector import data_collector
from app.services.kguard_device import (
    INFO,
    MAGIC,
    KGuardDevice,
    build_fake_device,
    decode_event,
    encode_event,
)
from app.services.process_resolver import ProcessResolver

from .conftest import TCP_SYN


def v2_event(**fields):
    base = {
        "timestamp": time.time_ns(),
        "family": 4,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 40000,
        "dst_port": 443,
        "protocol": "TCP",
        "flags": 0x10,
        "direction": "in",
        "ct_state": "established",
        "netns": 4026531840,
        "ifindex": 2,
        "pid": -1,
        "comm": "",
        "uid": -1,
        "sock_ino": 0,
        "ttl": 64,
        "ip_len": 52,
        "df": True,
        "tcp_window": 502,
        "tcp_mss": 0,
        "tcp_wscale": -1,
        "tcp_options": "",
    }
    base.update(fields)
    return base


def test_encode_decode_round_trip():
    for event in (
        v2_event(),
        v2_event(family=6, src_ip="2001:db8::1", dst_ip="::1", protocol="UDP", direction="out",
                 pid=4242, comm="curl", uid=1000, sock_ino=98765, ct_state="new"),
        v2_event(flags=0x02, ttl=128, tcp_window=64240, tcp_mss=1460, tcp_wscale=8,
                 tcp_options="M,N,W,N,N,S"),
    ):
        assert decode_event(encode_event(event)) == event


def test_collects_from_device_and_advances_tail(fake_device, collect, db):
    t = time.time_ns()
    build_fake_device(fake_device, [
        [v2_event(timestamp=t + 2, dst_port=22), v2_event(timestamp=t + 4)],
        [v2_event(timestamp=t + 1, family=6, src_ip="2001:db8::7", dst_ip="2001:db8::1",
                  direction="out", pid=321, comm="curl", uid=1000, sock_ino=555, ct_state="new")],
    ])

    assert collect() == 3
    assert data_collector.active_source == "device"
    assert collect() == 0  # the tail moved past what was read

    rows = db.query(NetworkEvent).order_by(NetworkEvent.timestamp).all()
    assert [r.timestamp for r in rows] == [t + 1, t + 2, t + 4]
    first = rows[0]
    assert (first.family, first.src_ip, first.direction, first.ct_state) == (6, "2001:db8::7", "out", "new")
    assert (first.pid, first.process_name, first.uid, first.sock_ino) == (321, "curl", 1000, 555)
    assert rows[1].pid is None and rows[1].process_name is None and rows[1].uid is None


def test_device_events_appear_in_api(fake_device, collect, client):
    build_fake_device(fake_device, [[v2_event(direction="in", pid=77, comm="nginx", uid=33, sock_ino=9)]])
    collect()
    item = client.get("/api/events/").json()["items"][0]
    assert item["direction"] == "in"
    assert item["process_name"] == "nginx"
    assert item["pid"] == 77
    assert item["ct_state"] == "established"


def test_device_drop_counter(fake_device, collect, client):
    build_fake_device(fake_device, [[v2_event()]], dropped=17)
    collect()
    assert data_collector.stats["kernel_events_dropped"] == 17
    details = client.get("/api/health/kernel").json()["details"]
    assert details["device_open"] is True
    assert details["source"] == "device"


def test_wrong_abi_falls_back_to_proc(fake_device, fake_kernel, collect, db):
    build_fake_device(fake_device, [[v2_event()]])
    with open(fake_device, "r+b") as f:  # corrupt the magic number
        f.write(INFO.pack(MAGIC ^ 1, *([0] * 8))[:4])
    fake_kernel.write([v2_event(dst_port=8080)])

    assert collect() == 1
    assert data_collector.active_source == "proc"
    assert db.query(NetworkEvent).one().dst_port == 8080


def test_proc_v2_fields_are_stored(fake_kernel, collect, db):
    fake_kernel.write_raw(
        '{"dropped": 0, "events": [\n'
        '{"timestamp": 1762380000123456789, "family": 6, "src_ip": "::1", "dst_ip": "::1", '
        '"src_port": 5000, "dst_port": 53, "protocol": "UDP", "flags": 0, "direction": "out", '
        '"ct_state": "new", "netns": 4026531840, "ifindex": 1, "pid": 99, "comm": "dig", '
        '"uid": 0, "sock_ino": 1234}\n]}\n'
    )
    assert collect() == 1
    row = db.query(NetworkEvent).one()
    assert (row.family, row.direction, row.process_name) == (6, "out", "dig")
    assert (row.uid, row.netns) == (0, 4026531840)


def make_fake_proc(root, processes):
    """processes: {pid: (comm, [socket inodes])}"""
    for pid, (comm, inodes) in processes.items():
        fd_dir = root / str(pid) / "fd"
        fd_dir.mkdir(parents=True)
        (root / str(pid) / "comm").write_text(comm + "\n")
        for n, inode in enumerate(inodes):
            os.symlink(f"socket:[{inode}]", fd_dir / str(n + 3))
        os.symlink("/dev/null", fd_dir / "0")


def test_process_resolver(tmp_path):
    make_fake_proc(tmp_path, {100: ("nc", [5555]), 200: ("sshd", [6000, 6001])})
    resolver = ProcessResolver(str(tmp_path), min_rescan_seconds=0)
    assert resolver.lookup(5555) == (100, "nc")
    assert resolver.lookup_many([6001, 7777]) == {6001: (200, "sshd")}


def test_resolver_rescans_at_most_once_per_interval(tmp_path):
    make_fake_proc(tmp_path, {100: ("nc", [5555])})
    resolver = ProcessResolver(str(tmp_path), min_rescan_seconds=60)
    resolver.lookup(5555)
    resolver.lookup(9999)  # unknown, but a scan just ran
    assert resolver.scans == 1


def test_collector_names_socket_owners(fake_device, collect, db, tmp_path, monkeypatch):
    make_fake_proc(tmp_path, {4321: ("nc", [8888])})
    monkeypatch.setattr(data_collector, "resolver", ProcessResolver(str(tmp_path), min_rescan_seconds=0))
    build_fake_device(fake_device, [[v2_event(direction="in", dst_port=4444, flags=TCP_SYN,
                                              uid=1000, sock_ino=8888)]])
    collect()
    row = db.query(NetworkEvent).one()
    assert (row.pid, row.process_name, row.sock_ino) == (4321, "nc", 8888)


def test_outgoing_copies_do_not_count_twice(fake_device, collect, db):
    # A local scan: every SYN is seen leaving and arriving
    events = []
    for port in range(12):
        for direction in ("out", "in"):
            events.append(v2_event(src_ip="127.0.0.1", dst_ip="127.0.0.1", dst_port=1000 + port,
                                   flags=TCP_SYN, direction=direction, ct_state="new"))
    build_fake_device(fake_device, [events])
    collect()
    alert = db.query(SecurityAlert).one()
    assert alert.alert_metadata["unique_ports"] == 12
    assert len(alert.related_event_ids) == 12


def test_outgoing_only_traffic_raises_no_alerts(fake_device, collect, db):
    build_fake_device(fake_device, [[
        v2_event(dst_port=1000 + p, flags=TCP_SYN, direction="out") for p in range(30)
    ]])
    collect()
    assert db.query(SecurityAlert).count() == 0


def test_old_database_gets_new_columns(tmp_path, monkeypatch):
    import app.database as database

    old = create_engine(f"sqlite:///{tmp_path}/old.db")
    Table("network_events", MetaData(), Column("id", Integer, primary_key=True),
          Column("src_ip", String(45))).create(old)
    monkeypatch.setattr(database, "engine", old)
    database._add_missing_columns()
    columns = {c["name"] for c in inspect(old).get_columns("network_events")}
    assert {"direction", "process_name", "sock_ino", "netns"} <= columns


def test_device_reader_class_reads_once(fake_device):
    build_fake_device(fake_device, [[v2_event(dst_port=p) for p in (1, 2, 3)]], slots=4)
    dev = KGuardDevice(fake_device)
    try:
        assert [e["dst_port"] for e in dev.read()] == [1, 2, 3]
        assert dev.read() == []
    finally:
        dev.close()


def test_resolver_scans_on_first_lookup_right_after_boot(tmp_path, monkeypatch):
    # On a freshly booted machine time.monotonic() is small; the first lookup must still scan
    import app.services.process_resolver as pr

    make_fake_proc(tmp_path, {100: ("nc", [5555])})
    monkeypatch.setattr(pr.time, "monotonic", lambda: 3.0)
    resolver = ProcessResolver(str(tmp_path), min_rescan_seconds=60)
    assert resolver.lookup(5555) == (100, "nc")
