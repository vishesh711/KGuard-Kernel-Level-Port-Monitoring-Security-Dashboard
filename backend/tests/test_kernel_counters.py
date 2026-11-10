"""Kernel health panel data (U7.7): the module's counters over Generic Netlink"""

import struct

import app.api.health as health
from app.services.kguard_netlink import STATS, attr


class FakeControl:
    def __init__(self, *args):
        pass

    def request(self, cmd, payload=b""):
        # One GET_STATS reply: every counter, value = attribute id * 1000
        return [b"".join(attr(a, struct.pack("Q", a * 1000)) for a in STATS)]

    def stats(self):
        from app.services.kguard_netlink import KGuardControlSocket

        return KGuardControlSocket.stats(self)

    def enforcing(self):
        return False

    def close(self):
        pass


def test_no_module(client, monkeypatch):
    def missing():
        raise OSError(2, "No such file or directory")
    monkeypatch.setattr(health, "KGuardControlSocket", missing)
    assert client.get("/api/health/kernel/counters").json() == {
        "available": False, "reason": "kernel module not loaded (No such file or directory)"}


def test_counters_are_decoded(client, monkeypatch, viewer):
    monkeypatch.setattr(health, "KGuardControlSocket", FakeControl)
    monkeypatch.setattr(health, "ring_capacity", lambda: 65536)
    body = viewer.get("/api/health/kernel/counters").json()
    assert body["available"] is True and body["enforcing"] is False and body["ring_capacity"] == 65536
    assert body["stats"]["packets"] == 1000 and body["stats"]["ns_per_packet"] == 5000
    assert body["stats"]["spoofed"] == 43000
    assert set(body["stats"]) == set(STATS.values())


def test_ring_capacity_rounds_like_the_kernel(monkeypatch, tmp_path):
    files = {"/sys/module/kguard/parameters/buffer_size": "10000\n",
             "/sys/devices/system/cpu/possible": "0-3\n"}
    real_open = open

    def fake_open(path, *args, **kwargs):
        if path in files:
            target = tmp_path / path.replace("/", "_")
            target.write_text(files[path])
            return real_open(target, *args, **kwargs)
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(health.data_collector, "device", None)
    assert health.ring_capacity() == 4 * 16384  # 10000 rounds up to 16384 per CPU
    files["/sys/module/kguard/parameters/buffer_size"] = "10"
    assert health.ring_capacity() == 4 * 64  # at least 64
