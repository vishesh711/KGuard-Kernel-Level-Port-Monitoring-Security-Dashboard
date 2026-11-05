"""
Minimal Python reader for /dev/kguard (standard library only).

Maps the per-CPU rings and consumes events using the protocol described in
include/uapi/linux/kguard.h. Python cannot issue acquire/release barriers,
so this relies on the strong memory ordering of x86-64; use the C reader
(kernel/tools/kguard_reader) on weakly ordered CPUs.
"""

import mmap
import os
import select
import socket
import struct

EVENT = struct.Struct("<QQ16s16sHHBBBBBB2xIIII16s4x")
INFO = struct.Struct("<IIIIIIQQQ")
MAGIC = 0x4452474B
ABI_VERSION = 1

TAIL_OFFSET = 64
DROPPED_OFFSET = 128

PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
DIRECTIONS = {1: "in", 2: "out", 3: "fwd"}
CT_STATES = {0: "none", 1: "new", 2: "established", 3: "related", 4: "invalid", 5: "untracked"}

EVF_FRAGMENT = 0x01
EVF_PROC = 0x02
EVF_SOCK = 0x04


def decode(raw):
    (ts, ino, src, dst, sport, dport, family, proto, flags, direction, ct, info,
     netns, pid, uid, ifindex, comm) = EVENT.unpack(raw)
    af = socket.AF_INET6 if family == 10 else socket.AF_INET
    size = 16 if af == socket.AF_INET6 else 4
    return {
        "timestamp": ts,
        "family": 6 if af == socket.AF_INET6 else 4,
        "src_ip": socket.inet_ntop(af, src[:size]),
        "dst_ip": socket.inet_ntop(af, dst[:size]),
        "src_port": sport,
        "dst_port": dport,
        "protocol": PROTOCOLS.get(proto, "OTHER"),
        "flags": flags,
        "direction": DIRECTIONS.get(direction, "unknown"),
        "ct_state": CT_STATES.get(ct, "none"),
        "netns": netns,
        "ifindex": ifindex,
        "pid": pid if info & EVF_PROC else -1,
        "comm": comm.split(b"\0", 1)[0].decode(errors="replace") if info & EVF_PROC else "",
        "uid": uid if info & EVF_SOCK else -1,
        "sock_ino": ino if info & EVF_SOCK else 0,
        "fragment": bool(info & EVF_FRAGMENT),
    }


class KGuardDevice:
    def __init__(self, path="/dev/kguard"):
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        head = mmap.mmap(self.fd, mmap.PAGESIZE, mmap.MAP_SHARED, mmap.PROT_READ)
        (magic, abi, self.nr_rings, self.event_size, self.slots, self.header_size,
         self.stride, self.rings_offset, self.size) = INFO.unpack_from(head, 0)
        head.close()
        if magic != MAGIC or abi != ABI_VERSION or self.event_size != EVENT.size:
            raise RuntimeError(f"unsupported KGuard ABI: magic={magic:#x} abi={abi}")
        self.mm = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        self.poller = select.poll()
        self.poller.register(self.fd, select.POLLIN)

    def wait(self, timeout_ms):
        """Sleep until events are waiting or the timeout passes"""
        return bool(self.poller.poll(timeout_ms))

    def read_raw(self, limit=None):
        """Consume waiting events; returns raw 96-byte records"""
        out = []
        mask = self.slots - 1
        for n in range(self.nr_rings):
            base = self.rings_offset + n * self.stride
            head, = struct.unpack_from("<Q", self.mm, base)
            tail, = struct.unpack_from("<Q", self.mm, base + TAIL_OFFSET)
            if head - tail > self.slots:  # bogus tail from an earlier reader
                tail = head
            data = base + self.header_size
            while tail != head and (limit is None or len(out) < limit):
                off = data + (tail & mask) * self.event_size
                out.append(self.mm[off:off + self.event_size])
                tail += 1
            struct.pack_into("<Q", self.mm, base + TAIL_OFFSET, tail)
        return out

    def read(self, limit=None):
        return [decode(raw) for raw in self.read_raw(limit)]

    def dropped(self):
        return sum(
            struct.unpack_from("<Q", self.mm, self.rings_offset + n * self.stride + DROPPED_OFFSET)[0]
            for n in range(self.nr_rings)
        )

    def close(self):
        self.mm.close()
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
