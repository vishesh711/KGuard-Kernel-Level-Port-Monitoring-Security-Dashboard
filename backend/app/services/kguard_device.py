"""
Reader for /dev/kguard, the kernel module's zero-copy event interface.

The module exposes one ring buffer per CPU in a single mmap() area; this
class maps it and consumes events using the protocol in
kernel/include/uapi/linux/kguard.h:

    head = ring.head            (written by the kernel)
    consume slots tail .. head
    ring.tail = head            (written by us, tells the kernel slots are free)

Python cannot issue acquire/release barriers, so this relies on the strong
memory ordering of x86-64.
"""

import mmap
import os
import select
import socket
import struct
from typing import Any, Dict, List, Optional

# struct kguard_event (96 bytes) and struct kguard_mmap_info
EVENT = struct.Struct("<QQ16s16sHHBBBBBB2xIIII16s4x")
INFO = struct.Struct("<IIIIIIQQQ")
MAGIC = 0x4452474B
ABI_VERSION = 1

HEAD_OFFSET = 0
TAIL_OFFSET = 64
DROPPED_OFFSET = 128

AF_INET6 = 10
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
DIRECTIONS = {1: "in", 2: "out", 3: "fwd"}
CT_STATES = {0: "none", 1: "new", 2: "established", 3: "related", 4: "invalid", 5: "untracked"}

EVF_FRAGMENT = 0x01
EVF_PROC = 0x02
EVF_SOCK = 0x04


def decode_event(raw: bytes) -> Dict[str, Any]:
    """Turn one 96-byte record into the same shape as /proc/kguard JSON"""
    (timestamp, sock_ino, src, dst, src_port, dst_port, family, protocol, tcp_flags,
     direction, ct_state, info, netns, pid, uid, ifindex, comm) = EVENT.unpack(raw)
    if family == AF_INET6:
        src_ip = socket.inet_ntop(socket.AF_INET6, src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, dst)
    else:
        src_ip = socket.inet_ntop(socket.AF_INET, src[:4])
        dst_ip = socket.inet_ntop(socket.AF_INET, dst[:4])
    has_proc = bool(info & EVF_PROC)
    has_sock = bool(info & EVF_SOCK)
    return {
        "timestamp": timestamp,
        "family": 6 if family == AF_INET6 else 4,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": PROTOCOLS.get(protocol, "OTHER"),
        "flags": tcp_flags,
        "direction": DIRECTIONS.get(direction, "unknown"),
        "ct_state": CT_STATES.get(ct_state, "none"),
        "netns": netns,
        "ifindex": ifindex,
        "pid": pid if has_proc else -1,
        "comm": comm.split(b"\0", 1)[0].decode(errors="replace") if has_proc else "",
        "uid": uid if has_sock else -1,
        "sock_ino": sock_ino if has_sock else 0,
    }


def encode_event(event: Dict[str, Any]) -> bytes:
    """Inverse of decode_event (used to build fake devices in tests)"""
    v6 = event.get("family") == 6
    af = socket.AF_INET6 if v6 else socket.AF_INET
    info = 0
    if event.get("pid", -1) >= 0:
        info |= EVF_PROC
    if event.get("uid", -1) >= 0:
        info |= EVF_SOCK
    return EVENT.pack(
        event["timestamp"],
        event.get("sock_ino", 0),
        socket.inet_pton(af, event["src_ip"]).ljust(16, b"\0"),
        socket.inet_pton(af, event["dst_ip"]).ljust(16, b"\0"),
        event["src_port"],
        event["dst_port"],
        AF_INET6 if v6 else 2,
        {v: k for k, v in PROTOCOLS.items()}.get(event["protocol"], 255),
        event.get("flags", 0),
        {v: k for k, v in DIRECTIONS.items()}.get(event.get("direction"), 0),
        {v: k for k, v in CT_STATES.items()}.get(event.get("ct_state"), 0),
        info,
        event.get("netns", 0),
        max(event.get("pid", 0), 0),
        max(event.get("uid", 0), 0),
        event.get("ifindex", 0),
        event.get("comm", "").encode()[:15],
    )


class KGuardDevice:
    """An open, mapped /dev/kguard. Only one reader may hold it at a time."""

    def __init__(self, path: str = "/dev/kguard"):
        self.path = path
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        try:
            first = mmap.mmap(self.fd, mmap.PAGESIZE, mmap.MAP_SHARED, mmap.PROT_READ)
            (magic, abi, self.nr_rings, self.event_size, self.slots, self.header_size,
             self.stride, self.rings_offset, self.size) = INFO.unpack_from(first, 0)
            first.close()
            if magic != MAGIC or abi != ABI_VERSION or self.event_size != EVENT.size:
                raise RuntimeError(
                    f"Unsupported KGuard ABI (magic {magic:#x}, version {abi}); "
                    f"rebuild the kernel module and backend from the same release"
                )
            self.mm = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED,
                                mmap.PROT_READ | mmap.PROT_WRITE)
        except Exception:
            os.close(self.fd)
            raise
        self.poller = select.poll()
        self.poller.register(self.fd, select.POLLIN)

    def wait(self, timeout_ms: int) -> bool:
        """Sleep until events are waiting or the timeout passes"""
        return bool(self.poller.poll(timeout_ms))

    def read(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Consume waiting events from every ring, oldest first"""
        raw = []
        mask = self.slots - 1
        for n in range(self.nr_rings):
            base = self.rings_offset + n * self.stride
            (head,) = struct.unpack_from("<Q", self.mm, base + HEAD_OFFSET)
            (tail,) = struct.unpack_from("<Q", self.mm, base + TAIL_OFFSET)
            if head - tail > self.slots:  # bogus tail left by an earlier reader
                tail = head
            data = base + self.header_size
            while tail != head and (limit is None or len(raw) < limit):
                offset = data + (tail & mask) * self.event_size
                raw.append(self.mm[offset:offset + self.event_size])
                tail += 1
            struct.pack_into("<Q", self.mm, base + TAIL_OFFSET, tail)
        events = [decode_event(r) for r in raw]
        events.sort(key=lambda e: e["timestamp"])
        return events

    def dropped(self) -> int:
        """Events the kernel lost because a ring was full (since load)"""
        return sum(
            struct.unpack_from("<Q", self.mm, self.rings_offset + n * self.stride + DROPPED_OFFSET)[0]
            for n in range(self.nr_rings)
        )

    def close(self) -> None:
        self.mm.close()
        os.close(self.fd)


def build_fake_device(path: str, rings: List[List[Dict[str, Any]]], slots: int = 64,
                      dropped: int = 0) -> None:
    """
    Write a regular file with the same layout as the /dev/kguard mapping.
    KGuardDevice can open it like the real device; used by tests.
    """
    page = mmap.PAGESIZE
    stride = page + ((slots * EVENT.size + page - 1) // page) * page
    size = page + len(rings) * stride
    buf = bytearray(size)
    INFO.pack_into(buf, 0, MAGIC, ABI_VERSION, len(rings), EVENT.size, slots, page, stride, page, size)
    for n, events in enumerate(rings):
        base = page + n * stride
        for i, event in enumerate(events):
            off = base + page + (i & (slots - 1)) * EVENT.size
            buf[off:off + EVENT.size] = encode_event(event)
        struct.pack_into("<Q", buf, base + HEAD_OFFSET, len(events))
        struct.pack_into("<Q", buf, base + TAIL_OFFSET, 0)
        struct.pack_into("<Q", buf, base + DROPPED_OFFSET, dropped if n == 0 else 0)
    with open(path, "wb") as f:
        f.write(buf)
