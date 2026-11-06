"""
Packet capture on alert, roadmap N5.11.

Keeps the last `pcap_seconds` of this server's traffic in memory and, when a
high-severity alert is raised, saves the packets involved (from before and
after the alert) as a .pcap file next to the alert.

How the packets get here, cheaply:

  AF_PACKET socket, SOCK_DGRAM (link headers stripped: pcap link type RAW,
  the same for Ethernet, loopback and tunnels), every interface.

  A classic BPF socket filter, a single instruction "ret #snaplen", makes the
  kernel copy only the first `pcap_snaplen` bytes of each packet (headers,
  not bulk payload), before anything reaches user space.

  PACKET_RX_RING with TPACKET_V3: the kernel writes packets straight into a
  ring of blocks mapped into this process, and hands over a whole block at a
  time (when full, or after 100 ms). A thread copies each finished block
  out and gives it back, keeping blocks for `pcap_seconds` within
  `pcap_buffer_mb`. No system call or copy per packet.

On an alert the kept blocks are walked (struct tpacket3_hdr), packets to or
from the alert's addresses are picked, and written as a nanosecond pcap.
A packet sent over loopback is seen twice (outgoing and incoming); only
its incoming copy is kept.

Off by default (`pcap_on_alert`): it records traffic, and it needs root or
CAP_NET_RAW. Only this server's own alerts get a capture; agents' traffic
is not visible here.
"""

import asyncio
import ctypes
import ipaddress
import logging
import mmap
import select
import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, Iterator, List, Optional, Set, Tuple

from ..config import settings
from ..database import SessionLocal
from ..models.security_alert import SecurityAlert

logger = logging.getLogger(__name__)

# <linux/if_packet.h>, <linux/if_ether.h>, <asm-generic/socket.h>
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_RX_RING = 5
PACKET_VERSION = 10
TPACKET_V3 = 2
TP_STATUS_KERNEL, TP_STATUS_USER = 0, 1
PACKET_OUTGOING = 4
SO_ATTACH_FILTER = 26
BPF_RET_K = 0x06
LOOPBACK_IFINDEX = 1

# struct tpacket_block_desc: version, offset_to_priv, then tpacket_hdr_v1
BLOCK_STATUS_OFFSET = 8
BLOCK_HEADER = struct.Struct("=IIIIII")  # version, priv, status, num_pkts, first_pkt, blk_len
# struct tpacket3_hdr: next_offset, sec, nsec, snaplen, len, status, mac, net
PACKET_HEADER = struct.Struct("=IIIIIIHH")
SLL_OFFSET = 48  # TPACKET_ALIGN(sizeof(struct tpacket3_hdr))
SOCKADDR_LL = struct.Struct("=HHiHBB")  # family, protocol, ifindex, hatype, pkttype, halen

PCAP_MAGIC_NS = 0xA1B23C4D
LINKTYPE_RAW = 101

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

Packet = Tuple[int, int, bytes, int]  # sec, nsec, data (snaplen), original length


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8),
                ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter))]


def iter_block(block: bytes) -> Iterator[Packet]:
    """Packets of one TPACKET_V3 block (copied out of the ring)"""
    _version, _priv, _status, num_pkts, offset, _blk_len = BLOCK_HEADER.unpack_from(block, 0)
    for _ in range(num_pkts):
        if offset <= 0 or offset + SLL_OFFSET + SOCKADDR_LL.size > len(block):
            return
        next_offset, sec, nsec, snaplen, length, _st, mac, _net = PACKET_HEADER.unpack_from(block, offset)
        _fam, _proto, ifindex, _hatype, pkttype, _halen = SOCKADDR_LL.unpack_from(block, offset + SLL_OFFSET)
        start = offset + mac
        if not (ifindex == LOOPBACK_IFINDEX and pkttype == PACKET_OUTGOING):
            yield sec, nsec, block[start:start + snaplen], length
        if not next_offset:
            return
        offset += next_offset


def addresses(data: bytes) -> Optional[Tuple[str, str, int, int]]:
    """(src, dst, src port, dst port) of a raw IP packet; ports 0 when absent"""
    if len(data) < 20:
        return None
    version = data[0] >> 4
    if version == 4:
        header = (data[0] & 0x0F) * 4
        proto, src, dst = data[9], data[12:16], data[16:20]
    elif version == 6 and len(data) >= 40:
        header, proto, src, dst = 40, data[6], data[8:24], data[24:40]
    else:
        return None
    sport = dport = 0
    if proto in (6, 17) and len(data) >= header + 4:
        sport, dport = struct.unpack_from("!HH", data, header)
    return str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst)), sport, dport


def write_pcap(path: Path, packets: List[Packet], snaplen: int) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_NS, 2, 4, 0, 0, snaplen, LINKTYPE_RAW))
        for sec, nsec, data, length in packets:
            f.write(struct.pack("<IIII", sec, nsec, len(data), length))
            f.write(data)


def select_packets(blocks, ips: Set[str], port: Optional[int], since: float, until: float) -> List[Packet]:
    chosen = []
    for _ts, block in blocks:
        for packet in iter_block(block):
            sec, nsec, data, _length = packet
            t = sec + nsec / 1e9
            if t < since or t > until:
                continue
            found = addresses(data)
            if not found:
                continue
            src, dst, sport, dport = found
            if not (src in ips or dst in ips):
                continue
            if port and port not in (sport, dport):
                continue
            chosen.append(packet)
    chosen.sort(key=lambda p: (p[0], p[1]))
    return chosen


class PacketCapture:
    def __init__(self):
        self.enabled = settings.pcap_on_alert
        self.seconds = float(settings.pcap_seconds)
        self.post_seconds = float(settings.pcap_post_seconds)
        self.budget = settings.pcap_buffer_mb << 20
        self.snaplen = settings.pcap_snaplen
        self.directory = Path(settings.pcap_dir)
        self.min_severity = SEVERITY_ORDER.get(settings.pcap_min_severity.upper(), 2)
        self.max_files = settings.pcap_max_files
        self.blocks: Deque[Tuple[float, bytes]] = deque()  # (time handed over, block bytes)
        self.buffered = 0
        self.lock = threading.Lock()
        self.sock: Optional[socket.socket] = None
        self.ring: Optional[mmap.mmap] = None
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.pending: Dict[int, asyncio.Task] = {}
        self.stats = {"blocks": 0, "captures": 0, "error": None}

    # ---- ring ----

    def start(self, block_size: int = 1 << 20, retire_ms: int = 100) -> bool:
        if not self.enabled or self.thread:
            return bool(self.thread)
        block_nr = max(4, min(64, self.budget // block_size // 4))
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
            program = (SockFilter * 1)(SockFilter(BPF_RET_K, 0, 0, self.snaplen))
            fprog = SockFprog(1, program)
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))
            sock.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
            # struct tpacket_req3: block_size, block_nr, frame_size, frame_nr, retire_blk_tov,
            # sizeof_priv, feature_req_word
            req = struct.pack("=IIIIIII", block_size, block_nr, 2048, block_size * block_nr // 2048,
                              retire_ms, 0, 0)
            sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
            ring = mmap.mmap(sock.fileno(), block_size * block_nr, mmap.MAP_SHARED,
                             mmap.PROT_READ | mmap.PROT_WRITE)
        except (OSError, AttributeError) as e:
            self.stats["error"] = str(e)
            logger.warning(f"Packet capture on alert unavailable: {e} (needs root or CAP_NET_RAW)")
            return False
        self.sock, self.ring = sock, ring
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, args=(block_size, block_nr), name="pcap-ring",
                                       daemon=True)
        self.thread.start()
        logger.info(f"Packet capture on alert: keeping {self.seconds:.0f} s, up to {self.budget >> 20} MiB, "
                    f"{self.snaplen} bytes per packet")
        return True

    def _run(self, block_size: int, block_nr: int) -> None:
        poller = select.poll()
        poller.register(self.sock.fileno(), select.POLLIN | select.POLLERR)
        current = 0
        while not self.stop_event.is_set():
            base = current * block_size
            status = struct.unpack_from("=I", self.ring, base + BLOCK_STATUS_OFFSET)[0]
            if not status & TP_STATUS_USER:
                poller.poll(200)
                continue
            blk_len = BLOCK_HEADER.unpack_from(self.ring, base)[5]
            block = bytes(self.ring[base:base + min(blk_len, block_size)])
            # Hand the block back to the kernel
            struct.pack_into("=I", self.ring, base + BLOCK_STATUS_OFFSET, TP_STATUS_KERNEL)
            self._keep(block)
            current = (current + 1) % block_nr

    def _keep(self, block: bytes, now: float = None) -> None:
        now = now or time.time()
        with self.lock:
            self.blocks.append((now, block))
            self.buffered += len(block)
            while self.blocks and (self.blocks[0][0] < now - self.seconds - self.post_seconds
                                   or self.buffered > self.budget):
                self.buffered -= len(self.blocks.popleft()[1])
        self.stats["blocks"] += 1

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        for task in self.pending.values():
            task.cancel()
        if self.ring:
            self.ring.close()
        if self.sock:
            self.sock.close()
        self.thread = self.sock = self.ring = None

    # ---- alerts ----

    def wants(self, alert: dict) -> bool:
        return (self.thread is not None and alert.get("host_id") is None and alert.get("id") is not None
                and SEVERITY_ORDER.get(str(alert.get("severity")), 0) >= self.min_severity
                and bool(alert.get("src_ip") or alert.get("dst_ip")))

    def on_alert(self, alert: dict) -> None:
        if not self.wants(alert) or alert["id"] in self.pending:
            return
        self.pending[alert["id"]] = asyncio.ensure_future(self._capture(alert))

    async def _capture(self, alert: dict) -> Optional[Path]:
        try:
            await asyncio.sleep(self.post_seconds)  # also catch what follows the alert
            return await asyncio.get_running_loop().run_in_executor(None, self.save, alert)
        finally:
            self.pending.pop(alert["id"], None)

    def save(self, alert: dict, now: float = None) -> Optional[Path]:
        """Write the alert's packets to a pcap and note it on the alert"""
        now = now or time.time()
        ips = {ip for ip in (alert.get("src_ip"), alert.get("dst_ip")) if ip}
        # Without a source (e.g. a SYN flood from random addresses) narrow by port
        port = alert.get("dst_port") if not alert.get("src_ip") else None
        with self.lock:
            blocks = list(self.blocks)
        packets = select_packets(blocks, ips, port, now - self.seconds - self.post_seconds, now)
        if not packets:
            return None
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"alert-{alert['id']}.pcap"
        write_pcap(path, packets, self.snaplen)
        self._prune()
        self.stats["captures"] += 1

        db = SessionLocal()
        try:
            row = db.get(SecurityAlert, alert["id"])
            if row:
                row.alert_metadata = {**(row.alert_metadata or {}),
                                      "pcap": {"file": path.name, "packets": len(packets),
                                               "seconds": self.seconds + self.post_seconds}}
                db.commit()
        finally:
            db.close()
        logger.info(f"Saved {len(packets)} packets for alert {alert['id']} to {path}")
        return path

    def _prune(self) -> None:
        files = sorted(self.directory.glob("alert-*.pcap"), key=lambda p: p.stat().st_mtime)
        for old in files[: max(0, len(files) - self.max_files)]:
            old.unlink(missing_ok=True)

    def path_for(self, alert_id: int) -> Optional[Path]:
        path = self.directory / f"alert-{int(alert_id)}.pcap"
        return path if path.is_file() else None

    def get_stats(self) -> dict:
        return {**self.stats, "enabled": self.enabled, "running": self.thread is not None,
                "buffered_mb": round(self.buffered / 2**20, 1), "kept_blocks": len(self.blocks)}


packet_capture = PacketCapture()
