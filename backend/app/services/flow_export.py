"""
Flow export over IPFIX (RFC 7011), roadmap N5.10.

Packet events (from this server's kernel module and from agents) are grouped
into unidirectional flows keyed by host and 5-tuple: packets, octets (IP
total length, as IPFIX's octetDeltaCount defines it), first and last packet
time, the OR of TCP flags, direction and interface. A flow is exported when

    it ends     a FIN or RST was seen and nothing followed for 2 s (reason 3)
    it is idle  no packet for `ipfix_idle_timeout` seconds           (reason 1)
    it is long  open for `ipfix_active_timeout` seconds; the flow
                continues in a new record                              (reason 2)
    the table is full (`ipfix_max_flows`): oldest first                (reason 5)

and sent over UDP to each collector in `ipfix_collectors` ("host:port",
usually port 4739), so any IPFIX tool (nfcapd/nfdump, Wireshark, pmacct,
Elastic, ntopng...) can store and query KGuard's traffic.

Wire format: a 16-byte message header (version 10, length, export time,
sequence number = data records sent before this message, observation
domain = the reporting host: 0 for this server, the agent's id otherwise),
then sets. Template set 2 describes records 256 (IPv4) and 257 (IPv6); data
sets carry the records. Over UDP a collector may join at any time, so the
templates are repeated every `ipfix_template_refresh` seconds. Messages are
kept under 1400 bytes so they are never fragmented.

Each network namespace is a separate observation point: a packet from a
container to the host is seen leaving the container's namespace and arriving
in the host's, and counting both in one flow would double it. So the
observation domain is the agent's id for agents, and for this server 0 (the
initial namespace) or the namespace's inode number. Within one namespace a
packet on loopback is seen leaving and arriving; only its outgoing copy is
counted.
"""

import ipaddress
import logging
import socket
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..config import settings

logger = logging.getLogger(__name__)

IPFIX_VERSION = 10
TEMPLATE_SET_ID = 2
TEMPLATE_V4, TEMPLATE_V6 = 256, 257
MAX_MESSAGE = 1400
FIN_GRACE_SECONDS = 2.0
LOOPBACK_IFINDEX = 1
INIT_NETNS = 0xF0000000  # inode of the initial network namespace (PROC_NET_INIT_INO)

END_IDLE, END_ACTIVE, END_FIN, END_FORCED, END_RESOURCES = 1, 2, 3, 4, 5
PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPv6": 58}
FIN, RST = 0x01, 0x04

# (information element id, length): IANA IPFIX registry
COMMON_FIELDS = [
    (7, 2),    # sourceTransportPort
    (11, 2),   # destinationTransportPort
    (4, 1),    # protocolIdentifier
    (6, 2),    # tcpControlBits
    (61, 1),   # flowDirection: 0 ingress, 1 egress
    (136, 1),  # flowEndReason
    (2, 8),    # packetDeltaCount
    (1, 8),    # octetDeltaCount
    (152, 8),  # flowStartMilliseconds
    (153, 8),  # flowEndMilliseconds
    (10, 4),   # ingressInterface (egressInterface for outgoing flows is the same index here)
]
TEMPLATES = {
    TEMPLATE_V4: [(8, 4), (12, 4)] + COMMON_FIELDS,    # sourceIPv4Address, destinationIPv4Address
    TEMPLATE_V6: [(27, 16), (28, 16)] + COMMON_FIELDS,  # sourceIPv6Address, destinationIPv6Address
}
RECORD = {TEMPLATE_V4: struct.Struct("!4s4sHHBHBBQQQQI"), TEMPLATE_V6: struct.Struct("!16s16sHHBHBBQQQQI")}

FlowKey = Tuple[int, str, str, int, int, str]  # observation domain, 5-tuple


@dataclass
class Flow:
    family: int
    direction: int
    ifindex: int
    first_ns: int
    last_ns: int
    packets: int = 0
    octets: int = 0
    tcp_flags: int = 0
    ended_at: Optional[float] = None  # wall time a FIN/RST was seen
    seen_at: float = 0.0              # wall time of the latest packet


def parse_collectors(entries: List[str]) -> List[Tuple[str, int]]:
    """"host:port", "[v6]:port", or a bare host / IPv6 address (port 4739)"""
    result = []
    for entry in entries:
        entry = entry.strip()
        if entry.startswith("["):
            host, _, rest = entry[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else "4739"
        elif entry.count(":") == 1:
            host, port = entry.split(":")
        else:
            host, port = entry, "4739"  # a name, or an IPv6 address without a port
        try:
            port_number = int(port)
        except ValueError:
            logger.error(f"Ignoring IPFIX collector {entry!r}: expected host:port")
            continue
        if host and 0 < port_number < 65536:
            result.append((host, port_number))
        else:
            logger.error(f"Ignoring IPFIX collector {entry!r}: expected host:port")
    return result


def observation_domain(event) -> int:
    host_id = getattr(event, "host_id", None)
    if host_id is not None:
        return host_id
    netns = getattr(event, "netns", None)
    return 0 if netns in (None, 0, INIT_NETNS) else netns & 0xFFFFFFFF


def template_set() -> bytes:
    body = b""
    for template_id, fields in TEMPLATES.items():
        body += struct.pack("!HH", template_id, len(fields))
        body += b"".join(struct.pack("!HH", ie, length) for ie, length in fields)
    return struct.pack("!HH", TEMPLATE_SET_ID, 4 + len(body)) + body


def encode_record(key: FlowKey, flow: Flow, reason: int) -> Tuple[int, bytes]:
    _host, src, dst, sport, dport, protocol = key
    template = TEMPLATE_V6 if flow.family == 6 else TEMPLATE_V4
    return template, RECORD[template].pack(
        ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed, sport, dport,
        PROTOCOL_NUMBERS.get(protocol, 0), flow.tcp_flags, flow.direction, reason,
        flow.packets, flow.octets, flow.first_ns // 1_000_000, flow.last_ns // 1_000_000, flow.ifindex)


class FlowExporter:
    def __init__(self, collectors: List[str] = None):
        if collectors is None:
            collectors = settings.ipfix_collectors
        self.collectors = parse_collectors(collectors)
        self.idle = float(settings.ipfix_idle_timeout)
        self.active = float(settings.ipfix_active_timeout)
        self.max_flows = settings.ipfix_max_flows
        self.template_refresh = float(settings.ipfix_template_refresh)
        self.flows: "OrderedDict[FlowKey, Flow]" = OrderedDict()
        self.sequence: Dict[int, int] = {}  # observation domain -> data records sent
        self.templates_sent: Dict[int, float] = {}
        self.sockets: Dict[int, socket.socket] = {}  # address family -> socket
        self.stats = {"flows_exported": 0, "messages_sent": 0, "send_errors": 0, "packets_counted": 0}

    @property
    def enabled(self) -> bool:
        return bool(self.collectors)

    def reset(self) -> None:
        self.flows.clear()
        self.sequence.clear()
        self.templates_sent.clear()

    # ---- metering ----

    def observe(self, events, now: float = None) -> None:
        if not self.enabled:
            return
        now = now or time.time()
        for e in events:
            direction = getattr(e, "direction", None)
            if direction == "in" and getattr(e, "ifindex", None) == LOOPBACK_IFINDEX:
                continue  # counted when it left
            if not e.timestamp:
                continue
            key = (observation_domain(e), e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.protocol)
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(family=6 if ":" in e.src_ip else 4, direction=1 if direction == "out" else 0,
                            ifindex=getattr(e, "ifindex", None) or 0,
                            first_ns=e.timestamp, last_ns=e.timestamp)
                self.flows[key] = flow
                if len(self.flows) > self.max_flows:
                    old_key, old = self.flows.popitem(last=False)
                    self._export([(old_key, old, END_RESOURCES)])
            flow.packets += 1
            flow.octets += getattr(e, "ip_len", None) or 0
            flow.first_ns = min(flow.first_ns, e.timestamp)
            flow.last_ns = max(flow.last_ns, e.timestamp)
            flow.seen_at = now
            if e.protocol == "TCP":
                flags = e.flags or 0
                flow.tcp_flags |= flags
                if flags & (FIN | RST) and flow.ended_at is None:
                    flow.ended_at = now
        self.stats["packets_counted"] += len(events)

    def tick(self, now: float = None) -> int:
        """Export flows that ended, went idle or ran too long. Returns the number exported."""
        if not self.enabled or not self.flows:
            return 0
        now = now or time.time()
        due = []
        for key, flow in list(self.flows.items()):
            if flow.ended_at is not None and now - flow.seen_at >= FIN_GRACE_SECONDS:
                due.append((key, flow, END_FIN))
            elif now - flow.seen_at >= self.idle:
                due.append((key, flow, END_IDLE))
            elif (flow.last_ns - flow.first_ns) / 1e9 >= self.active:
                due.append((key, flow, END_ACTIVE))
        for key, _flow, reason in due:
            del self.flows[key]
        self._export(due)
        return len(due)

    def flush(self) -> int:
        """Export every open flow (shutdown)"""
        due = [(k, f, END_FORCED) for k, f in self.flows.items()]
        self.flows.clear()
        self._export(due)
        return len(due)

    # ---- export ----

    def _export(self, due) -> None:
        if not due:
            return
        by_domain: Dict[int, List[Tuple[int, bytes]]] = {}
        for key, flow, reason in due:
            by_domain.setdefault(key[0], []).append(encode_record(key, flow, reason))
        for domain, records in by_domain.items():
            for message in self.messages(domain, records):
                self._send(message)
        self.stats["flows_exported"] += len(due)

    def messages(self, domain: int, records: List[Tuple[int, bytes]], now: float = None) -> List[bytes]:
        """Pack records into IPFIX messages under MAX_MESSAGE bytes, templates first when due"""
        now = now or time.time()
        out = []
        pending = list(records)
        while pending:
            sets = b""
            if now - self.templates_sent.get(domain, -1e9) >= self.template_refresh:
                sets += template_set()
                self.templates_sent[domain] = now
            count = 0
            for template_id in (TEMPLATE_V4, TEMPLATE_V6):
                chosen = []
                room = MAX_MESSAGE - 16 - len(sets) - 4
                for record in [r for r in pending if r[0] == template_id]:
                    if len(record[1]) > room:
                        break
                    chosen.append(record)
                    room -= len(record[1])
                if not chosen:
                    continue
                data = b"".join(r[1] for r in chosen)
                sets += struct.pack("!HH", template_id, 4 + len(data)) + data
                for r in chosen:
                    pending.remove(r)
                count += len(chosen)
            sequence = self.sequence.get(domain, 0)
            header = struct.pack("!HHIII", IPFIX_VERSION, 16 + len(sets), int(now), sequence, domain)
            self.sequence[domain] = (sequence + count) & 0xFFFFFFFF
            out.append(header + sets)
        return out

    def _send(self, message: bytes) -> None:
        for host, port in self.collectors:
            try:
                family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
                sock = self.sockets.get(family)
                if sock is None:
                    sock = self.sockets[family] = socket.socket(family, socket.SOCK_DGRAM)
                sock.sendto(message, address)
                self.stats["messages_sent"] += 1
            except OSError as e:
                self.stats["send_errors"] += 1
                logger.debug(f"IPFIX send to {host}:{port} failed: {e}")

    def get_stats(self) -> dict:
        return {**self.stats, "enabled": self.enabled, "active_flows": len(self.flows),
                "collectors": [f"{h}:{p}" for h, p in self.collectors]}


flow_exporter = FlowExporter()
