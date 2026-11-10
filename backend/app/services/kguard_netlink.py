"""
Minimal Generic Netlink client for the KGuard kernel module.

Resolves the "kguard" family, joins its "events" multicast group and
decodes the alerts the in-kernel guard sends. Constants mirror
kernel/include/uapi/linux/kguard.h (checked by tests/test_kernel_abi.py).
"""

import ipaddress
import os
import socket
import struct
from typing import Any, Dict, Iterator, List, Optional, Tuple

NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NLMSG_ERROR = 2
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4

GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_OPS = 6
CTRL_ATTR_OP_ID = 1
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

KGUARD_GENL_NAME = "kguard"
KGUARD_GENL_MCGRP = "events"

# enum kguard_genl_cmd
KGUARD_CMD_CONFIG_CHANGED = 4
KGUARD_CMD_ALERT = 5
KGUARD_CMD_GET_STATS = 1
KGUARD_CMD_GET_CONFIG = 2
KGUARD_CMD_BLOCK_ADD = 6  # present from module v3 on, which also sends alerts
KGUARD_CMD_BLOCK_DEL = 7

# enum kguard_genl_attr
KGUARD_ATTR_CFG_ENFORCE = 22
# GET_STATS reply: attribute id -> name (as in kguardctl and debugfs "stats")
STATS = {1: "packets", 2: "events", 3: "dropped", 4: "filtered", 5: "ns_per_packet", 6: "ring_fill",
         7: "netns_hooked", 15: "sources", 16: "track_full", 17: "alerts", 18: "block_drops",
         19: "rate_drops", 20: "would_drop", 21: "blocks", 43: "spoofed"}
KGUARD_ATTR_ADDR = 29
KGUARD_ATTR_TIMEOUT = 31
KGUARD_ATTR_NETNS = 34
KGUARD_ATTR_TIMESTAMP = 35
KGUARD_ATTR_ALERT_TYPE = 36
KGUARD_ATTR_ALERT_ACTION = 37
KGUARD_ATTR_ALERT_PORTS = 38
KGUARD_ATTR_ALERT_ATTEMPTS = 39
KGUARD_ATTR_SPOOF_REASON = 41
KGUARD_ATTR_IFINDEX = 42

ALERT_TYPES = {1: "scan", 2: "syn_rate", 3: "spoof"}
SPOOF_REASONS = {1: "loopback", 2: "local", 3: "martian"}
ALERT_ACTIONS = {0: "none", 1: "dropped", 2: "blocked"}


def attr(atype: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("HH", length, atype) + payload + b"\0" * (-length % 4)


def iter_attrs(data: bytes) -> Iterator[Tuple[int, bytes]]:
    off = 0
    while off + 4 <= len(data):
        length, atype = struct.unpack_from("HH", data, off)
        if length < 4:
            break
        yield atype & 0x3FFF, data[off + 4: off + length]
        off += (length + 3) & ~3


def parse_attrs(data: bytes) -> Dict[int, bytes]:
    return dict(iter_attrs(data))


def iter_messages(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """(netlink message type, body after the netlink header) for each message"""
    off = 0
    while off + 16 <= len(data):
        length, mtype = struct.unpack_from("IH", data, off)
        if length < 16:
            break
        yield mtype, data[off + 16: off + length]
        off += (length + 3) & ~3


def genl_split(body: bytes) -> Tuple[int, bytes]:
    """(genl command, attributes) of a Generic Netlink message body"""
    return (body[0] if body else 0), body[4:]


def decode_alert(payload: bytes) -> Dict[str, Any]:
    a = parse_attrs(payload)
    return {
        "type": ALERT_TYPES.get(a[KGUARD_ATTR_ALERT_TYPE][0], "unknown"),
        "action": ALERT_ACTIONS.get(a[KGUARD_ATTR_ALERT_ACTION][0], "unknown"),
        "src_ip": str(ipaddress.ip_address(a[KGUARD_ATTR_ADDR])),
        "netns": struct.unpack("I", a[KGUARD_ATTR_NETNS][:4])[0],
        "ports": struct.unpack("I", a[KGUARD_ATTR_ALERT_PORTS][:4])[0],
        "attempts": struct.unpack("I", a[KGUARD_ATTR_ALERT_ATTEMPTS][:4])[0],
        "timestamp": struct.unpack("Q", a[KGUARD_ATTR_TIMESTAMP][:8])[0],
        **({"spoof_reason": SPOOF_REASONS.get(a[KGUARD_ATTR_SPOOF_REASON][0], "unknown"),
            "ifindex": struct.unpack("I", a[KGUARD_ATTR_IFINDEX][:4])[0]}
           if KGUARD_ATTR_SPOOF_REASON in a else {}),
    }


def encode_alert(alert: Dict[str, Any]) -> bytes:
    """Inverse of decode_alert, wrapped as a netlink message (used by tests)"""
    types = {v: k for k, v in ALERT_TYPES.items()}
    actions = {v: k for k, v in ALERT_ACTIONS.items()}
    payload = (
        attr(KGUARD_ATTR_TIMESTAMP, struct.pack("Q", alert["timestamp"]))
        + attr(KGUARD_ATTR_ADDR, ipaddress.ip_address(alert["src_ip"]).packed)
        + attr(KGUARD_ATTR_NETNS, struct.pack("I", alert.get("netns", 0)))
        + attr(KGUARD_ATTR_ALERT_TYPE, struct.pack("B", types[alert["type"]]))
        + attr(KGUARD_ATTR_ALERT_ACTION, struct.pack("B", actions[alert["action"]]))
        + attr(KGUARD_ATTR_ALERT_PORTS, struct.pack("I", alert.get("ports", 0)))
        + attr(KGUARD_ATTR_ALERT_ATTEMPTS, struct.pack("I", alert.get("attempts", 0)))
    )
    if "spoof_reason" in alert:
        reasons = {v: k for k, v in SPOOF_REASONS.items()}
        payload += (attr(KGUARD_ATTR_SPOOF_REASON, struct.pack("B", reasons[alert["spoof_reason"]]))
                    + attr(KGUARD_ATTR_IFINDEX, struct.pack("I", alert.get("ifindex", 0))))
    body = struct.pack("BBH", KGUARD_CMD_ALERT, 1, 0) + payload
    return struct.pack("IHHII", 16 + len(body), 0x20, 0, 0, 0) + body


class KGuardEventSocket:
    """A netlink socket joined to the kernel module's multicast events"""

    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        try:
            self.sock.bind((0, 0))
            self.family, groups, ops = self._resolve()
            # v2 modules have the events group but never send alerts
            self.sends_alerts = KGUARD_CMD_BLOCK_ADD in ops
            self.sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, groups[KGUARD_GENL_MCGRP])
            self.sock.setblocking(False)
        except Exception:
            self.sock.close()
            raise

    def fileno(self) -> int:
        return self.sock.fileno()

    def _resolve(self) -> Tuple[int, Dict[str, int], set]:
        body = struct.pack("BBH", CTRL_CMD_GETFAMILY, 1, 0) + attr(
            CTRL_ATTR_FAMILY_NAME, KGUARD_GENL_NAME.encode() + b"\0"
        )
        header = struct.pack("IHHII", 16 + len(body), GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
        self.sock.send(header + body)
        reply: Optional[bytes] = None
        while True:
            for mtype, body in iter_messages(self.sock.recv(65536)):
                if mtype == NLMSG_ERROR:
                    error = struct.unpack_from("i", body)[0] if len(body) >= 4 else 0
                    if error or reply is None:
                        raise OSError(-error or 2, "KGuard netlink family not found")
                    family_attrs = parse_attrs(reply)
                    groups = {}
                    for _idx, grp in iter_attrs(family_attrs.get(CTRL_ATTR_MCAST_GROUPS, b"")):
                        g = parse_attrs(grp)
                        name = g[CTRL_ATTR_MCAST_GRP_NAME].rstrip(b"\0").decode()
                        groups[name] = struct.unpack("I", g[CTRL_ATTR_MCAST_GRP_ID][:4])[0]
                    ops = set()
                    for _idx, op in iter_attrs(family_attrs.get(CTRL_ATTR_OPS, b"")):
                        op_attrs = parse_attrs(op)
                        if CTRL_ATTR_OP_ID in op_attrs:
                            ops.add(struct.unpack("I", op_attrs[CTRL_ATTR_OP_ID][:4])[0])
                    family = struct.unpack("H", family_attrs[CTRL_ATTR_FAMILY_ID][:2])[0]
                    return family, groups, ops
                reply = genl_split(body)[1]

    def read_alerts(self) -> List[Dict[str, Any]]:
        """Decode every alert waiting on the socket (non-blocking)"""
        alerts = []
        while True:
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                return alerts
            for _mtype, body in iter_messages(data):
                cmd, payload = genl_split(body)
                if cmd == KGUARD_CMD_ALERT:
                    alerts.append(decode_alert(payload))

    def close(self) -> None:
        self.sock.close()


class KGuardControlSocket:
    """
    Requests to the kernel module (roadmap S6.4): add and remove blocks, read
    whether it enforces them. Block commands need CAP_NET_ADMIN; without it
    the kernel answers EPERM, raised as PermissionError.
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.seq = 100
        try:
            self.sock.bind((0, 0))
            self.sock.settimeout(2.0)
            # Reuse the event socket's family lookup
            self.family = KGuardEventSocket._resolve(self)[0]
        except Exception:
            self.sock.close()
            raise

    def request(self, cmd: int, payload: bytes = b"") -> List[bytes]:
        """Send one command with an ACK request; return the reply payloads"""
        self.seq += 1
        body = struct.pack("BBH", cmd, 1, 0) + payload
        header = struct.pack("IHHII", 16 + len(body), self.family, NLM_F_REQUEST | NLM_F_ACK, self.seq, 0)
        self.sock.send(header + body)
        replies = []
        while True:
            for mtype, body in iter_messages(self.sock.recv(65536)):
                if mtype == NLMSG_ERROR:
                    error = struct.unpack_from("i", body)[0] if len(body) >= 4 else 0
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    return replies
                replies.append(genl_split(body)[1])

    def block_add(self, address: str, timeout_s: int) -> None:
        self.request(KGUARD_CMD_BLOCK_ADD, attr(KGUARD_ATTR_ADDR, ipaddress.ip_address(address).packed)
                     + attr(KGUARD_ATTR_TIMEOUT, struct.pack("I", max(0, int(timeout_s)))))

    def block_del(self, address: str) -> None:
        self.request(KGUARD_CMD_BLOCK_DEL, attr(KGUARD_ATTR_ADDR, ipaddress.ip_address(address).packed))

    def stats(self) -> Dict[str, int]:
        """The module's counters (GET_STATS needs no privileges)"""
        values: Dict[str, int] = {}
        for payload in self.request(KGUARD_CMD_GET_STATS):
            for attr_id, raw in parse_attrs(payload).items():
                if attr_id in STATS and len(raw) >= 8:
                    values[STATS[attr_id]] = struct.unpack("Q", raw[:8])[0]
        return values

    def enforcing(self) -> Optional[bool]:
        """Whether the module drops blocked traffic (enforce=1), or None if unknown"""
        for payload in self.request(KGUARD_CMD_GET_CONFIG):
            value = parse_attrs(payload).get(KGUARD_ATTR_CFG_ENFORCE)
            if value:
                return bool(value[0])
        return None

    def close(self) -> None:
        self.sock.close()
