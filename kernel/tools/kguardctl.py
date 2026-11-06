#!/usr/bin/env python3
"""
kguardctl - control the KGuard kernel module over Generic Netlink.

Uses only the Python standard library: it speaks raw Generic Netlink
(resolving the "kguard" family through the nlctrl controller).

  kguardctl stats                          counters
  kguardctl config                         current configuration
  kguardctl set enforce=1 syn_rate=100     change configuration (root)
  kguardctl block 203.0.113.9 [--timeout 600]   block an address (root)
  kguardctl unblock 203.0.113.9            (root)
  kguardctl blocks                         list blocked addresses
  kguardctl allow 10.0.0.0/8               never block this prefix (root)
  kguardctl disallow 10.0.0.0/8            (root)
  kguardctl allowlist                      list allowed prefixes
  kguardctl watch                          print alerts and configuration changes

Add --json for machine-readable output.
"""

import argparse
import ipaddress
import json
import os
import socket
import struct
import sys

NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1

NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLM_F_DUMP = 0x300
NLA_F_NESTED = 0x8000

GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

# Mirrors include/uapi/linux/kguard.h (checked by backend/tests/test_kernel_abi.py)
KGUARD_GENL_NAME = "kguard"
KGUARD_GENL_VERSION = 1
KGUARD_GENL_MCGRP = "events"

CMD_GET_STATS = 1
CMD_GET_CONFIG = 2
CMD_SET_CONFIG = 3
CMD_CONFIG_CHANGED = 4
CMD_ALERT = 5
CMD_BLOCK_ADD = 6
CMD_BLOCK_DEL = 7
CMD_BLOCK_LIST = 8
CMD_ALLOW_ADD = 9
CMD_ALLOW_DEL = 10
CMD_ALLOW_LIST = 11

STATS = {
    1: "packets",
    2: "events",
    3: "dropped",
    4: "filtered",
    5: "ns_per_packet",
    6: "ring_fill",
    7: "netns",
    15: "sources",
    16: "track_full",
    17: "alerts",
    18: "block_drops",
    19: "rate_drops",
    20: "would_drop",
    21: "blocks",
    43: "spoofed",
}
CONFIG = {  # attribute id: (name, struct format)
    9: ("capture_in", "B"),
    10: ("capture_out", "B"),
    11: ("capture_fwd", "B"),
    12: ("capture_ipv6", "B"),
    13: ("socket_lookup", "B"),
    14: ("wakeup_events", "I"),
    22: ("enforce", "B"),
    23: ("auto_block", "B"),
    24: ("scan_threshold", "I"),
    25: ("scan_window_ms", "I"),
    26: ("syn_rate", "I"),
    27: ("syn_burst", "I"),
    28: ("block_timeout", "I"),
}
CONFIG_BY_NAME = {name: (attr, fmt) for attr, (name, fmt) in CONFIG.items()}

ATTR_ADDR = 29
ATTR_PREFIX_LEN = 30
ATTR_TIMEOUT = 31
ATTR_EXPIRES_MS = 32
ATTR_REASON = 33
ATTR_NETNS = 34
ATTR_TIMESTAMP = 35
ATTR_ALERT_TYPE = 36
ATTR_ALERT_ACTION = 37
ATTR_ALERT_PORTS = 38
ATTR_ALERT_ATTEMPTS = 39
ATTR_ALLOW_ENTRY = 40
ATTR_SPOOF_REASON = 41
ATTR_IFINDEX = 42

ALERT_TYPES = {1: "scan", 2: "syn_rate", 3: "spoof"}
SPOOF_REASONS = {1: "loopback", 2: "local", 3: "martian"}
ALERT_ACTIONS = {0: "none", 1: "dropped", 2: "blocked"}
BLOCK_REASONS = {1: "manual", 2: "scan", 3: "syn_rate"}


def attr(atype, payload):
    length = 4 + len(payload)
    return struct.pack("HH", length, atype) + payload + b"\0" * (-length % 4)


def parse_attrs(data):
    attrs = {}
    off = 0
    while off + 4 <= len(data):
        length, atype = struct.unpack_from("HH", data, off)
        if length < 4:
            break
        attrs.setdefault(atype & 0x3FFF, []).append(data[off + 4: off + length])
        off += (length + 3) & ~3
    return {k: v[0] if len(v) == 1 else v for k, v in attrs.items()}


def iter_attrs(data):
    """Payloads of every attribute, in order"""
    off = 0
    while off + 4 <= len(data):
        length, _ = struct.unpack_from("HH", data, off)
        if length < 4:
            break
        yield data[off + 4: off + length]
        off += (length + 3) & ~3


def parse_attr_list(data, atype):
    """All attributes of one type (for repeated nests)"""
    out = []
    off = 0
    while off + 4 <= len(data):
        length, t = struct.unpack_from("HH", data, off)
        if length < 4:
            break
        if t & 0x3FFF == atype:
            out.append(data[off + 4: off + length])
        off += (length + 3) & ~3
    return out


def addr_bytes(text):
    return ipaddress.ip_address(text).packed


def addr_text(raw):
    return str(ipaddress.ip_address(raw))


def u(raw, fmt):
    return struct.unpack(fmt, raw[: struct.calcsize(fmt)])[0]


class GenlSocket:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.seq = 0

    def request(self, family, cmd, payload=b"", version=1, dump=False):
        """Send one request; return the reply's payload (or all payloads of a dump)"""
        self.seq += 1
        flags = NLM_F_REQUEST | (NLM_F_DUMP if dump else NLM_F_ACK)
        body = struct.pack("BBH", cmd, version, 0) + payload
        self.sock.send(struct.pack("IHHII", 16 + len(body), family, flags, self.seq, 0) + body)

        replies = []
        while True:
            data = self.sock.recv(1 << 20)
            off = 0
            while off + 16 <= len(data):
                length, mtype, _flags, seq, _pid = struct.unpack_from("IHHII", data, off)
                msg = data[off + 16: off + length]
                off += (length + 3) & ~3
                if seq != self.seq:
                    continue
                if mtype == NLMSG_DONE:
                    return replies
                if mtype == NLMSG_ERROR:
                    (error,) = struct.unpack_from("i", msg)
                    if error:
                        raise OSError(-error, os.strerror(-error) + self._extack(msg, length))
                    return replies if dump else (replies[0] if replies else None)
                replies.append(msg[4:])

    @staticmethod
    def _extack(msg, length):
        """Kernel's error message (NLMSGERR_ATTR_MSG), when present"""
        try:
            # error code + original header (and maybe payload) + TLVs
            orig_len = struct.unpack_from("I", msg, 4)[0]
            for offset in (4 + orig_len, 20):
                attrs = parse_attrs(msg[offset:])
                if 1 in attrs and isinstance(attrs[1], bytes):
                    return ": " + attrs[1].rstrip(b"\0").decode(errors="replace")
        except struct.error:
            pass
        return ""

    def resolve(self, name):
        """Return (family id, {multicast group name: id})"""
        reply = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attr(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\0"))
        attrs = parse_attrs(reply)
        family = u(attrs[CTRL_ATTR_FAMILY_ID], "H")
        groups = {}
        for grp in iter_attrs(attrs.get(CTRL_ATTR_MCAST_GROUPS, b"")):
            g = parse_attrs(grp)
            groups[g[CTRL_ATTR_MCAST_GRP_NAME].rstrip(b"\0").decode()] = u(g[CTRL_ATTR_MCAST_GRP_ID], "I")
        return family, groups


def decode_stats(payload):
    attrs = parse_attrs(payload)
    return {name: u(attrs[a], "Q") for a, name in STATS.items() if a in attrs}


def decode_config(payload):
    attrs = parse_attrs(payload)
    return {name: u(attrs[a], fmt) for a, (name, fmt) in CONFIG.items() if a in attrs}


def decode_alert(payload):
    a = parse_attrs(payload)
    return {
        "type": ALERT_TYPES.get(u(a[ATTR_ALERT_TYPE], "B"), "unknown"),
        "action": ALERT_ACTIONS.get(u(a[ATTR_ALERT_ACTION], "B"), "unknown"),
        "src_ip": addr_text(a[ATTR_ADDR]),
        "netns": u(a[ATTR_NETNS], "I"),
        "ports": u(a[ATTR_ALERT_PORTS], "I"),
        "attempts": u(a[ATTR_ALERT_ATTEMPTS], "I"),
        "timestamp": u(a[ATTR_TIMESTAMP], "Q"),
        **({"spoof_reason": SPOOF_REASONS.get(u(a[ATTR_SPOOF_REASON], "B"), "unknown"),
            "ifindex": u(a[ATTR_IFINDEX], "I")} if ATTR_SPOOF_REASON in a else {}),
    }


def decode_block(payload):
    a = parse_attrs(payload)
    expires_ms = u(a[ATTR_EXPIRES_MS], "Q")
    return {
        "address": addr_text(a[ATTR_ADDR]),
        "expires_in": round(expires_ms / 1000) if expires_ms else None,
        "reason": BLOCK_REASONS.get(u(a[ATTR_REASON], "B"), "unknown"),
    }


def decode_allowlist(payload):
    entries = []
    for nest in parse_attr_list(payload, ATTR_ALLOW_ENTRY):
        e = parse_attrs(nest)
        entries.append(f"{addr_text(e[ATTR_ADDR])}/{u(e[ATTR_PREFIX_LEN], 'B')}")
    return entries


def prefix_payload(text):
    net = ipaddress.ip_network(text, strict=False)
    return attr(ATTR_ADDR, net.network_address.packed) + attr(ATTR_PREFIX_LEN, struct.pack("B", net.prefixlen))


def show(values, as_json):
    if as_json:
        print(json.dumps(values))
    elif isinstance(values, dict):
        for key, value in values.items():
            print(f"{key:15} {value}")
    else:
        for value in values:
            print(value)


def parse_settings(pairs):
    payload = b""
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"expected key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        if key not in CONFIG_BY_NAME:
            raise SystemExit(f"unknown setting {key!r}; choose from {', '.join(CONFIG_BY_NAME)}")
        attr_id, fmt = CONFIG_BY_NAME[key]
        payload += attr(attr_id, struct.pack(fmt, int(value)))
    return payload


def main():
    parser = argparse.ArgumentParser(description="Control the KGuard kernel module")
    parser.add_argument("--json", action="store_true", help="print JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("stats", help="show counters")
    sub.add_parser("config", help="show configuration")
    p = sub.add_parser("set", help="change configuration (needs CAP_NET_ADMIN)")
    p.add_argument("settings", nargs="+", metavar="key=value")
    p = sub.add_parser("block", help="block an address (needs CAP_NET_ADMIN)")
    p.add_argument("address")
    p.add_argument("--timeout", type=int, default=0, help="seconds (default: until removed)")
    p = sub.add_parser("unblock", help="remove a block (needs CAP_NET_ADMIN)")
    p.add_argument("address")
    sub.add_parser("blocks", help="list blocked addresses")
    p = sub.add_parser("allow", help="never block an address or prefix (needs CAP_NET_ADMIN)")
    p.add_argument("prefix")
    p = sub.add_parser("disallow", help="remove an allowlist entry (needs CAP_NET_ADMIN)")
    p.add_argument("prefix")
    sub.add_parser("allowlist", help="list allowed prefixes")
    sub.add_parser("watch", help="print alerts and configuration changes as they happen")
    args = parser.parse_args()

    genl = GenlSocket()
    try:
        family, groups = genl.resolve(KGUARD_GENL_NAME)
    except OSError as e:
        raise SystemExit(f"KGuard Generic Netlink family not found ({e}); is the module loaded?")

    def call(cmd, payload=b"", dump=False):
        try:
            return genl.request(family, cmd, payload, KGUARD_GENL_VERSION, dump)
        except PermissionError:
            raise SystemExit("permission denied: this needs root (CAP_NET_ADMIN)")
        except OSError as e:
            if e.errno == 99:  # EADDRNOTAVAIL
                raise SystemExit("refused: that address is local or allowlisted, so it is never blocked")
            raise SystemExit(f"error: {e.strerror}")

    cmd = args.command
    if cmd == "stats":
        show(decode_stats(call(CMD_GET_STATS)), args.json)
    elif cmd == "config":
        show(decode_config(call(CMD_GET_CONFIG)), args.json)
    elif cmd == "set":
        show(decode_config(call(CMD_SET_CONFIG, parse_settings(args.settings))), args.json)
    elif cmd == "block":
        payload = attr(ATTR_ADDR, addr_bytes(args.address))
        if args.timeout:
            payload += attr(ATTR_TIMEOUT, struct.pack("I", args.timeout))
        call(CMD_BLOCK_ADD, payload)
    elif cmd == "unblock":
        call(CMD_BLOCK_DEL, attr(ATTR_ADDR, addr_bytes(args.address)))
    elif cmd == "blocks":
        blocks = [decode_block(m) for m in call(CMD_BLOCK_LIST, dump=True)]
        if args.json:
            print(json.dumps(blocks))
        else:
            for b in blocks:
                left = f"{b['expires_in']}s left" if b["expires_in"] else "permanent"
                print(f"{b['address']:40} {left:14} {b['reason']}")
    elif cmd == "allow":
        call(CMD_ALLOW_ADD, prefix_payload(args.prefix))
    elif cmd == "disallow":
        call(CMD_ALLOW_DEL, prefix_payload(args.prefix))
    elif cmd == "allowlist":
        show(decode_allowlist(call(CMD_ALLOW_LIST)), args.json)
    elif cmd == "watch":
        genl.sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, groups[KGUARD_GENL_MCGRP])
        print("watching alerts and configuration changes (Ctrl-C to stop)", file=sys.stderr)
        try:
            while True:
                data = genl.sock.recv(65536)
                off = 0
                while off + 20 <= len(data):
                    length = struct.unpack_from("I", data, off)[0]
                    msg_cmd, payload = data[off + 16], data[off + 20: off + length]
                    off += (length + 3) & ~3
                    if msg_cmd == CMD_CONFIG_CHANGED:
                        out = {"event": "config", **decode_config(payload)}
                    elif msg_cmd == CMD_ALERT:
                        out = {"event": "alert", **decode_alert(payload)}
                    else:
                        continue
                    if args.json:
                        print(json.dumps(out))
                    else:
                        print(" ".join(f"{k}={v}" for k, v in out.items()))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
