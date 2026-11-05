#!/usr/bin/env python3
"""
kguardctl - control the KGuard kernel module over Generic Netlink.

Uses only the Python standard library: it speaks raw Generic Netlink
(resolving the "kguard" family through the nlctrl controller).

  kguardctl stats                      counters
  kguardctl config                     current configuration
  kguardctl set capture_out=0 wakeup_events=128   change configuration (root)
  kguardctl watch                      print configuration changes as they happen

Add --json for machine-readable output.
"""

import argparse
import json
import os
import socket
import struct
import sys

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
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

# Mirrors include/uapi/linux/kguard.h
KGUARD_GENL_NAME = "kguard"
KGUARD_GENL_VERSION = 1
KGUARD_GENL_MCGRP = "events"

CMD_GET_STATS = 1
CMD_GET_CONFIG = 2
CMD_SET_CONFIG = 3
CMD_CONFIG_CHANGED = 4

STATS = {
    1: "packets",
    2: "events",
    3: "dropped",
    4: "filtered",
    5: "ns_per_packet",
    6: "ring_fill",
    7: "netns",
}
CONFIG = {  # attribute id: (name, struct format)
    9: ("capture_in", "B"),
    10: ("capture_out", "B"),
    11: ("capture_fwd", "B"),
    12: ("capture_ipv6", "B"),
    13: ("socket_lookup", "B"),
    14: ("wakeup_events", "I"),
}
CONFIG_BY_NAME = {name: (attr, fmt) for attr, (name, fmt) in CONFIG.items()}


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
        attrs[atype & 0x3FFF] = data[off + 4: off + length]
        off += (length + 3) & ~3
    return attrs


class GenlSocket:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.seq = 0

    def request(self, family, cmd, payload=b"", version=1):
        """Send one request and return the attributes of its reply"""
        self.seq += 1
        body = struct.pack("BBH", cmd, version, 0) + payload
        header = struct.pack("IHHII", 16 + len(body), family, NLM_F_REQUEST | NLM_F_ACK, self.seq, 0)
        self.sock.send(header + body)

        reply = None
        while True:
            data = self.sock.recv(65536)
            off = 0
            while off + 16 <= len(data):
                length, mtype, _flags, seq, _pid = struct.unpack_from("IHHII", data, off)
                msg = data[off + 16: off + length]
                off += (length + 3) & ~3
                if seq != self.seq:
                    continue
                if mtype == NLMSG_ERROR:
                    (error,) = struct.unpack_from("i", msg)
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    return reply  # ACK ends the exchange
                reply = parse_attrs(msg[4:])

    def resolve(self, name):
        """Return (family id, {multicast group name: id})"""
        attrs = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attr(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\0"))
        family = struct.unpack("H", attrs[CTRL_ATTR_FAMILY_ID][:2])[0]
        groups = {}
        for grp in parse_attrs(attrs.get(CTRL_ATTR_MCAST_GROUPS, b"")).values():
            g = parse_attrs(grp)
            groups[g[CTRL_ATTR_MCAST_GRP_NAME].rstrip(b"\0").decode()] = struct.unpack(
                "I", g[CTRL_ATTR_MCAST_GRP_ID]
            )[0]
        return family, groups


def decode_stats(attrs):
    return {name: struct.unpack("Q", attrs[a])[0] for a, name in STATS.items() if a in attrs}


def decode_config(attrs):
    out = {}
    for a, (name, fmt) in CONFIG.items():
        if a in attrs:
            out[name] = struct.unpack(fmt, attrs[a][: struct.calcsize(fmt)])[0]
    return out


def show(values, as_json):
    if as_json:
        print(json.dumps(values))
    else:
        for key, value in values.items():
            print(f"{key:15} {value}")


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
    set_parser = sub.add_parser("set", help="change configuration (needs CAP_NET_ADMIN)")
    set_parser.add_argument("settings", nargs="+", metavar="key=value")
    sub.add_parser("watch", help="print configuration changes")
    args = parser.parse_args()

    genl = GenlSocket()
    try:
        family, groups = genl.resolve(KGUARD_GENL_NAME)
    except OSError as e:
        raise SystemExit(f"KGuard Generic Netlink family not found ({e}); is the module loaded?")

    if args.command == "stats":
        show(decode_stats(genl.request(family, CMD_GET_STATS, version=KGUARD_GENL_VERSION)), args.json)
    elif args.command == "config":
        show(decode_config(genl.request(family, CMD_GET_CONFIG, version=KGUARD_GENL_VERSION)), args.json)
    elif args.command == "set":
        try:
            reply = genl.request(family, CMD_SET_CONFIG, parse_settings(args.settings), KGUARD_GENL_VERSION)
        except PermissionError:
            raise SystemExit("permission denied: changing configuration needs root (CAP_NET_ADMIN)")
        show(decode_config(reply), args.json)
    elif args.command == "watch":
        genl.sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, groups[KGUARD_GENL_MCGRP])
        print("watching for configuration changes (Ctrl-C to stop)", file=sys.stderr)
        try:
            while True:
                data = genl.sock.recv(65536)
                cmd = data[16]
                if cmd == CMD_CONFIG_CHANGED:
                    show(decode_config(parse_attrs(data[20:])), args.json)
                    sys.stdout.flush()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
