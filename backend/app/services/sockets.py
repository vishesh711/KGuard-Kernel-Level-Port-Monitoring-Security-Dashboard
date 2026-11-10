"""
Listening ports and connections with their processes (roadmap U7.2), like
`ss -tunap`, read from /proc/net/{tcp,tcp6,udp,udp6}.

Each socket's owner comes from scanning /proc/<pid>/fd for its inode, and
the user from its uid. This server is read live (in Docker that needs the
host's network and processes: network_mode and pid "host"); agents send the
same snapshot for their own hosts.

"Unexpected" listeners: the first snapshot from each host is taken as its
normal set (baseline). A listener that appears afterwards, i.e. a
(protocol, port, process) not seen in the baseline or marked known by an
admin, is flagged `new` until someone marks it known.
"""

import ipaddress
import os
import pwd
import struct
from typing import Any, Dict, List, Optional, Tuple

from .process_resolver import ProcessResolver

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
    "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}
MAX_CONNECTIONS = 2000


def decode_address(text: str) -> Tuple[str, int]:
    """'0100007F:1F90' -> ('127.0.0.1', 8080); IPv6 is four little-endian words"""
    addr_hex, port_hex = text.split(":")
    raw = bytes.fromhex(addr_hex)
    if len(raw) == 4:
        packed = raw[::-1]
    else:
        packed = b"".join(struct.pack(">I", struct.unpack("<I", raw[i:i + 4])[0]) for i in range(0, 16, 4))
    ip = ipaddress.ip_address(packed)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip), int(port_hex, 16)


def parse_table(text: str, proto: str) -> List[Dict[str, Any]]:
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local, lport = decode_address(fields[1])
            remote, rport = decode_address(fields[2])
        except (ValueError, struct.error):
            continue
        state_hex = fields[3].upper()
        if proto.startswith("tcp"):
            state = TCP_STATES.get(state_hex, state_hex)
        else:
            # UDP has no listen state: an unconnected bound socket receives from anyone
            state = "LISTEN" if rport == 0 else "CONNECTED"
        rows.append({"proto": proto.rstrip("6").upper(), "family": 6 if proto.endswith("6") else 4,
                     "local": local, "lport": lport, "remote": remote, "rport": rport, "state": state,
                     "uid": int(fields[7]), "inode": int(fields[9])})
    return rows


def user_name(uid: int, cache: Dict[int, str] = {}) -> str:  # noqa: B006 (deliberate cache)
    if uid not in cache:
        try:
            cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            cache[uid] = str(uid)
    return cache[uid]


def snapshot(proc_root: str = "/proc", resolver: Optional[ProcessResolver] = None) -> Dict[str, Any]:
    """Every listening socket, and established connections (capped), with process and user"""
    rows: List[Dict[str, Any]] = []
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(os.path.join(proc_root, "net", name)) as f:
                rows.extend(parse_table(f.read(), name))
        except OSError:
            continue
    resolver = resolver or ProcessResolver(proc_root, min_rescan_seconds=0)
    owners = resolver.lookup_many(r["inode"] for r in rows)
    listeners, connections = [], []
    for r in rows:
        pid, comm = owners.get(r["inode"], (None, None))
        item = {**r, "pid": pid, "process": comm, "user": user_name(r["uid"])}
        if r["state"] == "LISTEN":
            listeners.append(item)
        elif r["state"] not in ("CLOSE", "TIME_WAIT") and len(connections) < MAX_CONNECTIONS:
            connections.append(item)
    listeners.sort(key=lambda x: (x["proto"], x["lport"], x["local"]))
    connections.sort(key=lambda x: (x["state"] != "ESTABLISHED", x["proto"], x["lport"]))
    return {"listeners": listeners, "connections": connections}


def listener_key(item: Dict[str, Any]) -> Tuple[str, int, str]:
    return (item["proto"], int(item["lport"]), item.get("process") or "")
