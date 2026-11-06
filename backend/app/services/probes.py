"""
Classify incoming packets as scan probes.

Based on what each nmap scan type looks like in KGuard events (observed on
Linux 6.8 with conntrack):

    scan   probe                 conntrack state
    -sS    SYN                   new
    -sF    FIN                   invalid
    -sN    no flags              invalid
    -sX    FIN+PSH+URG           invalid
    -sA    ACK                   new (picked up mid-stream)
    -sM    FIN+ACK               invalid
    -sU    UDP                   new (closed ports answer with ICMP)

FIN, NULL and Xmas packets never occur in normal TCP. ACK and FIN+ACK do,
so they only count as probes when they do not belong to a known
connection: conntrack says new/invalid, or, when there is no conntrack
(eBPF engine), when they target a non-ephemeral port (below 32768), as
replies to this host's own connections go to its ephemeral ports.
"""

from typing import Optional

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

# Linux's default ephemeral range starts at 32768
EPHEMERAL_START = 32768

LABELS = {
    "syn": "SYN",
    "udp": "UDP",
    "fin": "FIN",
    "null": "NULL",
    "xmas": "Xmas",
    "ack": "ACK",
    "maimon": "Maimon",
}

# Probes that open (or try to open) a connection
CONNECTION_PROBES = {"syn", "udp"}


def classify_probe(protocol: str, flags: Optional[int], ct_state: Optional[str],
                   dst_port: Optional[int]) -> Optional[str]:
    """Probe type of an incoming packet, or None for ordinary traffic"""
    if protocol == "UDP":
        return "udp"
    if protocol != "TCP":
        return None

    f = flags or 0
    if f & RST:
        return None
    if f & SYN:
        return "syn" if not f & ACK else None  # SYN-ACK is a reply
    if f == 0:
        return "null"
    if f == FIN:
        return "fin"
    if f & FIN and f & PSH and f & URG and not f & ACK:
        return "xmas"

    unknown_connection = ct_state in ("new", "invalid") or (
        ct_state in (None, "none") and (dst_port or 0) < EPHEMERAL_START
    )
    if f == ACK and unknown_connection:
        return "ack"
    if f == FIN | ACK and unknown_connection:
        return "maimon"
    return None
