"""
Passive TCP fingerprinting (p0f-style).

A SYN packet carries choices each TCP/IP stack makes in its own way: the
initial TTL, the window size, the MSS and window-scale options and, most of
all, the order of the TCP options. Matching them against known signatures
names the sender's operating system, or the scanning tool that crafted it,
without sending it anything.

The initial TTL is the smallest of 32, 64, 128 and 255 at or above the
observed TTL; the difference is the number of router hops on the way.

Signatures (option letters: M=MSS, N=NOP, W=window scale, S=SACK permitted,
T=timestamps, E=end of list):

    Linux 3.x+, Android    ttl 64   M,S,T,N,W           (M,N,N,S,N,W without timestamps)
    Windows 7-11           ttl 128  M,N,W,N,N,S         (M,N,W,S,T on servers with timestamps)
    macOS, iOS             ttl 64   M,N,W,N,N,T,S,E
    FreeBSD                ttl 64   M,N,W,S,T
    OpenBSD                ttl 64   M,N,N,S,N,W,N,N

Crafted SYNs from scanners are recognisable too: nmap's SYN scan sends only
an MSS option with a window of 1024-4096, masscan and zmap send no options
at all (window 1024 and 65535), and other raw-packet tools (hping3, scapy)
usually send no options either.
"""

from dataclasses import dataclass
from typing import Optional

INITIAL_TTLS = (32, 64, 128, 255)

# (name, initial TTL, option order)
OS_SIGNATURES = (
    ("Linux", 64, "M,S,T,N,W"),
    ("Linux", 64, "M,N,N,S,N,W"),
    ("Linux", 64, "M,S,N,W"),
    ("Windows", 128, "M,N,W,N,N,S"),
    ("Windows", 128, "M,N,W,S,T"),
    ("Windows", 128, "M,N,N,S"),
    ("macOS", 64, "M,N,W,N,N,T,S,E"),
    ("FreeBSD", 64, "M,N,W,S,T"),
    ("OpenBSD", 64, "M,N,N,S,N,W,N,N"),
)

# Names given to crafted packets
TOOLS = {"nmap", "masscan", "zmap", "crafted"}


@dataclass(frozen=True)
class Fingerprint:
    name: str  # OS or tool, "unknown" when nothing matches
    initial_ttl: int
    hops: int
    signature: str  # ttl:window:mss:wscale:options:df, for unknown stacks
    exact: bool  # option order and initial TTL both matched

    @property
    def is_tool(self) -> bool:
        return self.name in TOOLS


def initial_ttl(ttl: int) -> int:
    return next((t for t in INITIAL_TTLS if ttl <= t), 255)


def fingerprint_syn(ttl: int, window: Optional[int], mss: Optional[int], wscale: Optional[int],
                    options: str, df: Optional[bool] = None) -> Fingerprint:
    """Guess who sent a SYN from its header fields"""
    init = initial_ttl(ttl)
    signature = (f"{init}:{window if window is not None else '*'}:{mss or '*'}:"
                 f"{wscale if wscale is not None else '*'}:{options or '-'}:{'df' if df else 'nodf'}")

    def result(name: str, exact: bool = True) -> Fingerprint:
        return Fingerprint(name=name, initial_ttl=init, hops=init - ttl, signature=signature, exact=exact)

    # Scanners first: their packets are built by hand, not by a kernel
    if options == "M" and window in (1024, 2048, 3072, 4096):
        return result("nmap")
    if not options:
        if window == 1024:
            return result("masscan")
        if window == 65535:
            return result("zmap")
        return result("crafted")

    for name, sig_ttl, sig_options in OS_SIGNATURES:
        if options == sig_options and init == sig_ttl:
            return result(name)
    # Right option order but an odd TTL (changed sysctl, or a middlebox)
    for name, _sig_ttl, sig_options in OS_SIGNATURES:
        if options == sig_options:
            return result(name, exact=False)
    return result("unknown", exact=False)
