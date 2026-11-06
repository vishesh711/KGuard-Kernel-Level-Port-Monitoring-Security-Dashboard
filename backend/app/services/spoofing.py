"""
Spoofed-traffic detection (SPOOFED_TRAFFIC).

Two signs that packets do not come from the address they claim:

TTL jumps. Every packet from one host travels roughly the same path, so its
hop count (initial TTL minus the TTL that arrives) stays within a hop or two.
Packets forged by someone else, somewhere else, arrive with a different hop
count. When at least `ttl_jump_packets` packets from one source differ from
that source's usual hop count by `ttl_jump_hops` or more, within the
detection window, the source is reported. Only packets with the same
initial TTL are compared: a NAT gateway with Windows (128) and Linux (64)
machines behind it is normal. Scanners such as nmap choose their own TTLs
for the packets they craft, so SYNs with a scanning tool's fingerprint are
not compared, and sources already reported as scanners are not reported
again here.

Bogon sources. Some addresses are never legitimate sources on a network:
documentation (TEST-NET) and benchmarking ranges, reserved space, and the
loopback, multicast, broadcast and "this network" addresses. This server's
kernel module already reports the last four itself (as KGUARD_ALERT_SPOOF,
together with packets claiming this host's own addresses), so for this
server they are left to it; for agents they are reported here. Private
(RFC 1918) and link-local addresses are normal on a LAN and not flagged.
Floods from random sources hit bogon ranges constantly (1 in 16 random IPv4
addresses is in 240.0.0.0/4), so there is one alert per host and category,
not per address.
"""

import ipaddress
import logging
from collections import Counter, OrderedDict, deque
from datetime import datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Deque, Dict, List, Optional, Tuple

from ..config import settings
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from .fingerprint import TOOLS, initial_ttl

if TYPE_CHECKING:
    from .anomaly_detector import AnomalyDetectorService

logger = logging.getLogger(__name__)

MAX_TRACKED_SOURCES = 50_000
MAX_SAMPLES_PER_SOURCE = 256
MAX_RELATED_EVENT_IDS = 100

_net = ipaddress.ip_network
BOGONS = (
    (_net("0.0.0.0/8"), "unspecified"),
    (_net("127.0.0.0/8"), "loopback"),
    (_net("192.0.0.0/24"), "reserved"),
    (_net("192.0.2.0/24"), "documentation"),
    (_net("198.18.0.0/15"), "benchmarking"),
    (_net("198.51.100.0/24"), "documentation"),
    (_net("203.0.113.0/24"), "documentation"),
    (_net("224.0.0.0/4"), "multicast"),
    (_net("255.255.255.255/32"), "broadcast"),
    (_net("240.0.0.0/4"), "reserved"),
    (_net("::/128"), "unspecified"),
    (_net("::1/128"), "loopback"),
    (_net("::ffff:0:0/96"), "ipv4-mapped"),
    (_net("100::/64"), "discard"),
    (_net("2001:db8::/32"), "documentation"),
    (_net("3fff::/20"), "documentation"),
    (_net("ff00::/8"), "multicast"),
)
# Categories this server's kernel module reports itself
KERNEL_CATEGORIES = {"unspecified", "loopback", "multicast", "broadcast"}

CATEGORY_TEXT = {
    "unspecified": "the unspecified \"this network\" range",
    "loopback": "a loopback address, which never leaves a host",
    "reserved": "reserved address space",
    "documentation": "a documentation (TEST-NET) range",
    "benchmarking": "the benchmarking range (198.18.0.0/15)",
    "multicast": "a multicast address, which cannot send",
    "broadcast": "the broadcast address",
    "ipv4-mapped": "an IPv4-mapped IPv6 address, which never appears on the wire",
    "discard": "the IPv6 discard prefix",
}


# First octets of the IPv4 bogon ranges above: a quick test that skips
# address parsing for almost every source (this runs for every packet)
BOGON_FIRST_OCTETS = {"0", "127", "192", "198", "203"} | {str(n) for n in range(224, 256)}


def bogon_category(ip: str) -> Optional[str]:
    if ":" not in ip and ip.partition(".")[0] not in BOGON_FIRST_OCTETS:
        return None
    return _bogon_category(ip)


@lru_cache(maxsize=4096)
def _bogon_category(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, category in BOGONS:
        if addr.version == net.version and addr in net:
            return category
    return None


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class SpoofingDetector:
    def __init__(self, detector: "AnomalyDetectorService"):
        self.detector = detector
        self.jump_hops = settings.ttl_jump_hops
        self.jump_packets = settings.ttl_jump_packets
        self.check_bogons = settings.bogon_detection
        # (host_id, src_ip) -> [(time, initial TTL, hops, event id)], oldest first
        self.samples: "OrderedDict[Tuple[Optional[int], str], Deque[tuple]]" = OrderedDict()

    def reset(self) -> None:
        self.samples.clear()

    def check(self, events, kernel_detection: bool) -> List[SecurityAlert]:
        touched = set()
        bogons: Dict[tuple, list] = {}
        for event in events:
            if getattr(event, "direction", None) == "out" or self.detector.is_trusted(event.src_ip):
                continue
            host_id = getattr(event, "host_id", None)

            category = bogon_category(event.src_ip) if self.check_bogons else None
            # Loopback to loopback is a host talking to itself
            if category == "loopback" and is_loopback(event.dst_ip):
                category = None
            if category and not (host_id is None and kernel_detection and category in KERNEL_CATEGORIES):
                bogons.setdefault((host_id, category), []).append(event)

            ttl = getattr(event, "ttl", None)
            crafted = getattr(event, "os_guess", None) in TOOLS
            if ttl and event.protocol in ("TCP", "UDP") and not category and not crafted:
                self._remember(host_id, event, ttl)
                touched.add((host_id, event.src_ip))

        alerts = []
        for (host_id, category), found in bogons.items():
            alert = self._bogon_alert(host_id, category, found)
            if alert:
                alerts.append(alert)
        for key in touched:
            alert = self._ttl_alert(key)
            if alert:
                alerts.append(alert)
        return alerts

    def _remember(self, host_id: Optional[int], event, ttl: int) -> None:
        key = (host_id, event.src_ip)
        samples = self.samples.get(key)
        if samples is None:
            samples = deque(maxlen=MAX_SAMPLES_PER_SOURCE)
            self.samples[key] = samples
            if len(self.samples) > MAX_TRACKED_SOURCES:
                self.samples.popitem(last=False)
        else:
            self.samples.move_to_end(key)
        init = initial_ttl(ttl)
        t = self.detector.event_time(event)
        samples.append((t, init, init - ttl, event.id))
        cutoff = t - self.detector.window_seconds
        while samples and samples[0][0] < cutoff:
            samples.popleft()

    def _ttl_alert(self, key) -> Optional[SecurityAlert]:
        samples = self.samples.get(key)
        if not samples or len(samples) <= self.jump_packets:
            return None
        (usual_init, usual_hops), usual_count = Counter((s[1], s[2]) for s in samples).most_common(1)[0]
        odd = [s for s in samples if s[1] == usual_init and abs(s[2] - usual_hops) >= self.jump_hops]
        if len(odd) < self.jump_packets:
            return None
        host_id, src_ip = key
        cooldown = f"spoof_ttl_{host_id}|{src_ip}"
        scanner = f"port_scan_{src_ip if host_id is None else f'{host_id}|{src_ip}'}"
        if self.detector._is_in_cooldown(cooldown) or self.detector._is_in_cooldown(scanner):
            return None
        self.detector._start_cooldown(cooldown)
        self.detector.stats["spoofing_detected"] += 1

        odd_hops = sorted({s[2] for s in odd})
        logger.warning(f"TTL jumps from {src_ip}: usually {usual_hops} hops, also {odd_hops}")
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.SPOOFED_TRAFFIC,
            severity=AlertSeverity.HIGH,
            title=f"Spoofed Packets Claiming {src_ip}",
            description=(
                f"Packets from {src_ip} normally arrive after {usual_hops} router hops "
                f"({usual_count} packets), but {len(odd)} arrived after "
                f"{', '.join(map(str, odd_hops))} hops. "
                f"A host's packets follow one path, so these were probably forged by someone "
                f"else using {src_ip} as the source address."
            ),
            src_ip=src_ip,
            host_id=host_id,
            related_event_ids=[s[3] for s in odd if s[3] is not None][-MAX_RELATED_EVENT_IDS:],
            alert_metadata={
                "spoof_reason": "ttl_jump",
                "usual_hops": usual_hops,
                "usual_packets": usual_count,
                "initial_ttl": usual_init,
                "odd_hops": odd_hops,
                "odd_packets": len(odd),
                "detection_method": "ttl_consistency",
            },
        )

    def _bogon_alert(self, host_id, category, events) -> Optional[SecurityAlert]:
        cooldown = f"spoof_bogon_{host_id}|{category}"
        if self.detector._is_in_cooldown(cooldown):
            return None
        self.detector._start_cooldown(cooldown)
        self.detector.stats["spoofing_detected"] += 1
        sources = sorted({e.src_ip for e in events})
        last = events[-1]
        claimed = sources[0] if len(sources) == 1 else f"{len(sources)} addresses such as {sources[0]}"
        logger.warning(f"Bogon sources ({category}): {claimed} -> {last.dst_ip}")
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.SPOOFED_TRAFFIC,
            severity=AlertSeverity.MEDIUM,
            title=(f"Impossible Source Address {sources[0]}" if len(sources) == 1
                   else f"Impossible Source Addresses ({len(sources)} {category})"),
            description=(
                f"{len(events)} packet(s) arrived claiming to come from {claimed}, in "
                f"{CATEGORY_TEXT.get(category, category)}. No real host sends from there, so the "
                f"source addresses were forged."
            ),
            src_ip=sources[0] if len(sources) == 1 else None,
            dst_ip=last.dst_ip,
            dst_port=last.dst_port or None,
            host_id=host_id,
            related_event_ids=[e.id for e in events if e.id is not None][-MAX_RELATED_EVENT_IDS:],
            alert_metadata={
                "spoof_reason": "bogon",
                "bogon_category": category,
                "packets": len(events),
                "distinct_sources": len(sources),
                "sample_sources": sources[:20],
                "detection_method": "bogon_source",
            },
        )
