"""
Reflection and amplification attacks (AMPLIFICATION).

An attacker sends small UDP requests to public services (DNS, NTP,
memcached, SSDP, ...) with the victim's address as the source. The services
send their much larger replies to the victim. Two views:

Victim. Large UDP packets (at least `amplification_min_bytes`) from a
reflector port that this host never asked for: conntrack calls them "new"
(a reply to our own query would be "established"), or, without conntrack
(eBPF agents), no query to that server and port was seen going out. At
least `amplification_threshold` of them to one destination within
`amplification_window_seconds` raise an alert.

Reflector. This host's own UDP service answering one client with at least
`reflector_ratio` times the bytes it received, and at least
`reflector_min_bytes`, within the window: the "client" is probably a
spoofed victim, and this host is helping attack it.
"""

import logging
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Deque, Dict, List, Optional

from ..config import settings
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert

if TYPE_CHECKING:
    from .anomaly_detector import AnomalyDetectorService

logger = logging.getLogger(__name__)

# UDP services abused for reflection, with their typical amplification factor
REFLECTOR_SERVICES = {
    17: ("QOTD", 140),
    19: ("chargen", 360),
    53: ("DNS", 54),
    111: ("portmap", 28),
    123: ("NTP", 556),
    161: ("SNMP", 6),
    389: ("CLDAP", 70),
    1900: ("SSDP", 30),
    3702: ("WS-Discovery", 150),
    11211: ("memcached", 50000),
}

MAX_TRACKED = 50_000
MAX_PACKETS_PER_VICTIM = 100_000
MAX_RELATED_EVENT_IDS = 100
QUERY_MEMORY_SECONDS = 30.0


class AmplificationDetector:
    def __init__(self, detector: "AnomalyDetectorService"):
        self.detector = detector
        self.min_bytes = settings.amplification_min_bytes
        self.threshold = settings.amplification_threshold
        self.window = float(settings.amplification_window_seconds)
        self.ratio = settings.reflector_ratio
        self.reflector_min_bytes = settings.reflector_min_bytes
        # (host, victim ip, service port) -> [(time, reflector ip, bytes, event id)]
        self.replies: Dict[tuple, Deque[tuple]] = {}
        # (host, server ip, server port) -> time of our last query
        self.queries: Dict[tuple, float] = {}
        # (host, client ip, service port) -> [window start, request bytes, reply bytes, requests, replies]
        self.served: Dict[tuple, list] = {}

    def reset(self) -> None:
        self.replies.clear()
        self.queries.clear()
        self.served.clear()

    def check(self, events) -> List[SecurityAlert]:
        victims = set()
        clients = set()
        latest = 0.0
        for event in events:
            if event.protocol != "UDP" or self.detector.is_trusted(event.src_ip):
                continue
            host_id = getattr(event, "host_id", None)
            size = getattr(event, "ip_len", None)
            t = self.detector.event_time(event)
            latest = max(latest, t)
            outgoing = getattr(event, "direction", None) == "out"

            if outgoing:
                if event.dst_port in REFLECTOR_SERVICES:
                    self.queries[(host_id, event.dst_ip, event.dst_port)] = t
                if event.src_port in REFLECTOR_SERVICES and size:
                    entry = self._served(host_id, event.dst_ip, event.src_port, t)
                    entry[2] += size
                    entry[4] += 1
                    clients.add((host_id, event.dst_ip, event.src_port))
                continue

            if event.dst_port in REFLECTOR_SERVICES and size:
                entry = self._served(host_id, event.src_ip, event.dst_port, t)
                entry[1] += size
                entry[3] += 1
            if event.src_port in REFLECTOR_SERVICES and size and size >= self.min_bytes \
                    and self._unsolicited(event, host_id, t):
                key = (host_id, event.dst_ip, event.src_port)
                replies = self.replies.setdefault(key, deque(maxlen=MAX_PACKETS_PER_VICTIM))
                replies.append((t, event.src_ip, size, event.id))
                victims.add(key)

        alerts = []
        for key in victims:
            alert = self._victim_alert(key)
            if alert:
                alerts.append(alert)
        for key in clients:
            alert = self._reflector_alert(key)
            if alert:
                alerts.append(alert)
        self._forget(latest)
        return alerts

    def _served(self, host_id, client, port, t) -> list:
        key = (host_id, client, port)
        entry = self.served.get(key)
        if entry is None or t - entry[0] > self.window:
            entry = [t, 0, 0, 0, 0]
            self.served[key] = entry
        return entry

    def _unsolicited(self, event, host_id, t) -> bool:
        ct = getattr(event, "ct_state", None)
        if ct in ("established", "related"):
            return False
        if ct in ("new", "invalid"):
            return True
        asked = self.queries.get((host_id, event.src_ip, event.src_port))
        return asked is None or t - asked > QUERY_MEMORY_SECONDS

    def _victim_alert(self, key) -> Optional[SecurityAlert]:
        replies = self.replies[key]
        cutoff = replies[-1][0] - self.window
        while replies and replies[0][0] < cutoff:
            replies.popleft()
        if len(replies) < self.threshold:
            return None
        host_id, victim, port = key
        cooldown = f"amplification_{host_id}|{victim}|{port}"
        if self.detector._is_in_cooldown(cooldown):
            return None
        self.detector._start_cooldown(cooldown)
        self.detector.stats["amplification_detected"] += 1

        service = REFLECTOR_SERVICES[port][0]
        reflectors = len({r[1] for r in replies})
        total = sum(r[2] for r in replies)
        span = max(replies[-1][0] - replies[0][0], 0.001)
        mbps = total * 8 / span / 1e6
        logger.warning(f"{service} amplification against {victim}: "
                       f"{len(replies)} replies from {reflectors} reflectors")
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.AMPLIFICATION,
            severity=AlertSeverity.CRITICAL if mbps >= 100 else AlertSeverity.HIGH,
            title=f"{service} Amplification Attack Against {victim}",
            description=(
                f"{victim} received {len(replies)} {service} replies ({total / 1024:.0f} KiB, "
                f"{mbps:.1f} Mbit/s) from {reflectors} server(s) in {span:.1f} seconds without asking "
                f"for them. Someone is sending requests with {victim} as the forged source so the "
                f"servers' larger replies flood it (reflection attack)."
            ),
            src_ip=replies[-1][1] if reflectors == 1 else None,
            dst_ip=victim,
            host_id=host_id,
            related_event_ids=[r[3] for r in replies if r[3] is not None][-MAX_RELATED_EVENT_IDS:],
            alert_metadata={
                "role": "victim",
                "service": service,
                "source_port": port,
                "replies": len(replies),
                "bytes": total,
                "mbit_per_second": round(mbps, 2),
                "reflectors": reflectors,
                "sample_reflectors": sorted({r[1] for r in replies})[:20],
                "window_seconds": self.window,
                "detection_method": "unsolicited_udp_replies",
            },
        )

    def _reflector_alert(self, key) -> Optional[SecurityAlert]:
        start, req_bytes, reply_bytes, requests, replies = self.served[key]
        if reply_bytes < self.reflector_min_bytes or reply_bytes < self.ratio * max(req_bytes, 1):
            return None
        host_id, client, port = key
        cooldown = f"reflector_{host_id}|{client}|{port}"
        if self.detector._is_in_cooldown(cooldown):
            return None
        self.detector._start_cooldown(cooldown)
        self.detector.stats["amplification_detected"] += 1

        service = REFLECTOR_SERVICES[port][0]
        factor = reply_bytes / max(req_bytes, 1)
        logger.warning(f"This host is a {service} reflector against {client}: {factor:.0f}x")
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.AMPLIFICATION,
            severity=AlertSeverity.HIGH,
            title=f"Host Used as {service} Reflector Against {client}",
            description=(
                f"This host's {service} service (port {port}) sent {client} {reply_bytes / 1024:.0f} KiB "
                f"in reply to {req_bytes} bytes of requests ({factor:.0f}× amplification, {requests} "
                f"requests). {client} is probably the victim of a reflection attack using forged "
                f"requests; restrict the service (e.g. disable NTP monlist, DNS recursion for "
                f"outsiders, or memcached UDP)."
            ),
            src_ip=client,
            dst_port=port,
            host_id=host_id,
            alert_metadata={
                "role": "reflector",
                "service": service,
                "request_bytes": req_bytes,
                "reply_bytes": reply_bytes,
                "requests": requests,
                "replies": replies,
                "amplification": round(factor, 1),
                "window_seconds": self.window,
                "detection_method": "reply_to_request_ratio",
            },
        )

    def _forget(self, now: float) -> None:
        if len(self.queries) > MAX_TRACKED:
            for key in [k for k, t in self.queries.items() if now - t > QUERY_MEMORY_SECONDS]:
                del self.queries[key]
        if len(self.served) > MAX_TRACKED:
            for key in [k for k, e in self.served.items() if now - e[0] > self.window]:
                del self.served[key]
        if len(self.replies) > MAX_TRACKED:
            for key in [k for k, r in self.replies.items() if not r or now - r[-1][0] > self.window]:
                del self.replies[key]
