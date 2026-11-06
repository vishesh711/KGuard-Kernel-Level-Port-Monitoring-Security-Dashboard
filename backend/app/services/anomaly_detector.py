"""
Anomaly Detection Service

Looks at network events as they are collected and raises security alerts.

Each incoming packet is classified as a scan probe or not (probes.py): SYN,
UDP, and the stealth probes FIN, NULL, Xmas, ACK and Maimon. Each source has
a sliding window of its recent probes, so activity spread across several
collection cycles is still seen as one pattern. Outgoing copies of packets
are ignored so local traffic is not counted twice.

Rules (all per host and source, with a cooldown so one attacker does not
flood the alert list):
- PORT_SCAN: at least `port_scan_threshold` distinct ports probed with one
  probe type within the window. The alert names the scan type. When this
  server's kernel module reports scans itself, SYN and UDP scans are left
  to it; stealth scans are always detected here (the kernel counts only
  SYN and UDP).
- HIGH_FREQUENCY: more than `high_frequency_threshold` connection attempts
  per minute (left to the kernel for this server when it detects).
- BRUTE_FORCE: at least `brute_force_threshold` new connections to one
  login/database port (`brute_force_ports`) within the window.
- SUSPICIOUS_PORT: a connection attempt to a port in `suspicious_ports`
  (skipped for sources already reported as scanners).
- SYN_FLOOD: at least `syn_flood_threshold` half-open connections (SYN seen,
  handshake never completed) to one destination within
  `syn_flood_window_seconds`, whatever their sources, so floods from random
  spoofed addresses are caught.

Sources in `trusted_sources` are never alerted on.
"""

import ipaddress
import logging
from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..config import settings
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from .probes import ACK, CONNECTION_PROBES, LABELS, SYN, classify_probe

logger = logging.getLogger(__name__)

TCP_SYN = SYN
TCP_ACK = ACK

# Most event IDs stored on one alert
MAX_RELATED_EVENT_IDS = 100
# Most half-open connections remembered per destination
MAX_PENDING_PER_DESTINATION = 200_000


@dataclass(frozen=True)
class Probe:
    """One probe remembered in a source's window"""
    time: float  # seconds since the Unix epoch
    kind: str  # see probes.py
    dst_ip: str
    dst_port: int
    event_id: Optional[int]


# Kept for callers that still say "Attempt"
Attempt = Probe


def is_incoming(event: NetworkEvent) -> bool:
    return getattr(event, "direction", None) != "out"


def probe_kind(event: NetworkEvent) -> Optional[str]:
    """Probe type of an incoming event, None for ordinary traffic"""
    if not is_incoming(event):
        return None
    return classify_probe(event.protocol, event.flags, getattr(event, "ct_state", None), event.dst_port)


def is_connection_attempt(event: NetworkEvent) -> bool:
    """True for an incoming TCP SYN without ACK, or any incoming UDP packet"""
    return probe_kind(event) in CONNECTION_PROBES


def source_key(src_ip: str, host_id: Optional[int]) -> str:
    """Per-host identity of a source: local events keep the bare IP"""
    return src_ip if host_id is None else f"{host_id}|{src_ip}"


def event_time(event: NetworkEvent) -> float:
    """Event time in seconds, from the kernel timestamp when available"""
    if event.timestamp:
        return event.timestamp / 1e9
    if event.created_at:
        return event.created_at.timestamp()
    return datetime.utcnow().timestamp()


def syn_cookies_enabled() -> Optional[int]:
    """This server's net.ipv4.tcp_syncookies (0 off, 1 when needed, 2 always)"""
    try:
        return int(Path("/proc/sys/net/ipv4/tcp_syncookies").read_text().strip())
    except (OSError, ValueError):
        return None


class FloodTracker:
    """Half-open TCP connections per destination (host, address, port)"""

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        # destination -> {(src_ip, src_port): time of SYN}, oldest first
        self.pending: Dict[tuple, "OrderedDict[tuple, float]"] = {}

    def syn(self, dest: tuple, src: tuple, t: float) -> None:
        pending = self.pending.setdefault(dest, OrderedDict())
        pending[src] = t
        pending.move_to_end(src)
        if len(pending) > MAX_PENDING_PER_DESTINATION:
            pending.popitem(last=False)

    def completed(self, dest: tuple, src: tuple) -> None:
        pending = self.pending.get(dest)
        if pending:
            pending.pop(src, None)

    def half_open(self, dest: tuple, now: float) -> Tuple[int, int]:
        """(half-open connections in the window, distinct sources among them)"""
        pending = self.pending.get(dest)
        if not pending:
            return 0, 0
        cutoff = now - self.window_seconds
        while pending and next(iter(pending.values())) < cutoff:
            pending.popitem(last=False)
        return len(pending), len({src for src, _port in pending})

    def forget_idle(self, now: float) -> None:
        idle = [d for d, p in self.pending.items() if not p or max(p.values()) < now - self.window_seconds]
        for dest in idle:
            del self.pending[dest]


class AnomalyDetectorService:
    """Detects suspicious network behaviour and stores security alerts"""

    def __init__(self):
        self.port_scan_threshold = settings.port_scan_threshold
        self.suspicious_ports = set(settings.suspicious_ports)
        self.high_frequency_threshold = settings.high_frequency_threshold
        self.brute_force_ports = set(settings.brute_force_ports)
        self.brute_force_threshold = settings.brute_force_threshold
        self.syn_flood_threshold = settings.syn_flood_threshold
        self.window_seconds = float(settings.detection_window_seconds)
        self.max_attempts_per_source = settings.max_attempts_per_source
        self.alert_cooldown = timedelta(seconds=settings.alert_cooldown_seconds)
        self.trusted_networks = [ipaddress.ip_network(n, strict=False) for n in settings.trusted_sources]
        # Kept for analyze_historical_patterns callers
        self.detection_window = timedelta(seconds=settings.detection_window_seconds)

        # Recent probes per (host, source)
        self.windows: Dict[str, Deque[Probe]] = {}
        self.floods = FloodTracker(float(settings.syn_flood_window_seconds))

        # True while this server's kernel module reports SYN/UDP scans and
        # SYN-rate abuse itself (see kernel_alerts.py)
        self.kernel_detection = False

        # Last alert time per rule and source, to rate-limit alerts
        self.recent_alerts: Dict[str, datetime] = {}

        self.stats = {
            "events_analyzed": 0,
            "connection_attempts": 0,
            "probes": 0,
            "alerts_generated": 0,
            "port_scans_detected": 0,
            "suspicious_ports_detected": 0,
            "high_frequency_detected": 0,
            "brute_force_detected": 0,
            "syn_floods_detected": 0,
            "last_analysis": None,
        }

    def reset(self) -> None:
        """Forget all remembered activity and cooldowns"""
        self.windows.clear()
        self.recent_alerts.clear()
        self.floods.pending.clear()

    def is_trusted(self, ip: str) -> bool:
        if not self.trusted_networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.trusted_networks)

    async def analyze_events(self, events: List[NetworkEvent]) -> List[SecurityAlert]:
        """
        Add a batch of stored events to the sliding windows and return
        the alerts this batch triggered. Alerts are saved to the database.
        """
        if not events:
            return []

        self.stats["events_analyzed"] += len(events)

        batch: Dict[str, List[Probe]] = defaultdict(list)
        sources: Dict[str, tuple] = {}
        flood_dests: Dict[tuple, Optional[int]] = {}
        latest = 0.0

        for event in events:
            if not is_incoming(event) or self.is_trusted(event.src_ip):
                continue
            host_id = getattr(event, "host_id", None)
            t = event_time(event)
            latest = max(latest, t)

            # Half-open tracking for SYN floods
            if event.protocol == "TCP":
                dest = (host_id, event.dst_ip, event.dst_port)
                src = (event.src_ip, event.src_port)
                flags = event.flags or 0
                if flags & SYN and not flags & ACK:
                    self.floods.syn(dest, src, t)
                    flood_dests[dest] = host_id
                elif flags & ACK:
                    self.floods.completed(dest, src)

            kind = probe_kind(event)
            if not kind:
                continue
            key = source_key(event.src_ip, host_id)
            sources[key] = (event.src_ip, host_id)
            probe = Probe(time=t, kind=kind, dst_ip=event.dst_ip, dst_port=event.dst_port, event_id=event.id)
            batch[key].append(probe)
            self._remember(key, probe)

        self.stats["probes"] += sum(len(p) for p in batch.values())
        self.stats["connection_attempts"] += sum(
            1 for probes in batch.values() for p in probes if p.kind in CONNECTION_PROBES
        )

        alerts: List[SecurityAlert] = []
        try:
            for key, new_probes in batch.items():
                window = self.windows.get(key)
                if not window:
                    continue
                src_ip, host_id = sources[key]
                kernel_covers = host_id is None and self.kernel_detection
                found: List[SecurityAlert] = []
                found.extend(self._check_port_scans(key, src_ip, window, kernel_covers))
                if not kernel_covers:
                    found.extend(self._check_high_frequency(key, src_ip, window))
                found.extend(self._check_brute_force(key, src_ip, window, new_probes))
                found.extend(self._check_suspicious_ports(key, src_ip, new_probes))
                for alert in found:
                    alert.host_id = host_id
                alerts.extend(found)

            for dest, host_id in flood_dests.items():
                alert = self._check_syn_flood(dest, latest)
                if alert:
                    alert.host_id = host_id
                    alerts.append(alert)
        except Exception as e:
            logger.error(f"Error during anomaly analysis: {e}", exc_info=True)

        stored = [alert for alert in alerts if self._store_alert(alert)]

        self.stats["alerts_generated"] += len(stored)
        self.stats["last_analysis"] = datetime.utcnow()
        if stored:
            logger.info(f"Analyzed {len(events)} events, generated {len(stored)} alerts")
        return stored

    def _remember(self, key: str, probe: Probe) -> None:
        """Add a probe to its source's window and drop expired ones"""
        window = self.windows.get(key)
        if window is None:
            window = deque(maxlen=self.max_attempts_per_source)
            self.windows[key] = window
        window.append(probe)

        cutoff = probe.time - self.window_seconds
        while window and window[0].time < cutoff:
            window.popleft()

    def _check_port_scans(self, key: str, src_ip: str, window: Deque[Probe],
                          kernel_covers: bool) -> List[SecurityAlert]:
        ports_by_kind: Dict[str, set] = defaultdict(set)
        for p in window:
            ports_by_kind[p.kind].add(p.dst_port)

        alerts = []
        for kind, ports in ports_by_kind.items():
            if len(ports) < self.port_scan_threshold:
                continue
            if kernel_covers and kind in CONNECTION_PROBES:
                continue  # this server's kernel reports SYN and UDP scans
            cooldown = f"port_scan_{key}_{kind}"
            if self._is_in_cooldown(cooldown):
                continue

            probes = [p for p in window if p.kind == kind]
            span = probes[-1].time - probes[0].time
            label = LABELS[kind]
            alert = SecurityAlert.create_port_scan_alert(
                src_ip=src_ip,
                event_count=len(probes),
                event_ids=self._event_ids(probes),
            )
            alert.title = f"{label} Scan Detected from {src_ip}"
            alert.description = (
                f"{src_ip} sent {label} probes to {len(ports)} different ports in {span:.1f} seconds "
                f"({len(probes)} probes), which looks like a{'n' if label[0] in 'AEFINSUX' else ''} "
                f"{label} port scan."
            )
            alert.dst_ip = probes[-1].dst_ip
            alert.alert_metadata = {
                **(alert.alert_metadata or {}),
                "scan_type": kind,
                "unique_ports": len(ports),
                "sample_ports": sorted(ports)[:50],
                "window_seconds": round(span, 3),
                "detection_method": "sliding_window_distinct_ports",
            }
            self._start_cooldown(cooldown)
            # Also silences per-port SUSPICIOUS_PORT alerts for this scanner
            self._start_cooldown(f"port_scan_{key}")
            self.stats["port_scans_detected"] += 1
            logger.warning(f"{label} scan detected from {src_ip}: {len(ports)} ports in {span:.1f}s")
            alerts.append(alert)
        return alerts

    def _check_high_frequency(self, key: str, src_ip: str, window: Deque[Probe]) -> List[SecurityAlert]:
        attempts = [p for p in window if p.kind in CONNECTION_PROBES]
        per_minute = len(attempts) * 60.0 / self.window_seconds
        if per_minute <= self.high_frequency_threshold:
            return []

        cooldown = f"high_freq_{key}"
        if self._is_in_cooldown(cooldown):
            return []

        span = attempts[-1].time - attempts[0].time
        severity = (
            AlertSeverity.HIGH
            if per_minute > self.high_frequency_threshold * 10
            else AlertSeverity.MEDIUM
        )
        alert = SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.HIGH_FREQUENCY,
            severity=severity,
            title=f"High Frequency Connections from {src_ip}",
            description=(
                f"{src_ip} made {len(attempts)} connection attempts in {span:.1f} seconds "
                f"(about {per_minute:.0f} per minute; limit {self.high_frequency_threshold})."
            ),
            src_ip=src_ip,
            dst_ip=attempts[-1].dst_ip,
            related_event_ids=self._event_ids(attempts),
            alert_metadata={
                "attempts_per_minute": round(per_minute, 1),
                "event_count": len(attempts),
                "window_seconds": round(span, 3),
                "detection_method": "sliding_window_rate",
            },
        )

        self._start_cooldown(cooldown)
        self.stats["high_frequency_detected"] += 1
        logger.warning(f"High frequency connections from {src_ip}: {per_minute:.0f}/min")
        return [alert]

    def _check_brute_force(self, key: str, src_ip: str, window: Deque[Probe],
                           new_probes: List[Probe]) -> List[SecurityAlert]:
        alerts = []
        ports = {p.dst_port for p in new_probes if p.kind == "syn" and p.dst_port in self.brute_force_ports}
        for port in ports:
            attempts = [p for p in window if p.kind == "syn" and p.dst_port == port]
            if len(attempts) < self.brute_force_threshold:
                continue
            cooldown = f"brute_force_{key}_{port}"
            if self._is_in_cooldown(cooldown):
                continue
            span = attempts[-1].time - attempts[0].time
            alerts.append(SecurityAlert(
                timestamp=datetime.utcnow(),
                alert_type=AlertType.BRUTE_FORCE,
                severity=AlertSeverity.HIGH,
                title=f"Possible Brute Force on Port {port} from {src_ip}",
                description=(
                    f"{src_ip} opened {len(attempts)} new connections to port {port} in {span:.1f} seconds, "
                    f"the pattern of repeated login attempts."
                ),
                src_ip=src_ip,
                dst_ip=attempts[-1].dst_ip,
                dst_port=port,
                related_event_ids=self._event_ids(attempts),
                alert_metadata={
                    "connections": len(attempts),
                    "window_seconds": round(span, 3),
                    "threshold": self.brute_force_threshold,
                    "detection_method": "repeated_connections_to_login_port",
                },
            ))
            self._start_cooldown(cooldown)
            self.stats["brute_force_detected"] += 1
            logger.warning(f"Possible brute force from {src_ip} on port {port}: {len(attempts)} connections")
        return alerts

    def _check_syn_flood(self, dest: tuple, now: float) -> Optional[SecurityAlert]:
        host_id, dst_ip, dst_port = dest
        half_open, sources = self.floods.half_open(dest, now)
        if half_open < self.syn_flood_threshold:
            return None
        cooldown = f"syn_flood_{host_id}|{dst_ip}|{dst_port}"
        if self._is_in_cooldown(cooldown):
            return None

        cookies = syn_cookies_enabled() if host_id is None else None
        cookie_text = {
            0: " SYN cookies are OFF on this server: enable net.ipv4.tcp_syncookies.",
            1: " SYN cookies are on (used when the backlog fills).",
            2: " SYN cookies are always on.",
        }.get(cookies, "")
        window = self.floods.window_seconds
        self._start_cooldown(cooldown)
        self.stats["syn_floods_detected"] += 1
        logger.warning(f"SYN flood against {dst_ip}:{dst_port}: {half_open} half-open from {sources} sources")
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.SYN_FLOOD,
            severity=AlertSeverity.CRITICAL if cookies == 0 else AlertSeverity.HIGH,
            title=f"SYN Flood Against {dst_ip}:{dst_port}",
            description=(
                f"{half_open} connections to {dst_ip}:{dst_port} were opened but never completed in the "
                f"last {window:.0f} seconds, from {sources} different source addresses.{cookie_text}"
            ),
            src_ip=None,
            dst_ip=dst_ip,
            dst_port=dst_port,
            alert_metadata={
                "half_open": half_open,
                "distinct_sources": sources,
                "window_seconds": window,
                "syn_cookies": cookies,
                "detection_method": "half_open_per_destination",
            },
        )

    def _check_suspicious_ports(self, key: str, src_ip: str, probes: List[Probe]) -> List[SecurityAlert]:
        # A known scanner touches many sensitive ports; the scan alert covers it
        if self._is_in_cooldown(f"port_scan_{key}"):
            return []

        alerts = []
        for probe in probes:
            if probe.kind not in CONNECTION_PROBES or probe.dst_port not in self.suspicious_ports:
                continue

            cooldown = f"suspicious_port_{key}_{probe.dst_port}"
            if self._is_in_cooldown(cooldown):
                continue

            alerts.append(
                SecurityAlert.create_suspicious_port_alert(
                    src_ip=src_ip,
                    dst_ip=probe.dst_ip,
                    dst_port=probe.dst_port,
                    event_ids=[probe.event_id] if probe.event_id is not None else [],
                )
            )
            self._start_cooldown(cooldown)
            self.stats["suspicious_ports_detected"] += 1
            logger.warning(f"Suspicious port access: {src_ip} -> {probe.dst_ip}:{probe.dst_port}")
        return alerts

    @staticmethod
    def _event_ids(probes) -> List[int]:
        """Most recent event IDs, capped"""
        ids = [p.event_id for p in probes if p.event_id is not None]
        return ids[-MAX_RELATED_EVENT_IDS:]

    def _is_in_cooldown(self, alert_key: str) -> bool:
        last_alert = self.recent_alerts.get(alert_key)
        if last_alert is None:
            return False
        return datetime.utcnow() - last_alert < self.alert_cooldown

    def _start_cooldown(self, alert_key: str) -> None:
        self.recent_alerts[alert_key] = datetime.utcnow()

    def _store_alert(self, alert: SecurityAlert) -> bool:
        """Save an alert. Returns True on success."""
        db = SessionLocal()
        try:
            db.add(alert)
            db.commit()
            db.refresh(alert)
            return True
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            db.rollback()
            return False
        finally:
            db.close()

    async def analyze_historical_patterns(self, hours: int = 24) -> Dict[str, Any]:
        """Summarise stored events from the last N hours"""
        db = SessionLocal()
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            events = db.query(NetworkEvent).filter(NetworkEvent.created_at >= cutoff_time).all()

            if not events:
                return {"error": "No events found in time range"}

            return {
                "time_range_hours": hours,
                "total_events": len(events),
                "unique_src_ips": len(set(e.src_ip for e in events)),
                "unique_dst_ips": len(set(e.dst_ip for e in events)),
                "protocol_distribution": dict(Counter(e.protocol for e in events)),
                "top_src_ips": self._get_top_ips([e.src_ip for e in events]),
                "top_dst_ports": self._get_top_ports([e.dst_port for e in events]),
                "suspicious_events": len([e for e in events if e.is_suspicious]),
                "hourly_distribution": self._get_hourly_distribution(events),
            }
        except Exception as e:
            logger.error(f"Error analyzing historical patterns: {e}")
            return {"error": str(e)}
        finally:
            db.close()

    def _get_top_ips(self, ips: List[str], limit: int = 10) -> List[Dict[str, Any]]:
        return [{"ip": ip, "count": count} for ip, count in Counter(ips).most_common(limit)]

    def _get_top_ports(self, ports: List[int], limit: int = 10) -> List[Dict[str, Any]]:
        return [{"port": port, "count": count} for port, count in Counter(ports).most_common(limit)]

    def _get_hourly_distribution(self, events: List[NetworkEvent]) -> List[Dict[str, Any]]:
        hourly_counts: Dict[int, int] = defaultdict(int)
        for event in events:
            hourly_counts[event.created_at.hour] += 1
        return [{"hour": hour, "count": count} for hour, count in sorted(hourly_counts.items())]

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            "port_scan_threshold": self.port_scan_threshold,
            "high_frequency_threshold": self.high_frequency_threshold,
            "detection_window_seconds": self.window_seconds,
            "suspicious_ports_count": len(self.suspicious_ports),
            "alert_cooldown_seconds": self.alert_cooldown.total_seconds(),
            "active_cooldowns": len(self.recent_alerts),
            "tracked_sources": len(self.windows),
            "tracked_flood_destinations": len(self.floods.pending),
            "brute_force_threshold": self.brute_force_threshold,
            "syn_flood_threshold": self.syn_flood_threshold,
            "trusted_sources": [str(n) for n in self.trusted_networks],
            "kernel_detection": self.kernel_detection,
        }

    def cleanup_old_cooldowns(self) -> None:
        """Drop expired cooldowns and sources with no recent activity"""
        now = datetime.utcnow()
        expired_keys = [
            key for key, timestamp in self.recent_alerts.items()
            if now - timestamp > self.alert_cooldown
        ]
        for key in expired_keys:
            del self.recent_alerts[key]

        cutoff = now.timestamp() - self.window_seconds
        idle_sources = [
            src for src, window in self.windows.items()
            if not window or window[-1].time < cutoff
        ]
        for src in idle_sources:
            del self.windows[src]
        self.floods.forget_idle(now.timestamp())

        if expired_keys or idle_sources:
            logger.debug(
                f"Cleaned up {len(expired_keys)} cooldowns and {len(idle_sources)} idle sources"
            )


# Global instance
anomaly_detector = AnomalyDetectorService()
