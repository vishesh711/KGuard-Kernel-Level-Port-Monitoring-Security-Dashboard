"""
Anomaly Detection Service

Looks at network events as they are collected and raises security alerts.

Detection works on connection attempts only (TCP SYN without ACK, and UDP
packets), not on every packet, so that ordinary traffic such as a large
download does not look like an attack. Each source IP has a sliding window
of its recent attempts, so activity spread across several collection cycles
is still seen as one pattern.

Rules:
- PORT_SCAN: a source tries at least `port_scan_threshold` distinct ports
  within the window.
- HIGH_FREQUENCY: a source makes more than `high_frequency_threshold`
  attempts per minute (measured over the window).
- SUSPICIOUS_PORT: a source tries a port in `suspicious_ports`. Skipped for
  sources already reported as port scanners, which would otherwise raise one
  alert per port.

Every rule has a cooldown per source so a single attacker does not flood the
alert list.
"""

import logging
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional

from ..config import settings
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert

logger = logging.getLogger(__name__)

TCP_SYN = 0x02
TCP_ACK = 0x10

# Most event IDs stored on one alert
MAX_RELATED_EVENT_IDS = 100


@dataclass(frozen=True)
class Attempt:
    """One connection attempt remembered in a source's window"""
    time: float  # seconds since the Unix epoch
    dst_ip: str
    dst_port: int
    event_id: Optional[int]


def is_connection_attempt(event: NetworkEvent) -> bool:
    """
    True for a TCP SYN without ACK, or any UDP packet, arriving at or routed
    through this host. Outgoing copies are skipped so that local traffic
    (seen once leaving and once arriving) is not counted twice.
    """
    if getattr(event, "direction", None) == "out":
        return False
    if event.protocol == "TCP":
        flags = event.flags or 0
        return bool(flags & TCP_SYN) and not (flags & TCP_ACK)
    return event.protocol == "UDP"


def event_time(event: NetworkEvent) -> float:
    """Event time in seconds, from the kernel timestamp when available"""
    if event.timestamp:
        return event.timestamp / 1e9
    if event.created_at:
        return event.created_at.timestamp()
    return datetime.utcnow().timestamp()


class AnomalyDetectorService:
    """Detects suspicious network behaviour and stores security alerts"""

    def __init__(self):
        self.port_scan_threshold = settings.port_scan_threshold
        self.suspicious_ports = set(settings.suspicious_ports)
        self.high_frequency_threshold = settings.high_frequency_threshold
        self.window_seconds = float(settings.detection_window_seconds)
        self.max_attempts_per_source = settings.max_attempts_per_source
        self.alert_cooldown = timedelta(seconds=settings.alert_cooldown_seconds)
        # Kept for analyze_historical_patterns callers
        self.detection_window = timedelta(seconds=settings.detection_window_seconds)

        # Recent connection attempts per source IP
        self.windows: Dict[str, Deque[Attempt]] = {}

        # True while the kernel module reports scans and SYN floods itself
        # (see kernel_alerts.py); the matching rules here are then skipped
        self.kernel_detection = False

        # Last alert time per rule and source, to rate-limit alerts
        self.recent_alerts: Dict[str, datetime] = {}

        self.stats = {
            "events_analyzed": 0,
            "connection_attempts": 0,
            "alerts_generated": 0,
            "port_scans_detected": 0,
            "suspicious_ports_detected": 0,
            "high_frequency_detected": 0,
            "last_analysis": None,
        }

    def reset(self) -> None:
        """Forget all remembered activity and cooldowns"""
        self.windows.clear()
        self.recent_alerts.clear()

    async def analyze_events(self, events: List[NetworkEvent]) -> List[SecurityAlert]:
        """
        Add a batch of stored events to the sliding windows and return
        the alerts this batch triggered. Alerts are saved to the database.
        """
        if not events:
            return []

        self.stats["events_analyzed"] += len(events)

        # Connection attempts in this batch, grouped by source
        batch: Dict[str, List[Attempt]] = defaultdict(list)
        for event in events:
            if not is_connection_attempt(event):
                continue
            attempt = Attempt(
                time=event_time(event),
                dst_ip=event.dst_ip,
                dst_port=event.dst_port,
                event_id=event.id,
            )
            batch[event.src_ip].append(attempt)
            self._remember(event.src_ip, attempt)

        attempt_count = sum(len(a) for a in batch.values())
        self.stats["connection_attempts"] += attempt_count

        alerts: List[SecurityAlert] = []
        try:
            for src_ip, new_attempts in batch.items():
                window = self.windows.get(src_ip)
                if not window:
                    continue
                if not self.kernel_detection:
                    alerts.extend(self._check_port_scan(src_ip, window))
                    alerts.extend(self._check_high_frequency(src_ip, window))
                alerts.extend(self._check_suspicious_ports(src_ip, new_attempts))
        except Exception as e:
            logger.error(f"Error during anomaly analysis: {e}")

        stored = [alert for alert in alerts if self._store_alert(alert)]

        self.stats["alerts_generated"] += len(stored)
        self.stats["last_analysis"] = datetime.utcnow()
        if stored:
            logger.info(f"Analyzed {len(events)} events, generated {len(stored)} alerts")
        return stored

    def _remember(self, src_ip: str, attempt: Attempt) -> None:
        """Add an attempt to its source's window and drop expired ones"""
        window = self.windows.get(src_ip)
        if window is None:
            window = deque(maxlen=self.max_attempts_per_source)
            self.windows[src_ip] = window
        window.append(attempt)

        cutoff = attempt.time - self.window_seconds
        while window and window[0].time < cutoff:
            window.popleft()

    def _check_port_scan(self, src_ip: str, window: Deque[Attempt]) -> List[SecurityAlert]:
        ports = {a.dst_port for a in window}
        if len(ports) < self.port_scan_threshold:
            return []

        key = f"port_scan_{src_ip}"
        if self._is_in_cooldown(key):
            return []

        span = window[-1].time - window[0].time
        alert = SecurityAlert.create_port_scan_alert(
            src_ip=src_ip,
            event_count=len(window),
            event_ids=self._event_ids(window),
        )
        alert.description = (
            f"{src_ip} tried {len(ports)} different ports in {span:.1f} seconds "
            f"({len(window)} connection attempts), which looks like a port scan."
        )
        alert.dst_ip = window[-1].dst_ip
        alert.alert_metadata = {
            **(alert.alert_metadata or {}),
            "unique_ports": len(ports),
            "sample_ports": sorted(ports)[:50],
            "window_seconds": round(span, 3),
            "detection_method": "sliding_window_distinct_ports",
        }

        self._start_cooldown(key)
        self.stats["port_scans_detected"] += 1
        logger.warning(f"Port scan detected from {src_ip}: {len(ports)} ports in {span:.1f}s")
        return [alert]

    def _check_high_frequency(self, src_ip: str, window: Deque[Attempt]) -> List[SecurityAlert]:
        per_minute = len(window) * 60.0 / self.window_seconds
        if per_minute <= self.high_frequency_threshold:
            return []

        key = f"high_freq_{src_ip}"
        if self._is_in_cooldown(key):
            return []

        span = window[-1].time - window[0].time
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
                f"{src_ip} made {len(window)} connection attempts in {span:.1f} seconds "
                f"(about {per_minute:.0f} per minute; limit {self.high_frequency_threshold})."
            ),
            src_ip=src_ip,
            dst_ip=window[-1].dst_ip,
            related_event_ids=self._event_ids(window),
            alert_metadata={
                "attempts_per_minute": round(per_minute, 1),
                "event_count": len(window),
                "window_seconds": round(span, 3),
                "detection_method": "sliding_window_rate",
            },
        )

        self._start_cooldown(key)
        self.stats["high_frequency_detected"] += 1
        logger.warning(f"High frequency connections from {src_ip}: {per_minute:.0f}/min")
        return [alert]

    def _check_suspicious_ports(self, src_ip: str, attempts: List[Attempt]) -> List[SecurityAlert]:
        # A known scanner touches many sensitive ports; the scan alert covers it
        if self._is_in_cooldown(f"port_scan_{src_ip}"):
            return []

        alerts = []
        for attempt in attempts:
            if attempt.dst_port not in self.suspicious_ports:
                continue

            key = f"suspicious_port_{src_ip}_{attempt.dst_port}"
            if self._is_in_cooldown(key):
                continue

            alerts.append(
                SecurityAlert.create_suspicious_port_alert(
                    src_ip=src_ip,
                    dst_ip=attempt.dst_ip,
                    dst_port=attempt.dst_port,
                    event_ids=[attempt.event_id] if attempt.event_id is not None else [],
                )
            )
            self._start_cooldown(key)
            self.stats["suspicious_ports_detected"] += 1
            logger.warning(
                f"Suspicious port access: {src_ip} -> {attempt.dst_ip}:{attempt.dst_port}"
            )
        return alerts

    @staticmethod
    def _event_ids(window: Deque[Attempt]) -> List[int]:
        """Most recent event IDs in the window, capped"""
        ids = [a.event_id for a in window if a.event_id is not None]
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

        if expired_keys or idle_sources:
            logger.debug(
                f"Cleaned up {len(expired_keys)} cooldowns and {len(idle_sources)} idle sources"
            )


# Global instance
anomaly_detector = AnomalyDetectorService()
