"""
Kernel alert service.

The KGuard module (v3+) detects port scans and SYN floods in the kernel and
multicasts alerts over Generic Netlink. This service listens for them,
stores each as a SecurityAlert and pushes it to dashboards.

While it is connected, the backend's own port-scan and high-frequency rules
are switched off so each attack is reported once. If the module goes away,
the backend's rules take over again.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import update

from ..config import settings
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from .anomaly_detector import anomaly_detector
from .kguard_netlink import KGuardEventSocket
from .probes import CONNECTION_PROBES, LABELS, classify_probe
from .websocket_manager import broadcast_security_alert

logger = logging.getLogger(__name__)

RETRY_SECONDS = 10.0
# How far back to look at a source's events to name the scan type
SCAN_LOOKBACK_SECONDS = 15
# Events from an alerted source within this many seconds are marked suspicious
FLAG_SECONDS = 60
MAX_RELATED_EVENT_IDS = 100

ACTION_TEXT = {
    "blocked": "The kernel blocked this source automatically.",
    "dropped": "The kernel dropped the excess connection attempts.",
    "none": "No action was taken (monitor-only mode, or a protected address).",
}


def alert_from_kernel(event: Dict[str, Any]) -> SecurityAlert:
    """Turn a decoded kernel alert into a SecurityAlert (not yet saved)"""
    ip = event["src_ip"]
    action = event["action"]
    acted = action in ("blocked", "dropped")

    if event["type"] == "scan":
        alert_type = AlertType.PORT_SCAN
        severity = AlertSeverity.HIGH if acted or event["ports"] >= 100 else AlertSeverity.MEDIUM
        title = f"Port Scan Detected from {ip}"
        what = (f"The kernel saw {ip} try {event['ports']} different ports "
                f"({event['attempts']} connection attempts) within its scan window.")
    else:
        alert_type = AlertType.HIGH_FREQUENCY
        severity = AlertSeverity.HIGH if acted else AlertSeverity.MEDIUM
        title = f"Connection Flood from {ip}"
        what = (f"{ip} opened new TCP connections faster than the kernel's per-source "
                f"limit ({event['attempts']} attempts in the window).")

    return SecurityAlert(
        timestamp=datetime.fromtimestamp(event["timestamp"] / 1e9, tz=timezone.utc).replace(tzinfo=None),
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=f"{what} {ACTION_TEXT.get(action, '')}".strip(),
        src_ip=ip,
        alert_metadata={
            "source": "kernel",
            "detection_method": "kernel_guard",
            "action": action,
            "unique_ports": event["ports"],
            "attempts": event["attempts"],
            "netns": event["netns"],
            "kernel_timestamp": event["timestamp"],
        },
    )


class KernelAlertService:
    def __init__(self):
        self.enabled = settings.kernel_detection.lower() != "off"
        self.module_path = Path(settings.kguard_module_path)
        self.sock: Optional[KGuardEventSocket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._last_attempt = 0.0
        # source IP -> (monotonic expiry, event_type) for marking new events
        self._flagged: Dict[str, tuple] = {}
        self.stats = {"alerts_received": 0, "alerts_stored": 0}

    def flag_for(self, src_ip: str) -> Optional[str]:
        """event_type to give new events from src_ip, if it was alerted on recently"""
        entry = self._flagged.get(src_ip)
        if not entry:
            return None
        if entry[0] < time.monotonic():
            del self._flagged[src_ip]
            return None
        return entry[1]

    @property
    def active(self) -> bool:
        return self.sock is not None

    def check(self) -> None:
        """Connect when the module appears, disconnect when it goes. Cheap to call often."""
        if not self.enabled:
            return
        if self.sock and not self.module_path.exists():
            logger.info("KGuard module unloaded: backend detection rules back on")
            self.close()
            return
        if self.sock or time.monotonic() - self._last_attempt < RETRY_SECONDS:
            return
        self._last_attempt = time.monotonic()
        if not self.module_path.exists():
            return
        try:
            sock = KGuardEventSocket()
        except OSError as e:
            logger.debug(f"Kernel alerts unavailable: {e}")
            return
        if not sock.sends_alerts:
            sock.close()
            logger.info("KGuard module predates in-kernel detection; using backend rules")
            return
        self.loop = asyncio.get_running_loop()
        self.loop.add_reader(sock.fileno(), self._on_readable)
        self.sock = sock
        anomaly_detector.kernel_detection = True
        logger.info("Receiving in-kernel scan and SYN-rate alerts; backend copies of those rules off")

    def _on_readable(self) -> None:
        try:
            events = self.sock.read_alerts() if self.sock else []
        except OSError as e:
            logger.warning(f"Kernel alert socket failed: {e}")
            self.close()
            return
        for event in events:
            asyncio.ensure_future(self.handle(event))

    async def handle(self, event: Dict[str, Any]) -> Optional[SecurityAlert]:
        self.stats["alerts_received"] += 1
        alert = alert_from_kernel(event)
        if event["type"] == "scan":
            # Same suppression as backend-detected scans: no extra alert per sensitive port
            anomaly_detector._start_cooldown(f"port_scan_{event['src_ip']}")

        event_type = alert.alert_type.value.lower()
        ip = event["src_ip"]
        if event["type"] == "scan":
            # A fast scan can end before the collector has stored its events;
            # wait for them so the scan type can be named
            await self._wait_for_events(ip)
        db = SessionLocal()
        try:
            # Link and mark the source's recent events (kernel alerts carry no event IDs)
            since = datetime.utcnow() - timedelta(seconds=FLAG_SECONDS)
            ids = [row.id for row in db.query(NetworkEvent.id)
                   .filter(NetworkEvent.src_ip == ip, NetworkEvent.created_at >= since)
                   .order_by(NetworkEvent.id.desc()).limit(MAX_RELATED_EVENT_IDS)]
            if event["type"] == "scan":
                self._label_scan(db, alert, ip)
            if ids:
                db.execute(update(NetworkEvent).where(NetworkEvent.id.in_(ids))
                           .values(is_suspicious=True, event_type=event_type))
            alert.related_event_ids = sorted(ids)
            db.add(alert)
            db.commit()
            db.refresh(alert)
        except Exception as e:
            db.rollback()
            logger.error(f"Error storing kernel alert: {e}")
            return None
        finally:
            db.close()

        # Events still on their way from the kernel get marked as they are stored
        self._flagged[ip] = (time.monotonic() + FLAG_SECONDS, event_type)
        self.stats["alerts_stored"] += 1
        logger.warning(f"Kernel alert: {alert.title} (action: {event['action']})")
        await broadcast_security_alert(alert.to_dict())
        return alert

    @staticmethod
    async def _wait_for_events(ip: str, timeout: float = 3.0) -> None:
        since = datetime.utcnow() - timedelta(seconds=SCAN_LOOKBACK_SECONDS)
        deadline = time.monotonic() + timeout
        while True:
            db = SessionLocal()
            try:
                found = db.query(NetworkEvent.id).filter(
                    NetworkEvent.src_ip == ip, NetworkEvent.created_at >= since,
                    NetworkEvent.host_id.is_(None)).first()
            finally:
                db.close()
            if found or time.monotonic() >= deadline:
                return
            await asyncio.sleep(0.25)

    @staticmethod
    def _label_scan(db, alert: SecurityAlert, ip: str) -> None:
        """Name the scan type (the kernel counts SYN and UDP probes) from the source's recent events"""
        since = datetime.utcnow() - timedelta(seconds=SCAN_LOOKBACK_SECONDS)
        rows = (db.query(NetworkEvent.protocol, NetworkEvent.flags, NetworkEvent.ct_state,
                         NetworkEvent.dst_port, NetworkEvent.direction)
                .filter(NetworkEvent.src_ip == ip, NetworkEvent.created_at >= since,
                        NetworkEvent.host_id.is_(None))
                .limit(20000).all())
        ports: Dict[str, set] = {}
        for protocol, flags, ct_state, dst_port, direction in rows:
            if direction == "out":
                continue
            kind = classify_probe(protocol, flags, ct_state, dst_port)
            if kind in CONNECTION_PROBES:
                ports.setdefault(kind, set()).add(dst_port)
        if not ports:
            return
        kind = max(ports, key=lambda k: len(ports[k]))
        alert.title = f"{LABELS[kind]} Scan Detected from {ip}"
        alert.alert_metadata = {**alert.alert_metadata, "scan_type": kind}

    def reset(self) -> None:
        self._flagged.clear()

    def close(self) -> None:
        if self.sock:
            if self.loop:
                self.loop.remove_reader(self.sock.fileno())
            self.sock.close()
            self.sock = None
        anomaly_detector.kernel_detection = False

    def get_stats(self) -> Dict[str, Any]:
        return {**self.stats, "enabled": self.enabled, "active": self.active}


kernel_alerts = KernelAlertService()
