"""
Data Collector Service

Reads network events from the kernel module, stores them, runs anomaly
detection on them, and pushes new events and alerts to connected dashboards.

Sources (settings.kguard_source):
  device  /dev/kguard: per-CPU rings mapped into this process (zero-copy)
  proc    /proc/kguard: JSON text view
  auto    the device when it can be opened, otherwise /proc

Reading either source removes the events from the kernel, so this service
must be the only reader. Health checks only test that the files exist; they
never read them.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import insert, update

from ..config import settings
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from .anomaly_detector import anomaly_detector
from .kguard_device import KGuardDevice
from .process_resolver import ProcessResolver
from .websocket_manager import broadcast_network_event, broadcast_security_alert

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol")

# Most events taken from the device per collection cycle
MAX_EVENTS_PER_CYCLE = 200_000


class DataCollectorService:
    """Collects kernel events, stores them and hands them to detection"""

    def __init__(self):
        self.proc_path = Path(settings.proc_kguard_path)
        self.device_path = Path(settings.kguard_device_path)
        self.source_setting = settings.kguard_source.lower()
        self.device: Optional[KGuardDevice] = None
        self.active_source: Optional[str] = None
        self._device_error_logged = False
        self.resolver = ProcessResolver(settings.proc_root) if settings.resolve_processes else None
        self.collection_interval = settings.data_collection_interval
        self.running = False
        self._missing_logged = False
        self.stats = {
            "events_collected": 0,
            "events_stored": 0,
            "alerts_generated": 0,
            "kernel_events_dropped": 0,
            "errors": 0,
            "last_collection": None,
        }

    async def start_collection(self) -> None:
        """Run the collection loop until stop_collection() is called"""
        if self.running:
            logger.warning("Data collection is already running")
            return

        self.running = True
        logger.info(f"Starting data collection (source: {self.source_setting})")
        try:
            while self.running:
                await self.collect_once()
                await asyncio.sleep(self.collection_interval)
        finally:
            self.running = False

    def stop_collection(self) -> None:
        logger.info("Stopping data collection service")
        self.running = False
        self.close_device()

    def close_device(self) -> None:
        """Release /dev/kguard so another reader (or /proc/kguard) can use it"""
        if self.device:
            self.device.close()
            self.device = None

    async def collect_once(self) -> int:
        """
        Run one collection cycle: read, parse, store, detect, broadcast.
        Returns the number of events stored.
        """
        try:
            events = self._read_events()
            if not events:
                return 0
            self._attach_processes(events)

            stored = self._store_events(events)
            self.stats["events_collected"] += len(events)
            self.stats["events_stored"] += len(stored)
            self.stats["last_collection"] = datetime.utcnow()

            alerts = await anomaly_detector.analyze_events(stored)
            if alerts:
                self.stats["alerts_generated"] += len(alerts)
                self._mark_suspicious(alerts)

            await self._broadcast(stored, alerts)
            return len(stored)

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error collecting events: {e}", exc_info=True)
            return 0

    def _read_events(self) -> List[Dict[str, Any]]:
        """Take every waiting event from the configured source"""
        if self.source_setting in ("auto", "device"):
            device = self._ensure_device()
            if device:
                self.active_source = "device"
                events = device.read(limit=MAX_EVENTS_PER_CYCLE)
                self._note_dropped(device.dropped())
                return events
            if self.source_setting == "device":
                return []

        raw = self._read_kernel_events()
        if not raw:
            return []
        self.active_source = "proc"
        return self._parse_events(raw)

    def _ensure_device(self) -> Optional[KGuardDevice]:
        if self.device:
            return self.device
        if not self.device_path.exists():
            return None
        try:
            self.device = KGuardDevice(str(self.device_path))
            logger.info(f"Reading events from {self.device_path} (zero-copy rings)")
            self._device_error_logged = False
        except (OSError, RuntimeError) as e:
            if not self._device_error_logged:
                logger.warning(f"Cannot use {self.device_path}: {e}; falling back to {self.proc_path}")
                self._device_error_logged = True
        return self.device

    def _note_dropped(self, dropped: int) -> None:
        if dropped > self.stats["kernel_events_dropped"]:
            logger.warning(
                f"Kernel rings overflowed: {dropped - self.stats['kernel_events_dropped']} "
                f"events lost (raise the module's buffer_size or collect more often)"
            )
            self.stats["kernel_events_dropped"] = dropped

    def _attach_processes(self, events: List[Dict[str, Any]]) -> None:
        """Name the owner of each event's socket when the kernel only gave its inode"""
        if not self.resolver:
            return
        unknown = [e for e in events if e.get("sock_ino") and (e.get("pid", -1) or -1) < 0]
        if not unknown:
            return
        owners = self.resolver.lookup_many(e["sock_ino"] for e in unknown)
        for event in unknown:
            owner = owners.get(event["sock_ino"])
            if owner:
                event["pid"], event["comm"] = owner

    def _read_kernel_events(self) -> Optional[str]:
        """Read and drain /proc/kguard. Returns None when unavailable."""
        try:
            with open(self.proc_path, "r") as f:
                data = f.read().strip()
            self._missing_logged = False
            return data or None
        except FileNotFoundError:
            if not self._missing_logged:
                logger.warning(f"Kernel module interface not found: {self.proc_path}")
                self._missing_logged = True
            return None
        except PermissionError:
            if not self._missing_logged:
                logger.error(f"Permission denied reading {self.proc_path} (run as root)")
                self._missing_logged = True
            return None
        except OSError as e:
            logger.error(f"Error reading kernel events: {e}")
            return None

    def _parse_events(self, raw_data: str) -> List[Dict[str, Any]]:
        """Parse kernel JSON into a list of valid event dictionaries"""
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from kernel module: {e}")
            return []

        if isinstance(data, dict):
            if "error" in data:
                logger.warning(f"Kernel module error: {data['error']}")
                return []
            dropped = data.get("dropped")
            if isinstance(dropped, int):
                self._note_dropped(dropped)
            events = data.get("events", [data] if "src_ip" in data else [])
        elif isinstance(data, list):
            events = data
        else:
            logger.error(f"Unexpected data format: {type(data)}")
            return []

        valid = [e for e in events if self._validate_event(e)]
        if len(valid) != len(events):
            logger.warning(f"Skipped {len(events) - len(valid)} invalid events")
        return valid

    @staticmethod
    def _validate_event(event: Any) -> bool:
        if not isinstance(event, dict):
            return False
        if any(field not in event for field in REQUIRED_FIELDS):
            return False

        timestamp = event["timestamp"]
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0:
            return False
        if not isinstance(event["src_ip"], str) or not isinstance(event["dst_ip"], str):
            return False
        if not isinstance(event["protocol"], str):
            return False
        try:
            src_port = int(event["src_port"])
            dst_port = int(event["dst_port"])
        except (TypeError, ValueError):
            return False
        return 0 <= src_port <= 65535 and 0 <= dst_port <= 65535

    def _store_events(self, events: List[Dict[str, Any]]) -> List[NetworkEvent]:
        """
        Insert events in one statement and return them with their new IDs.
        The returned objects stay usable after the session closes.
        """
        rows = [
            {
                "timestamp": e["timestamp"],
                "src_ip": e["src_ip"],
                "dst_ip": e["dst_ip"],
                "src_port": int(e["src_port"]),
                "dst_port": int(e["dst_port"]),
                "protocol": e["protocol"],
                "flags": int(e.get("flags", 0) or 0),
                "is_suspicious": False,
                "event_type": "normal",
                **self._context(e),
            }
            for e in events
        ]

        db = SessionLocal(expire_on_commit=False)
        try:
            stored = list(db.scalars(insert(NetworkEvent).returning(NetworkEvent), rows))
            db.commit()
            return stored
        except Exception as e:
            db.rollback()
            logger.error(f"Database error storing events: {e}")
            return []
        finally:
            db.close()

    @staticmethod
    def _context(e: Dict[str, Any]) -> Dict[str, Any]:
        """Kernel v2 context fields; None when unknown (or from an older module)"""
        def known(value, unknown_values=(-1, None)):
            return None if value in unknown_values else value

        direction = e.get("direction")
        return {
            "family": e.get("family"),
            "direction": direction if direction in ("in", "out", "fwd") else None,
            "ct_state": e.get("ct_state"),
            "netns": known(e.get("netns"), (None, 0)),
            "ifindex": known(e.get("ifindex"), (None, 0)),
            "pid": known(e.get("pid")),
            "process_name": e.get("comm") or None,
            "uid": known(e.get("uid")),
            "sock_ino": known(e.get("sock_ino"), (None, 0)),
        }

    def _mark_suspicious(self, alerts) -> None:
        """Flag the events behind each alert as suspicious"""
        db = SessionLocal()
        try:
            for alert in alerts:
                ids = alert.related_event_ids or []
                if not ids:
                    continue
                db.execute(
                    update(NetworkEvent)
                    .where(NetworkEvent.id.in_(ids))
                    .values(is_suspicious=True, event_type=alert.alert_type.value.lower())
                )
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Error marking suspicious events: {e}")
        finally:
            db.close()

    async def _broadcast(self, events: List[NetworkEvent], alerts) -> None:
        """Push alerts and the newest events to connected dashboards"""
        for alert in alerts:
            await broadcast_security_alert(alert.to_dict())

        limit = settings.websocket_max_events_per_batch
        for event in events[-limit:] if limit > 0 else []:
            await broadcast_network_event(event.to_dict())

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self.stats,
            "running": self.running,
            "source": self.active_source,
            "source_setting": self.source_setting,
            "device_path": str(self.device_path),
            "proc_path": str(self.proc_path),
            "collection_interval": self.collection_interval,
        }

    async def test_kernel_connection(self) -> Dict[str, Any]:
        """
        Check that a kernel interface exists and is usable.
        Never reads events: that would take them from the collector.
        """
        device_exists = self.device_path.exists()
        proc_exists = self.proc_path.exists()
        proc_readable = proc_exists and os.access(self.proc_path, os.R_OK)
        exists = device_exists or proc_exists
        readable = self.device is not None or proc_readable or (
            device_exists and os.access(self.device_path, os.R_OK | os.W_OK)
        )
        error = None
        if not exists:
            error = "Kernel module not loaded (no /dev/kguard or /proc/kguard)"
        elif not readable:
            error = "Permission denied"

        return {
            "proc_exists": exists,
            "readable": readable,
            "device_exists": device_exists,
            "device_open": self.device is not None,
            "source": self.active_source,
            "collector_running": self.running,
            "last_collection": (
                self.stats["last_collection"].isoformat()
                if self.stats["last_collection"] else None
            ),
            "kernel_events_dropped": self.stats["kernel_events_dropped"],
            "error": error,
        }


# Global instance
data_collector = DataCollectorService()
