"""
Data Collector Service

Reads network events from the kernel module via /proc/kguard, stores them,
runs anomaly detection on them, and pushes new events and alerts to
connected dashboards.

Reading /proc/kguard removes the events from the kernel buffer, so this
service must be the only reader. Health checks only test that the file
exists and is readable; they never read it.
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
from .websocket_manager import broadcast_network_event, broadcast_security_alert

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol")


class DataCollectorService:
    """Collects kernel events, stores them and hands them to detection"""

    def __init__(self):
        self.proc_path = Path(settings.proc_kguard_path)
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
        logger.info(f"Starting data collection from {self.proc_path}")
        try:
            while self.running:
                await self.collect_once()
                await asyncio.sleep(self.collection_interval)
        finally:
            self.running = False

    def stop_collection(self) -> None:
        logger.info("Stopping data collection service")
        self.running = False

    async def collect_once(self) -> int:
        """
        Run one collection cycle: read, parse, store, detect, broadcast.
        Returns the number of events stored.
        """
        try:
            raw = self._read_kernel_events()
            if not raw:
                return 0

            events = self._parse_events(raw)
            if not events:
                return 0

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
            if isinstance(dropped, int) and dropped > self.stats["kernel_events_dropped"]:
                logger.warning(
                    f"Kernel buffer overflowed: {dropped - self.stats['kernel_events_dropped']} "
                    f"events lost (raise the module's buffer_size or collect more often)"
                )
                self.stats["kernel_events_dropped"] = dropped
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
            "proc_path": str(self.proc_path),
            "collection_interval": self.collection_interval,
        }

    async def test_kernel_connection(self) -> Dict[str, Any]:
        """
        Check that the kernel interface exists and is readable.
        Does not read it: reading would remove events from the kernel buffer.
        """
        exists = self.proc_path.exists()
        readable = exists and os.access(self.proc_path, os.R_OK)
        error = None
        if not exists:
            error = "Kernel module not loaded or /proc/kguard not found"
        elif not readable:
            error = "Permission denied"

        return {
            "proc_exists": exists,
            "readable": readable,
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
