"""
Data retention (roadmap S6.1): delete old data once a day.

    network events, DNS lookups, TLS handshakes   RETENTION_EVENTS_DAYS  (7)
    system metrics                                RETENTION_METRICS_DAYS (30)
    resolved alerts, and their saved pcap files   RETENTION_ALERTS_DAYS  (90)

Open (unresolved) alerts are never deleted automatically. 0 keeps a kind of
data forever. Rows go in batches of RETENTION_BATCH, each its own short
transaction, so a big first run never holds a long lock on a busy table.

The job runs a minute after start-up and then every 24 hours
(RETENTION_INTERVAL_HOURS).
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

from sqlalchemy import delete, select

from ..config import settings
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..models.payload import DnsQuery, TlsHandshake
from ..models.security_alert import SecurityAlert
from ..models.system_metric import SystemMetric

logger = logging.getLogger(__name__)


class RetentionJob:
    def __init__(self):
        self.interval = timedelta(hours=settings.retention_interval_hours)
        self.first_delay = timedelta(seconds=60)
        self.started = datetime.utcnow()
        self.last_run: Optional[datetime] = None
        self.last_result: Dict[str, int] = {}

    def due(self, now: datetime = None) -> bool:
        now = now or datetime.utcnow()
        if self.last_run is None:
            return now - self.started >= self.first_delay
        return now - self.last_run >= self.interval

    def run(self, now: datetime = None) -> Dict[str, int]:
        """Delete everything past its retention; returns rows deleted per table"""
        now = now or datetime.utcnow()
        plan = [
            (NetworkEvent, NetworkEvent.created_at, settings.retention_events_days, None),
            (DnsQuery, DnsQuery.created_at, settings.retention_events_days, None),
            (TlsHandshake, TlsHandshake.created_at, settings.retention_events_days, None),
            (SystemMetric, SystemMetric.timestamp, settings.retention_metrics_days, None),
            (SecurityAlert, SecurityAlert.created_at, settings.retention_alerts_days,
             SecurityAlert.resolved.is_(True)),
        ]
        result = {}
        for model, column, days, extra in plan:
            if days <= 0:
                continue
            condition = column < now - timedelta(days=days)
            if extra is not None:
                condition = condition & extra
            result[model.__tablename__] = self._delete(model, condition)
        self.last_run = now
        self.last_result = result
        if any(result.values()):
            logger.info(f"Retention: deleted {result}")
        return result

    @staticmethod
    def _delete(model, condition) -> int:
        removed = 0
        while True:
            db = SessionLocal()
            try:
                ids = [row[0] for row in db.execute(
                    select(model.id).where(condition).limit(settings.retention_batch))]
                if not ids:
                    return removed
                if model is SecurityAlert:
                    _remove_pcaps(ids)
                db.execute(delete(model).where(model.id.in_(ids)))
                db.commit()
                removed += len(ids)
            except Exception as e:
                db.rollback()
                logger.error(f"Retention of {model.__tablename__} failed: {e}")
                return removed
            finally:
                db.close()

    def get_stats(self) -> dict:
        return {"last_run": self.last_run.isoformat() if self.last_run else None,
                "last_result": self.last_result}


def _remove_pcaps(alert_ids) -> None:
    from .packet_capture import packet_capture

    for alert_id in alert_ids:
        path = packet_capture.path_for(alert_id)
        if path:
            path.unlink(missing_ok=True)


retention_job = RetentionJob()
