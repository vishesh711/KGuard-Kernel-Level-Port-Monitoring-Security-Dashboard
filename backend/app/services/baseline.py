"""
Traffic baseline: learn what normal looks like, alert on large deviations.

Every `baseline_interval_seconds` the service counts incoming connection
attempts (TCP SYN, UDP) per (host, destination port) over that interval and
keeps an exponentially weighted moving average and variance for each.

An interval is unusual when, after `baseline_warmup` intervals of learning,
its count is at least `baseline_min_count`, more than `baseline_sigma`
standard deviations above the mean, and more than `baseline_ratio` times
the mean. Unusual intervals raise UNUSUAL_TRAFFIC and are not learned from,
so an attack cannot teach the baseline that attacks are normal.

The baseline adapts to the recent past (minutes to hours); it does not model
time-of-day patterns.
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import and_, func, or_

from ..config import settings
from ..database import SessionLocal
from ..models.network_event import NetworkEvent
from ..models.security_alert import AlertSeverity, AlertType, SecurityAlert
from .websocket_manager import broadcast_security_alert

logger = logging.getLogger(__name__)

Key = Tuple[Optional[int], int]  # (host_id, dst_port)

# Most (host, port) pairs tracked; the busiest win
MAX_KEYS = 5000


@dataclass
class PortStats:
    mean: float = 0.0
    var: float = 0.0
    samples: int = 0
    last_alert: Optional[datetime] = field(default=None)


class TrafficBaseline:
    def __init__(self, alpha: float = None, warmup: int = None, sigma: float = None,
                 ratio: float = None, min_count: int = None, cooldown: timedelta = None):
        self.alpha = alpha if alpha is not None else settings.baseline_alpha
        self.warmup = warmup if warmup is not None else settings.baseline_warmup
        self.sigma = sigma if sigma is not None else settings.baseline_sigma
        self.ratio = ratio if ratio is not None else settings.baseline_ratio
        self.min_count = min_count if min_count is not None else settings.baseline_min_count
        self.cooldown = cooldown or timedelta(seconds=settings.alert_cooldown_seconds)
        self.stats: Dict[Key, PortStats] = {}

    def reset(self) -> None:
        self.stats.clear()

    def observe(self, key: Key, count: int, now: datetime) -> Optional[Dict[str, float]]:
        """
        Feed one interval's count. Returns details when the count is unusual
        (and not in cooldown), otherwise None.
        """
        s = self.stats.setdefault(key, PortStats())
        std = math.sqrt(s.var)
        unusual = (
            s.samples >= self.warmup
            and count >= self.min_count
            and count > s.mean + self.sigma * std
            and count > self.ratio * max(s.mean, 1.0)
        )
        if unusual:
            if s.last_alert and now - s.last_alert < self.cooldown:
                return None
            s.last_alert = now
            return {"count": count, "mean": round(s.mean, 2), "std": round(std, 2)}

        # Learn only from normal intervals
        if s.samples == 0:
            s.mean = float(count)
        else:
            diff = count - s.mean
            s.mean += self.alpha * diff
            s.var = (1 - self.alpha) * (s.var + self.alpha * diff * diff)
        s.samples += 1
        return None

    def _counts(self, start: datetime, end: datetime) -> Dict[Key, int]:
        """Incoming connection attempts per (host, port) between start and end"""
        db = SessionLocal()
        try:
            attempt = or_(
                NetworkEvent.protocol == "UDP",
                and_(NetworkEvent.protocol == "TCP",
                     NetworkEvent.flags.op("&")(0x02) != 0,
                     NetworkEvent.flags.op("&")(0x10) == 0),
            )
            incoming = or_(NetworkEvent.direction.is_(None), NetworkEvent.direction != "out")
            rows = (db.query(NetworkEvent.host_id, NetworkEvent.dst_port, func.count(NetworkEvent.id))
                    .filter(NetworkEvent.created_at >= start, NetworkEvent.created_at < end,
                            attempt, incoming)
                    .group_by(NetworkEvent.host_id, NetworkEvent.dst_port)
                    .order_by(func.count(NetworkEvent.id).desc())
                    .limit(MAX_KEYS).all())
            return {(host_id, port): count for host_id, port, count in rows}
        finally:
            db.close()

    async def tick(self, now: datetime = None, interval: timedelta = None) -> List[SecurityAlert]:
        """Count the last interval, update the baseline and raise alerts"""
        now = now or datetime.utcnow()
        interval = interval or timedelta(seconds=settings.baseline_interval_seconds)
        counts = self._counts(now - interval, now)

        # Ports seen before but quiet now count as zero, so the mean decays
        keys = set(counts) | set(self.stats)
        alerts = []
        for key in keys:
            unusual = self.observe(key, counts.get(key, 0), now)
            if unusual:
                alerts.append(self._alert(key, unusual, interval))

        if len(self.stats) > MAX_KEYS:
            quiet = sorted(self.stats, key=lambda k: self.stats[k].mean)[: len(self.stats) - MAX_KEYS]
            for key in quiet:
                del self.stats[key]

        stored = []
        for alert in alerts:
            db = SessionLocal()
            try:
                db.add(alert)
                db.commit()
                db.refresh(alert)
                stored.append(alert)
            except Exception as e:
                db.rollback()
                logger.error(f"Error storing baseline alert: {e}")
            finally:
                db.close()
        for alert in stored:
            logger.warning(alert.title)
            await broadcast_security_alert(alert.to_dict())
        return stored

    def _alert(self, key: Key, details: Dict[str, float], interval: timedelta) -> SecurityAlert:
        host_id, port = key
        seconds = int(interval.total_seconds())
        times = details["count"] / max(details["mean"], 1.0)
        return SecurityAlert(
            timestamp=datetime.utcnow(),
            alert_type=AlertType.UNUSUAL_TRAFFIC,
            severity=AlertSeverity.HIGH if times >= 20 else AlertSeverity.MEDIUM,
            title=f"Unusual Traffic to Port {port}",
            description=(
                f"{details['count']} connection attempts to port {port} in the last {seconds} seconds; "
                f"normal is about {details['mean']:.0f} (±{details['std']:.0f}), so this is "
                f"{times:.0f}× the usual level."
            ),
            dst_port=port,
            host_id=host_id,
            alert_metadata={
                **details,
                "interval_seconds": seconds,
                "times_normal": round(times, 1),
                "detection_method": "ewma_baseline",
            },
        )


traffic_baseline = TrafficBaseline()
