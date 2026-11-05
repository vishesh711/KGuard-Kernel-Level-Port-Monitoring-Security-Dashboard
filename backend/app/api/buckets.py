"""
Time-bucket helpers for statistics queries.

Groups rows into fixed-size time buckets inside the database (one GROUP BY
query) instead of running a query per bucket or loading every row into
Python. Works on SQLite and PostgreSQL.

Buckets are aligned to the Unix epoch, so one-hour buckets start on the hour
(UTC).
"""

from datetime import datetime, timezone
from typing import Dict, List, Tuple

from sqlalchemy import BigInteger, Integer, cast, extract, func
from sqlalchemy.orm import Session


def epoch_seconds(db: Session, column):
    """SQL expression for a timestamp column as whole seconds since the epoch (UTC)"""
    if db.get_bind().dialect.name == "sqlite":
        return cast(func.strftime("%s", column), Integer)
    return cast(extract("epoch", column), BigInteger)


def bucket_expr(db: Session, column, bucket_seconds: int):
    """SQL expression for the bucket number a timestamp falls into"""
    return epoch_seconds(db, column) // bucket_seconds


def bucket_range(start: datetime, end: datetime, bucket_seconds: int) -> List[int]:
    """Every bucket number from the one holding start to the one holding end"""
    first = int(_utc_timestamp(start)) // bucket_seconds
    last = int(_utc_timestamp(end)) // bucket_seconds
    return list(range(first, last + 1))


def bucket_start(bucket: int, bucket_seconds: int) -> datetime:
    """Naive UTC datetime at which a bucket starts"""
    return datetime.fromtimestamp(bucket * bucket_seconds, tz=timezone.utc).replace(tzinfo=None)


def fill_series(
    counts: Dict[int, int], start: datetime, end: datetime, bucket_seconds: int,
    limit: int = 0,
) -> List[Tuple[datetime, int]]:
    """
    Turn {bucket: count} into a list of (bucket start, count) covering
    start..end, with zero for empty buckets. If limit is set, keep only the
    most recent `limit` buckets.
    """
    buckets = bucket_range(start, end, bucket_seconds)
    if limit:
        buckets = buckets[-limit:]
    return [(bucket_start(b, bucket_seconds), int(counts.get(b, 0))) for b in buckets]


def _utc_timestamp(value: datetime) -> float:
    """Seconds since the epoch, treating naive datetimes as UTC"""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()
