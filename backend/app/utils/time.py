"""Datetime helpers"""

from datetime import datetime, timezone
from typing import Optional


def utc_naive(value: Optional[datetime]) -> Optional[datetime]:
    """
    A database datetime as naive UTC, for comparing with datetime.utcnow().
    PostgreSQL returns timezone=True columns timezone-aware, SQLite naive;
    mixing the two in a comparison raises TypeError.
    """
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)
