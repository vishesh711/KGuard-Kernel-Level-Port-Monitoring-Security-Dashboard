"""
Response engine tables (roadmap S6.4).

blocks           addresses and prefixes to drop, on every host or one agent's;
                 a row is never deleted: unblocking or expiry sets removed_at,
                 so the history stays
block_allowlist  prefixes that may never be blocked, by hand or automatically
audit_log        every block, unblock, expiry and allowlist change, and who
                 (a user, "auto-response" or "expiry") made it
"""

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from ..database import Base


class Block(Base):
    __tablename__ = "blocks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cidr = Column(String(49), nullable=False, index=True,
                  comment="Network in canonical form, e.g. 10.0.0.5/32")
    host_id = Column(Integer, nullable=True, index=True, comment="Agent that enforces it; empty = every host")
    reason = Column(Text, nullable=False)
    source = Column(String(16), nullable=False, comment="manual or auto")
    created_by = Column(String(64), nullable=False)
    alert_id = Column(Integer, nullable=True, comment="Alert that caused an automatic block")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True, comment="Empty = until unblocked")
    removed_at = Column(DateTime(timezone=True), nullable=True, index=True)
    removed_by = Column(String(64), nullable=True)

    def to_dict(self, now=None) -> dict:
        from datetime import datetime

        from ..utils.time import utc_naive

        now = now or datetime.utcnow()
        expires = utc_naive(self.expires_at) if self.expires_at else None
        active = self.removed_at is None and (expires is None or expires > now)
        return {
            "id": self.id,
            "cidr": self.cidr,
            "host_id": self.host_id,
            "reason": self.reason,
            "source": self.source,
            "created_by": self.created_by,
            "alert_id": self.alert_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "removed_at": self.removed_at.isoformat() if self.removed_at else None,
            "removed_by": self.removed_by,
            "active": active,
            "seconds_left": int((expires - now).total_seconds()) if active and expires else None,
        }


class AllowEntry(Base):
    __tablename__ = "block_allowlist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cidr = Column(String(49), nullable=False, unique=True)
    note = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def to_dict(self) -> dict:
        return {"id": self.id, "cidr": self.cidr, "note": self.note, "created_by": self.created_by,
                "created_at": self.created_at.isoformat() if self.created_at else None}


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    time = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    actor = Column(String(64), nullable=False, comment="User name, auto-response, expiry or an agent")
    action = Column(String(32), nullable=False, index=True)
    target = Column(String(64), nullable=True, comment="Usually the address or prefix")
    details = Column(JSON, nullable=True)

    def to_dict(self) -> dict:
        return {"id": self.id, "time": self.time.isoformat() if self.time else None, "actor": self.actor,
                "action": self.action, "target": self.target, "details": self.details}
