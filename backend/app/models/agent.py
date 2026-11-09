"""
Agent model: one KGuard agent (one monitored host) reporting to this backend.

Agents enroll with a shared enrollment key and receive their own token;
only a SHA-256 hash of the token is stored.
"""

from datetime import datetime, timedelta

from sqlalchemy import BigInteger, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from ..database import Base
from ..utils.time import utc_naive

# An agent that has not sent anything for this long is shown as offline
ONLINE_WINDOW = timedelta(seconds=30)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False, unique=True, comment="Name chosen at enrollment")
    hostname = Column(String(255), nullable=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True, comment="SHA-256 of the token")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    remote_addr = Column(String(45), nullable=True)
    engine = Column(String(16), nullable=True, comment="module or ebpf")
    version = Column(String(32), nullable=True)
    events_received = Column(BigInteger, default=0, nullable=False)
    kernel_dropped = Column(BigInteger, default=0, nullable=False,
                            comment="Lost in the host's kernel buffers")
    queue_dropped = Column(BigInteger, default=0, nullable=False, comment="Lost in the agent's queue")
    payload_dropped = Column(BigInteger, default=0, nullable=True,
                             comment="DNS/TLS payload samples lost in the agent's queue")

    def is_online(self, now: datetime = None) -> bool:
        if not self.last_seen:
            return False
        now = now or datetime.utcnow()
        last = utc_naive(self.last_seen)
        return now - last < ONLINE_WINDOW

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "engine": self.engine,
            "version": self.version,
            "online": self.is_online(),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "remote_addr": self.remote_addr,
            "events_received": self.events_received or 0,
            "kernel_dropped": self.kernel_dropped or 0,
            "queue_dropped": self.queue_dropped or 0,
            "payload_dropped": self.payload_dropped or 0,
        }
