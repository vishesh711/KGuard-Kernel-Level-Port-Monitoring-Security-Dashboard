"""
Known listening sockets per host (roadmap U7.2). host_key is 0 for this
server and the agent's id otherwise. A host's first snapshot fills the
table (created_by "baseline"); admins add more with "mark known".
"""

from sqlalchemy import Column, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.sql import func

from ..database import Base


class KnownListener(Base):
    __tablename__ = "known_listeners"
    __table_args__ = (UniqueConstraint("host_key", "proto", "port", "process"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_key = Column(Integer, nullable=False, index=True, comment="0 = this server, else the agent id")
    proto = Column(String(8), nullable=False)
    port = Column(Integer, nullable=False)
    process = Column(String(64), nullable=False, comment="Empty when the owner is unknown")
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ListenerBaseline(Base):
    """Hosts whose first snapshot has been recorded as normal"""
    __tablename__ = "listener_baselines"

    host_key = Column(Integer, primary_key=True, autoincrement=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
