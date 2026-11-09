"""
Dashboard users (roadmap S6.5).

Two roles: "viewer" may read everything; "admin" may also change things
(acknowledge and resolve alerts, delete data, block addresses, manage users).
Only a salted scrypt hash of each password is stored. token_version is part
of every login token: raising it (password change, user disabled or deleted)
makes the user's existing tokens stop working.
"""

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from ..database import Base

ROLES = ("viewer", "admin")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False, default="viewer", comment="viewer or admin")
    is_active = Column(Boolean, nullable=False, default=True)
    token_version = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)

    def to_dict(self):
        return {
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
