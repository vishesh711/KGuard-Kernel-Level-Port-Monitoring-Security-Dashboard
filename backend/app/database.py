"""
KGuard Database Configuration

Sets up the SQLAlchemy engine and session factory.
"""

import logging
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_database_url

logger = logging.getLogger(__name__)

DATABASE_URL = get_database_url()

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs = {
        "connect_args": {"check_same_thread": False, "timeout": 20},
        "echo": False,
    }
    # An in-memory database exists only inside one connection, so share it
    if ":memory:" in DATABASE_URL or DATABASE_URL in ("sqlite://", "sqlite:///"):
        engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(DATABASE_URL, **engine_kwargs)
else:
    engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Database session dependency for FastAPI"""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create database tables"""
    # Import models so they register with Base.metadata
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def check_db_connection() -> bool:
    """Return True if the database answers a trivial query"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False
