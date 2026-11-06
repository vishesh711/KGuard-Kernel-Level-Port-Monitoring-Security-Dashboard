"""
KGuard Database Configuration

Sets up the SQLAlchemy engine and session factory.
"""

import logging
from typing import Generator

from sqlalchemy import create_engine, inspect, text
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
    """Create database tables, and add columns that newer versions introduced"""
    # Import models so they register with Base.metadata
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
    _add_missing_enum_values()
    logger.info("Database tables created successfully")


def _add_missing_columns() -> None:
    """
    create_all() never alters existing tables, so a database made by an older
    version would lack newer columns. Add any missing nullable column.
    (Stopgap until Alembic migrations are in place: roadmap S6.1.)
    """
    inspector = inspect(engine)
    quote = engine.dialect.identifier_preparer.quote
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                if not column.nullable:
                    logger.warning(
                        f"Cannot add required column {table.name}.{column.name}; recreate the table"
                    )
                    continue
                column_type = column.type.compile(dialect=engine.dialect)
                conn.execute(text(
                    f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(column.name)} {column_type}"
                ))
                logger.info(f"Added column {table.name}.{column.name}")


def _add_missing_enum_values() -> None:
    """
    PostgreSQL stores Enum columns as native types, which reject values added
    in newer versions (such as new alert types) until the type is altered.
    """
    if engine.dialect.name != "postgresql":
        return
    from sqlalchemy import Enum

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for table in Base.metadata.sorted_tables:
            for column in table.columns:
                if not isinstance(column.type, Enum) or not column.type.native_enum:
                    continue
                for value in column.type.enums:
                    conn.execute(text(
                        f"ALTER TYPE {column.type.name} ADD VALUE IF NOT EXISTS '{value}'"
                    ))


def check_db_connection() -> bool:
    """Return True if the database answers a trivial query"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False
