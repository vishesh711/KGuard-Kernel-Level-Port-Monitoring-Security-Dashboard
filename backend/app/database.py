"""
KGuard Database Configuration

Sets up the SQLAlchemy engine and session factory.
"""

import logging
from pathlib import Path
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


# Revision that matches the schema of databases made before migrations existed
BASELINE_REVISION = "0001"
# The tables that revision has; later tables come from their own migrations
BASELINE_TABLES = ("agents", "dns_queries", "network_events", "security_alerts",
                   "system_metrics", "tls_handshakes")
ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"
_migrated = False


def alembic_config(connection=None):
    from alembic.config import Config

    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def init_db() -> None:
    """
    Bring the database schema up to date with Alembic migrations (once per
    process). A database created before migrations existed (tables, but no
    alembic_version) is first brought to the baseline the old way, then
    stamped, so its data is kept.
    """
    global _migrated
    if _migrated:
        return
    from alembic import command

    from . import models  # noqa: F401  (registers the tables)

    with engine.begin() as conn:
        tables = set(inspect(conn).get_table_names())
        config = alembic_config(conn)
        if "alembic_version" not in tables and "network_events" in tables:
            logger.info("Database predates migrations: adding missing columns, then stamping the baseline")
            _add_missing_columns(conn)
            _add_missing_enum_values()
            command.stamp(config, BASELINE_REVISION)
        command.upgrade(config, "head")
    _migrated = True
    logger.info("Database schema is up to date")


def _add_missing_columns(conn) -> None:
    """
    Bring a pre-migration database to the baseline: create_all() for tables it
    lacks, then any missing nullable column (create_all never alters tables).
    """
    baseline = [t for t in Base.metadata.sorted_tables if t.name in BASELINE_TABLES]
    Base.metadata.create_all(bind=conn, tables=baseline)
    inspector = inspect(conn)
    quote = conn.dialect.identifier_preparer.quote
    for table in baseline:
        existing = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            if not column.nullable:
                logger.warning(f"Cannot add required column {table.name}.{column.name}; recreate the table")
                continue
            column_type = column.type.compile(dialect=conn.dialect)
            conn.execute(text(
                f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(column.name)} {column_type}"
            ))
            logger.info(f"Added column {table.name}.{column.name}")


def _add_missing_enum_values() -> None:
    """
    PostgreSQL stores Enum columns as native types; a pre-migration database
    may lack values (alert types) added since. ADD VALUE cannot run inside a
    transaction block, so this uses its own autocommit connection.
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
