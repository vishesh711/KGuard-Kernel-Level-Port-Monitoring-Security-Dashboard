"""S6.1: the schema is built and upgraded by Alembic migrations"""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, inspect, text

import app.database as database

TABLES = set(database.BASELINE_TABLES) | {"users"}


def head():
    from alembic.script import ScriptDirectory
    return ScriptDirectory.from_config(database.alembic_config()).get_current_head()


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """init_db against a database of the test's own"""
    def use(url=None):
        engine = create_engine(url or f"sqlite:///{tmp_path}/db.sqlite")
        monkeypatch.setattr(database, "engine", engine)
        monkeypatch.setattr(database, "_migrated", False)
        return engine
    return use


def version(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def test_empty_database_gets_the_whole_schema(fresh):
    engine = fresh()
    database.init_db()
    assert TABLES <= set(inspect(engine).get_table_names())
    assert version(engine) == head()


def test_database_from_before_migrations_keeps_its_data(fresh):
    engine = fresh()
    Table("network_events", MetaData(), Column("id", Integer, primary_key=True),
          Column("src_ip", String(45))).create(engine)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO network_events (id, src_ip) VALUES (1, '10.0.0.5')"))
    database.init_db()
    columns = {c["name"] for c in inspect(engine).get_columns("network_events")}
    assert {"direction", "process_name", "sock_ino", "netns", "ttl", "os_guess"} <= columns
    assert TABLES <= set(inspect(engine).get_table_names())
    assert version(engine) == head()
    with engine.connect() as conn:
        assert conn.execute(text("SELECT src_ip FROM network_events WHERE id = 1")).scalar() == "10.0.0.5"


def test_running_again_changes_nothing(fresh, monkeypatch):
    engine = fresh()
    database.init_db()
    monkeypatch.setattr(database, "_migrated", False)
    database.init_db()
    assert version(engine) == head()


def test_models_and_migrations_agree():
    """Like `alembic check`: a model changed without a migration fails here"""
    from app import models  # noqa: F401

    with database.engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}),
                                database.Base.metadata)
    assert diff == []


def test_aware_datetimes_from_postgresql_are_normalised():
    from datetime import datetime, timedelta, timezone

    from app.models.agent import Agent
    from app.utils.time import utc_naive

    # A server in UTC+5:30 returns 17:00+05:30, which is 11:30 UTC
    india = timezone(timedelta(hours=5, minutes=30))
    assert utc_naive(datetime(2026, 1, 1, 17, 0, tzinfo=india)) == datetime(2026, 1, 1, 11, 30)
    assert utc_naive(datetime(2026, 1, 1, 17, 0)) == datetime(2026, 1, 1, 17, 0)
    now = datetime(2026, 1, 1, 11, 30, 10)
    assert Agent(last_seen=datetime(2026, 1, 1, 17, 0, tzinfo=india)).is_online(now)
