"""
Alembic environment for KGuard.

The database URL comes from the application settings (DATABASE_URL), not
alembic.ini. When the application runs migrations itself (app/database.py,
at start-up) it passes its own connection in config.attributes, so an
in-memory SQLite database is migrated in place.

    cd backend && alembic upgrade head          # build or update the schema
    alembic revision --autogenerate -m "..."    # after changing a model
    alembic check                               # models and migrations agree
"""

import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import models  # noqa: E402,F401  (registers every table)
from app.config import get_database_url  # noqa: E402
from app.database import Base  # noqa: E402

config = context.config

# The application configures its own logging; alembic.ini's only when run from the CLI
if config.config_file_name is not None and not config.attributes.get("connection"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def configure(**kwargs) -> None:
    url = kwargs.get("url") or str(kwargs["connection"].engine.url)
    context.configure(
        target_metadata=target_metadata,
        compare_type=True,
        # SQLite cannot ALTER most things: rebuild tables in batch mode
        render_as_batch=url.startswith("sqlite"),
        **kwargs,
    )


def run_migrations_offline() -> None:
    configure(url=get_database_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
        return

    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = get_database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
