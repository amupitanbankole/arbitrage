"""Alembic migration environment (§9, §141).

Runs against a **synchronous** engine.

That is a deliberate divergence from the application, which is async, and it is
worth stating plainly because the two must not be confused:

* ``DATABASE_URL`` uses an async driver (``asyncpg`` / ``aiosqlite``) and drives
  the running service.
* ``DATABASE_MIGRATION_URL`` uses the matching **sync** driver (``psycopg`` /
  ``sqlite``) and drives Alembic.

Alembic is synchronous throughout — including ``--sql`` offline mode and
``render_as_batch`` — so wrapping it in an async engine buys nothing and costs a
driver mismatch: every committed environment file supplies a sync migration URL,
and handing that to ``async_engine_from_config`` fails immediately
(``The asyncio extension requires an async driver``). Running migrations on the
sync driver keeps online and offline mode on one driver and removes the
``asyncio.run()`` nesting hazard for anything that embeds Alembic.

Both drivers are declared in ``packages/persistence/pyproject.toml`` so the
migration path never depends on a transitive install.

The URL is resolved from :class:`arb_core.config.Settings` rather than
``alembic.ini``:

1. ``-x url=...`` on the command line (highest priority, for one-off operations),
2. ``DATABASE_MIGRATION_URL`` (a sync driver — psycopg — so Alembic's
   ``offline``/``--sql`` mode works),
3. ``DATABASE_URL`` with an async driver swapped for its sync equivalent.

``render_as_batch=True`` is enabled unconditionally. SQLite cannot ``ALTER`` a
column in place, so without batch mode a migration that is valid on PostgreSQL
fails in the hermetic test-suite — and a migration that only works on one
dialect is a migration that will fail during an incident (§141).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic import context
from sqlalchemy import engine_from_config, pool

from arb_core.config import get_settings
from arb_core.log import configure_logging, get_logger
from arb_persistence.models import Base

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

_logger = get_logger("alembic.env")

config = context.config

# Structured, redacted logging instead of alembic.ini's fileConfig (§127).
_settings = get_settings()
configure_logging(
    # Migrations emit one INFO line per revision; SQL echo is opt-in. Without
    # this cap, a DEBUG log level floods the output with pool bookkeeping and
    # hides the revision history an operator is reading.
    level="INFO" if not _settings.database_echo else _settings.log_level,
    log_format=_settings.log_format,
    service=f"{_settings.service_name}-migrations",
    redaction_enabled=_settings.log_redaction_enabled,
)

if not _settings.database_echo:
    # Imported here so the log-level cap only applies once settings are known.
    import logging as _logging

    for _name in ("sqlalchemy.engine", "sqlalchemy.pool", "aiosqlite", "asyncio"):
        _logging.getLogger(_name).setLevel(_logging.WARNING)

target_metadata = Base.metadata

#: Async application drivers mapped to the sync driver Alembic uses. Applied only
#: to the last-resort fallback, when ``DATABASE_MIGRATION_URL`` is unset and the
#: async ``DATABASE_URL`` is all that is available.
_SYNC_DRIVER_MAP: dict[str, str] = {
    "postgresql+asyncpg": "postgresql+psycopg",
    "sqlite+aiosqlite": "sqlite",
}


def _x_argument(name: str) -> str | None:
    """Read a ``-x name=value`` argument, if supplied."""
    arguments = context.get_x_argument(as_dictionary=True)
    value = arguments.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def resolve_url() -> str:
    """Determine the database URL to migrate."""
    override = _x_argument("url")
    if override:
        _logger.info("using migration URL from -x url")
        return override

    # alembic.ini / programmatic override. Honoured ahead of settings because it
    # is the documented Alembic mechanism and is what the migration test-suite
    # uses to point at a throwaway database.
    from_ini = (config.get_main_option("sqlalchemy.url") or "").strip()
    if from_ini:
        return from_ini

    from_settings = _settings.database_migration_url.get_secret_value()
    if from_settings:
        return from_settings

    # Fall back to the application URL, converting an async driver to sync.
    application_url = _settings.database_url.get_secret_value()
    scheme = application_url.split("://", 1)[0]
    replacement = _SYNC_DRIVER_MAP.get(scheme)
    if replacement:
        return application_url.replace(f"{scheme}://", f"{replacement}://", 1)
    return application_url


def _configure(url: str) -> None:
    config.set_main_option("sqlalchemy.url", url)
    config.set_main_option("render_as_batch", "true")


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (§141 ``--sql`` mode).

    Useful for reviewing exactly what a deployment will execute before running
    it, and for archiving the DDL applied during an incident.
    """
    url = resolve_url()
    _configure(url)
    from arb_core.security.redaction import mask_dsn

    _logger.info("running migrations offline", extra={"url": mask_dsn(url)})
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=False,
        compare_server_default=False,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        # Type and server-default comparison is disabled: our portable
        # TypeDecorators (PreciseDecimal, UTCDateTime, JSONType) intentionally
        # render differently per dialect, so comparing them produces false
        # drift. Column, index and constraint changes are still detected.
        compare_type=False,
        compare_server_default=False,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and apply migrations."""
    url = resolve_url()
    _configure(url)

    from arb_core.security.redaction import mask_dsn

    _logger.info(
        "running migrations online",
        extra={"url": mask_dsn(url), "environment": _settings.environment.value},
    )

    # NullPool: a migration opens one connection, uses it and closes it. Holding
    # a pooled connection across a deployment step can keep a lock on
    # `alembic_version` alive while the next replica starts migrating.
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        _do_run_migrations(connection)

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
