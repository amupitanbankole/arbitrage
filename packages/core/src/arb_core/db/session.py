"""Async database engine, session lifecycle and health probe (§63, §81).

:func:`Database.unit_of_work` is the transaction boundary the platform uses for
anything that must be atomic — trade creation, order state transitions, fills,
P&L and balance updates, risk events and audit entries (§63). It commits on
clean exit and rolls back on **any** exception including ``CancelledError``, so
a task cancelled mid-write cannot leave a half-applied financial state.

Read paths should use :func:`Database.session`, which does not commit: opening a
write transaction for a read holds locks and, on PostgreSQL, pins an MVCC
snapshot that bloats the table.

Connection pooling is configured for a persistent service (§81): a bounded pool
with ``pool_pre_ping`` so a connection dropped by the server, a load balancer or
``idle_in_transaction_session_timeout`` is detected and replaced instead of
surfacing as a failed request.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from arb_core.clock import duration_ms, utc_now
from arb_core.health import ComponentCheck, HealthState
from arb_core.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from arb_core.config import Settings

__all__ = ["Database", "build_engine_kwargs", "describe_url", "is_sqlite_url"]

_logger = get_logger(__name__)

#: A probe slower than this is reported DEGRADED rather than HEALTHY: the
#: dependency still works, but latency is worth surfacing before it becomes an
#: outage (§111, §112).
_DEGRADED_AFTER_MS = 250


def is_sqlite_url(url: str) -> bool:
    """Return ``True`` for any SQLite URL (development/test only)."""
    return url.startswith("sqlite")


def _is_memory_sqlite(url: str) -> bool:
    return is_sqlite_url(url) and (":memory:" in url or url.endswith("://"))


def _ensure_sqlite_directory(url: str) -> None:
    """Create the parent directory of a file-backed SQLite database.

    Without this, a fresh checkout fails on the first test run with a confusing
    "unable to open database file" error rather than a clear setup step.
    """
    if not is_sqlite_url(url) or _is_memory_sqlite(url):
        return
    # sqlite+aiosqlite:///./tmpfiles/test.db  ->  ./tmpfiles/test.db
    path_text = url.split("///", 1)[-1]
    if not path_text or path_text.startswith(":memory:"):
        return
    parent = Path(path_text).expanduser().parent
    parent.mkdir(parents=True, exist_ok=True)


def build_engine_kwargs(
    url: str,
    *,
    echo: bool = False,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_timeout: int = 30,
    pool_recycle: int = 1800,
) -> dict[str, Any]:
    """Build dialect-appropriate ``create_async_engine`` keyword arguments.

    SQLite accepts none of the PostgreSQL pool arguments and needs a shared
    in-memory pool, so the two cases are handled here once rather than at every
    call site.
    """
    kwargs: dict[str, Any] = {"echo": echo, "future": True}

    if _is_memory_sqlite(url):
        # A single connection shared by every session; otherwise each new
        # connection would see an empty database.
        kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = {"check_same_thread": False}
        return kwargs

    if is_sqlite_url(url):
        kwargs["connect_args"] = {"check_same_thread": False}
        return kwargs

    kwargs.update(
        {
            "pool_size": pool_size,
            "max_overflow": max_overflow,
            "pool_timeout": pool_timeout,
            "pool_recycle": pool_recycle,
            "pool_pre_ping": True,
        }
    )
    return kwargs


class Database:
    """Owns one engine and its session factory.

    A single instance is created per process and shared. Creating engines
    per-request leaks connections and defeats pooling, which is the classic way
    a trading API exhausts its database under load (§81).
    """

    def __init__(self, engine: AsyncEngine, *, url_safe: str) -> None:
        self._engine = engine
        self._session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        self._url_safe = url_safe

    # --- construction ----------------------------------------------------
    @classmethod
    def create(cls, url: str, **engine_kwargs: Any) -> Database:
        """Create a :class:`Database` from a SQLAlchemy async URL."""
        _ensure_sqlite_directory(url)
        # Imported here rather than at module scope: arb_core.security.redaction and
        # this module are both reachable from arb_core.config, so a top-level import
        # would close a cycle.
        from arb_core.security.redaction import mask_dsn

        engine = create_async_engine(url, **engine_kwargs)
        return cls(engine, url_safe=mask_dsn(url))

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        """Create a :class:`Database` using pool settings from configuration.

        The pool arguments are routed through :func:`build_engine_kwargs` rather
        than passed straight to ``create_async_engine``: SQLite accepts none of
        them and raises ``TypeError`` if it receives any. Forwarding them
        unconditionally makes development and test startup (both SQLite) fail
        outright while production (PostgreSQL) works, which is the worst
        possible way for the bug to present itself.
        """
        url = settings.database_url.get_secret_value()
        return cls.create(
            url,
            **build_engine_kwargs(
                url,
                echo=settings.database_echo,
                pool_size=settings.database_pool_size,
                max_overflow=settings.database_max_overflow,
                pool_timeout=settings.database_pool_timeout_seconds,
                pool_recycle=settings.database_pool_recycle_seconds,
            ),
        )

    # --- accessors -------------------------------------------------------
    @property
    def engine(self) -> AsyncEngine:
        """The underlying engine (for migrations and diagnostics)."""
        return self._engine

    @property
    def url_safe(self) -> str:
        """The connection URL with credentials masked — safe to log (§127)."""
        return self._url_safe

    @property
    def dialect_name(self) -> str:
        """Active dialect name, e.g. ``postgresql`` or ``sqlite``."""
        return self._engine.dialect.name

    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Return the session factory (needed by Alembic and bulk jobs)."""
        return self._session_factory

    # --- lifecycles ------------------------------------------------------
    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Open a session **without** committing.

        Use for reads, or when the caller manages the transaction explicitly.
        """
        session = self._session_factory()
        try:
            yield session
        finally:
            await session.close()

    @asynccontextmanager
    async def unit_of_work(self) -> AsyncIterator[AsyncSession]:
        """Open a session inside an atomic transaction (§63).

        Commits when the block exits normally; rolls back on any exception,
        including cancellation, then re-raises so the caller sees the original
        failure.
        """
        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def probe(self, *, degraded_after_ms: int = _DEGRADED_AFTER_MS) -> ComponentCheck:
        """Execute ``SELECT 1`` and report state plus latency (§111)."""
        started = utc_now()
        try:
            async with self._engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - probe must never raise
            _logger.warning(
                "database health probe failed",
                extra={"error_type": type(exc).__name__, "database": self._url_safe},
            )
            return ComponentCheck(
                name="database",
                state=HealthState.UNAVAILABLE,
                latency_ms=duration_ms(started),
                # Exception type only: driver messages routinely embed the DSN,
                # which contains the database password (§133).
                detail=f"probe failed: {type(exc).__name__}",
            )

        latency = duration_ms(started)
        if latency > degraded_after_ms:
            return ComponentCheck(
                name="database",
                state=HealthState.DEGRADED,
                latency_ms=latency,
                detail=f"probe latency {latency}ms exceeds {degraded_after_ms}ms",
            )
        return ComponentCheck(name="database", state=HealthState.HEALTHY, latency_ms=latency)

    async def dispose(self) -> None:
        """Close every pooled connection. Called on graceful shutdown."""
        await self._engine.dispose()
        _logger.info("database engine disposed")


def describe_url(url: str) -> dict[str, Any]:
    """Return non-sensitive facts about a database URL, for diagnostics."""
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "database": parsed.path.lstrip("/"),
        "sqlite": is_sqlite_url(url),
    }
