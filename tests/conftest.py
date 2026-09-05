"""Shared test fixtures.

The suite is hermetic by design (§142): no network, no real exchange, no
services that must be started by hand.

* **Database** — SQLite through ``aiosqlite``, using the *same* models and the
  *same* portable types as production. ``arb_core.db.sql_types`` makes this
  honest rather than approximate: decimals are stored as exact text instead of
  floats, and datetimes come back timezone-aware instead of naive.
* **Redis** — ``fakeredis``, including Lua scripting (``lupa``), so the
  distributed lock is tested against its real compare-and-delete implementation
  rather than a mock that always succeeds.
* **Exchange** — there is none in Phase 1. ``MockExchangeAdapter`` and
  ``PaperExchangeAdapter`` arrive in Phase 3 (§143, §144).

Tests that require a real PostgreSQL or Redis server are marked ``postgres`` /
``redis_server`` and skipped unless the corresponding environment variable is
set. CI and ``docker-compose`` provide real servers, so those paths are
exercised on every pull request while local runs stay dependency-free.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import fakeredis
import pytest
from httpx import ASGITransport, AsyncClient

# Importing the models package registers every mapped class on Base.metadata.
# Without it, create_all() would silently create nothing.
import arb_persistence.models  # noqa: F401 - side-effect import: registers models
from arb_api.app import create_app
from arb_api.state import AppState
from arb_core.config import Environment, Settings
from arb_core.db.base import Base
from arb_core.db.session import Database
from arb_core.events import InProcessEventBus
from arb_core.metrics import Metrics
from arb_core.redis.client import RedisClient
from tests.support.config import (
    TEST_ENCRYPTION_KEY,
    TEST_JWT_SECRET,
    TEST_SESSION_SECRET,
    production_kwargs,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from sqlalchemy.ext.asyncio import AsyncSession

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def pytest_configure(config: pytest.Config) -> None:
    """Force the test environment before any settings are constructed.

    Assignment, not ``setdefault``: ``ENVIRONMENT`` selects which dotenv files
    :func:`arb_core.config.resolve_env_files` loads *and* whether
    ``validate_deployed_environment`` runs. A developer who happens to have
    ``ENVIRONMENT=production`` exported would otherwise get a suite that
    constructs production-validated settings, and every failure would look like
    an application bug rather than what it is — an ambient variable. CI sets this
    explicitly, so the hazard is local-only, which is exactly why nobody would
    think to look for it there.
    """
    os.environ["ENVIRONMENT"] = Environment.TEST.value


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip service-backed tests unless the service is actually available."""
    skip_postgres = pytest.mark.skip(
        reason="requires a real PostgreSQL server; set TEST_POSTGRES_URL"
    )
    skip_redis = pytest.mark.skip(reason="requires a real Redis server; set TEST_REDIS_URL")
    for item in items:
        if "postgres" in item.keywords and not os.getenv("TEST_POSTGRES_URL"):
            item.add_marker(skip_postgres)
        if "redis_server" in item.keywords and not os.getenv("TEST_REDIS_URL"):
            item.add_marker(skip_redis)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@pytest.fixture
def settings() -> Settings:
    """Deterministic test configuration.

    Values are passed explicitly rather than read from dotenv files so a stray
    local ``.env`` cannot change test behaviour.
    """
    return Settings(
        environment=Environment.TEST,
        service_name="arbitrage-platform-test",
        app_version="0.1.0-test",
        debug=False,
        log_format="json",
        log_level="WARNING",
        database_url="sqlite+aiosqlite:///:memory:",
        database_migration_url="sqlite:///:memory:",
        redis_url="redis://localhost:6379/15",
        redis_key_prefix="arb_test",
        jwt_secret=TEST_JWT_SECRET,
        session_secret=TEST_SESSION_SECRET,
        encryption_key=TEST_ENCRYPTION_KEY,
        rate_limit_enabled=False,
        metrics_enabled=True,
        metrics_auth_token="",
        live_trading_enabled=False,
        global_kill_switch_enabled=False,
        email_provider="none",
        cors_origins="http://testserver",
        worker_heartbeat_interval_seconds=5,
        worker_stale_after_seconds=30,
    )


@pytest.fixture
def production_settings() -> Settings:
    """A validated production configuration."""
    return Settings(**production_kwargs())


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
@pytest.fixture
async def database(settings: Settings) -> AsyncIterator[Database]:
    """An in-memory SQLite database with the full schema created."""
    db = Database.create(settings.database_url.get_secret_value(), echo=settings.database_echo)
    async with db.engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield db
    finally:
        await db.dispose()


@pytest.fixture
async def session(database: Database) -> AsyncIterator[AsyncSession]:
    """A session inside a transaction that is rolled back after the test."""
    async with database.unit_of_work() as session:
        yield session


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_redis_server() -> fakeredis.FakeServer:
    """An isolated in-memory Redis server instance."""
    return fakeredis.FakeServer()


@pytest.fixture
async def redis_client(
    settings: Settings, fake_redis_server: fakeredis.FakeServer
) -> AsyncIterator[RedisClient]:
    """A ``RedisClient`` backed by fakeredis, including Lua scripting."""
    raw = fakeredis.aioredis.FakeRedis(server=fake_redis_server, decode_responses=False)
    client = RedisClient(raw, key_prefix=settings.redis_key_prefix, url_safe="redis://fakeredis")
    try:
        yield client
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
@pytest.fixture
def events() -> InProcessEventBus:
    """A fresh in-process event bus."""
    return InProcessEventBus()


@pytest.fixture
def metrics() -> Metrics:
    """A fresh Prometheus registry (never the global default)."""
    return Metrics()


@pytest.fixture
def container(
    settings: Settings,
    database: Database,
    redis_client: RedisClient,
    events: InProcessEventBus,
    metrics: Metrics,
) -> AppState:
    """A fully-injected application state container."""
    state = AppState(
        settings=settings,
        database=database,
        redis=redis_client,
        metrics=metrics,
        events=events,
    )
    state.ready = True
    return state


@pytest.fixture
def app(settings: Settings, container: AppState) -> Any:
    """A FastAPI application wired to the injected container."""
    return create_app(settings=settings, container=container)


@pytest.fixture
async def client(app: Any) -> AsyncIterator[AsyncClient]:
    """An HTTP client that calls the ASGI app directly, with no open socket."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client


# ---------------------------------------------------------------------------
# Helpers available to tests
# ---------------------------------------------------------------------------
@pytest.fixture
def project_root() -> Path:
    """Absolute path to the monorepo root."""
    return PROJECT_ROOT


@pytest.fixture
def alembic_cfg(tmp_path: Path) -> Any:
    """An Alembic ``Config`` pointed at a throwaway SQLite file.

    ``sqlalchemy.url`` is set explicitly because ``alembic/env.py`` honours it
    ahead of ``DATABASE_MIGRATION_URL``; without that precedence the migration
    tests would run against whatever the ambient environment points at.

    Tests using this fixture must be **synchronous**: ``env.py`` calls
    ``asyncio.run()`` internally, which raises if a loop is already running.
    """
    from alembic.config import Config

    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "packages/persistence/alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'migrations.db'}")
    return cfg


@pytest.fixture
def some_user_id() -> UUID:
    """A stable, arbitrary user identifier for flag and permission tests."""
    return UUID("01890b1e-0000-7000-8000-000000000001")


@pytest.fixture(autouse=True)
def _clear_context() -> Iterator[None]:
    """Ensure ambient logging context never leaks between tests (§66)."""
    from arb_core.context import clear_context, reset

    token = clear_context()
    try:
        yield
    finally:
        reset(token)


@pytest.fixture(autouse=True)
def _preserve_logging_configuration() -> Iterator[None]:
    """Restore the root logger after every test.

    :func:`arb_core.log.configure_logging` removes *all* existing root handlers
    before installing its own — correct for a long-lived process, destructive
    under a test-suite. Two code paths call it during tests: the FastAPI app
    factory and ``alembic/env.py`` (re-executed by every migration command).
    Without this fixture the first test that builds an app silently strips
    pytest's ``caplog`` handler, and later log assertions pass vacuously by
    capturing nothing.
    """
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_third_party = {
        name: (logging.getLogger(name).level, list(logging.getLogger(name).handlers))
        for name in ("sqlalchemy.engine", "sqlalchemy.pool", "aiosqlite", "uvicorn.access")
    }
    try:
        yield
    finally:
        for handler in list(root.handlers):
            if handler not in saved_handlers:
                root.removeHandler(handler)
                handler.close()
        for handler in saved_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
        root.setLevel(saved_level)
        for name, (level, handlers) in saved_third_party.items():
            logger = logging.getLogger(name)
            logger.setLevel(level)
            logger.handlers[:] = handlers
