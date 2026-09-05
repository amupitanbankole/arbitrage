"""FastAPI application factory and lifespan (§115).

The factory pattern — rather than a module-level ``app = FastAPI()`` — is what
makes the API testable: a test constructs an app with an injected state
container backed by SQLite and fakeredis, and no global object is mutated. It
also means configuration is read once per application, not once per import.

Middleware ordering
-------------------
``add_middleware`` inserts at the front of the stack, so **the last call is the
outermost layer**. The order below is deliberate:

1. ``RequestContextMiddleware`` (outermost) — assigns the request identifier
   before anything else runs, and therefore times and logs *every* response,
   including CORS rejections and security-header additions.
2. ``SecurityHeadersMiddleware`` — sees the final response from any layer below
   it, so error responses and preflight responses carry headers too.
3. ``CORSMiddleware`` (innermost) — handles preflight ``OPTIONS`` early; its
   responses still pass back out through the two layers above.

Reordering these silently degrades observability or security, so the rationale
lives next to the code.
"""

from __future__ import annotations

import contextlib
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from arb_api.api.health import router as health_router
from arb_api.api.metrics import router as metrics_router
from arb_api.api.root import router as root_router
from arb_api.api.v1.router import api_v1_router
from arb_api.middleware.error_handlers import register_exception_handlers
from arb_api.middleware.request_context import RequestContextMiddleware
from arb_api.middleware.security_headers import SecurityHeadersMiddleware
from arb_api.services.feature_flag_service import FeatureFlagService
from arb_api.state import AppState
from arb_core.config import Settings, get_settings
from arb_core.db.session import Database
from arb_core.events import InProcessEventBus
from arb_core.log import configure_logging, get_logger
from arb_core.metrics import Metrics
from arb_core.redis.client import RedisClient
from arb_core.redis.locks import RedisLock

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

__all__ = ["create_app", "lifespan"]

_logger = get_logger("arb_api.app")

#: Lock preventing several API replicas from seeding feature flags at once.
_BOOTSTRAP_LOCK_NAME = "bootstrap:feature-flags"
_BOOTSTRAP_LOCK_TTL_SECONDS = 30.0

_CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_CORS_ALLOW_HEADERS: list[str] = ["Authorization", "Content-Type", "X-Request-ID"]
_CORS_EXPOSE_HEADERS: list[str] = ["X-Request-ID"]
_CORS_MAX_AGE_SECONDS = 600

_OPENAPI_TAGS: list[dict[str, Any]] = [
    {
        "name": "meta",
        "description": "Service identity and entry points.",
    },
    {
        "name": "health",
        "description": (
            "Liveness, readiness and full dependency health. Unauthenticated and "
            "deliberately free of hostnames, ports and driver details."
        ),
    },
    {
        "name": "system",
        "description": (
            "Platform status including the global trading safety gates. "
            "`trading_mode_label` is computed server-side and must be rendered "
            "verbatim by clients."
        ),
    },
]

_OPENAPI_DESCRIPTION = """\
Non-custodial cryptocurrency arbitrage trading platform API.

## Conventions

* **Errors** are always `{"error": {"code", "message", "request_id", "details?"}}`.
  Match on `code`, which is stable; never on `message`. Stack traces, SQL and
  dependency error text are never returned.
* **Request correlation**: every response carries `X-Request-ID`. You may send
  your own (ASCII letters, digits and `._:-`, up to 128 characters); it will be
  echoed and used in server logs. Quote it when contacting support.
* **Pagination** is server-side on every list endpoint: `page` (1-based) and
  `page_size` (max 200), returning `items`, `total`, `page`, `page_size`,
  `total_pages`, `has_more`.
* **Time** is ISO-8601 UTC everywhere. Clients convert to a local timezone for
  display only.
* **Money** is transmitted as a decimal **string**, never a JSON number, because
  JSON numbers are binary doubles and would lose precision.

## Safety

Live trading is disabled by default and gated twice: the `LIVE_TRADING_ENABLED`
environment master switch **and** the `live_trading` feature flag must both be
on, and each bot additionally requires an explicit, audited activation. This
platform never holds user funds, never requests withdrawal permission, and never
places a live order without that activation.

## Status

This document describes **Phase 1** (platform foundation). Authentication,
exchange connectivity, market data, arbitrage, risk, trading, portfolio,
backtesting and administration are delivered in later phases and are not yet
present. `docs/STATUS.md` tracks every capability and labels it
`IMPLEMENTED`, `PARTIALLY IMPLEMENTED`, `MOCKED` or `NOT IMPLEMENTED`.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Build shared dependencies, bootstrap, then release them on shutdown.

    Startup does **not** fail when PostgreSQL or Redis is unreachable. Failing
    hard would put the container into a restart loop during a dependency outage
    and take down endpoints that still work, including ``/health/live`` and
    ``/health`` — the very endpoints an operator needs to diagnose the outage.
    Readiness reports the problem and nginx stops routing traffic instead (§111).
    """
    settings: Settings = app.state.settings
    injected = getattr(app.state, "container", None)

    if injected is not None:
        # A test or an embedding host supplied the container; do not own or
        # dispose its dependencies.
        injected.ready = True
        _logger.info("api started with an injected state container")
        try:
            yield
        finally:
            injected.ready = False
        return

    database = Database.from_settings(settings)
    redis = RedisClient.from_settings(settings)
    container = AppState(
        settings=settings,
        database=database,
        redis=redis,
        metrics=Metrics(),
        events=InProcessEventBus(),
    )
    app.state.container = container

    await _bootstrap(container)

    container.ready = True
    _logger.info(
        "api startup complete",
        extra={
            "environment": settings.environment.value,
            "version": settings.app_version,
            "database": settings.database_url_safe,
            "redis": settings.redis_url_safe,
            "live_trading_enabled": settings.live_trading_enabled,
            "global_kill_switch_enabled": settings.global_kill_switch_enabled,
        },
    )
    try:
        yield
    finally:
        container.ready = False
        _logger.info("api shutting down")
        with contextlib.suppress(Exception):
            await redis.aclose()
        with contextlib.suppress(Exception):
            await database.dispose()
        _logger.info("api shutdown complete")


async def _bootstrap(state: AppState) -> None:
    """Idempotent startup work. Never fatal.

    Feature-flag seeding takes a Redis lock so that when several API replicas
    start together only one performs the insert. The lock is an optimisation, not
    the correctness guarantee: the unique constraint on ``feature_flags.key`` is,
    which is why the ``IntegrityError`` path is handled rather than assumed
    impossible (§64, §65).
    """
    lock = RedisLock(state.redis, _BOOTSTRAP_LOCK_NAME, ttl_seconds=_BOOTSTRAP_LOCK_TTL_SECONDS)
    acquired = False
    try:
        acquired = await lock.acquire()
    except Exception:  # noqa: BLE001 - Redis being down must not block startup
        _logger.warning(
            "could not take the bootstrap lock; skipping startup seeding",
            extra={"lock": _BOOTSTRAP_LOCK_NAME},
        )
        return

    if not acquired:
        _logger.info("another instance holds the bootstrap lock; skipping seeding")
        return

    try:
        async with state.database.unit_of_work() as session:
            flags = FeatureFlagService(settings=state.settings, session=session, redis=state.redis)
            inserted = await flags.ensure_seeded()
        _logger.info("feature flag bootstrap complete", extra={"inserted": inserted})
    except IntegrityError:
        # Lost a race with another replica. The unique constraint did its job.
        _logger.info("feature flags were seeded concurrently by another instance")
    except SQLAlchemyError as exc:
        _logger.warning(
            "feature flag bootstrap deferred; the database may not be migrated yet. "
            "Run 'make migrate'.",
            extra={"error_type": type(exc).__name__},
        )
    except Exception:  # startup must survive a bootstrap failure
        _logger.exception("feature flag bootstrap failed")
    finally:
        with contextlib.suppress(Exception):
            await lock.release()


def create_app(
    *,
    settings: Settings | None = None,
    container: AppState | None = None,
) -> FastAPI:
    """Build the FastAPI application.

    ``container`` may be supplied to inject dependencies (tests, embedding
    hosts). When it is, the lifespan uses it as-is and does not close it.
    """
    resolved = settings or get_settings()

    # Configure logging before anything else can emit a line, so no output
    # escapes unstructured or unredacted (§127).
    configure_logging(
        level=resolved.log_level,
        log_format=resolved.log_format.value,
        service=resolved.service_name,
        redaction_enabled=resolved.log_redaction_enabled,
    )

    app = FastAPI(
        title="Arbitrage Platform API",
        description=_OPENAPI_DESCRIPTION,
        version=resolved.app_version,
        lifespan=lifespan,
        openapi_tags=_OPENAPI_TAGS,
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        # The API never serves HTML, so the interactive docs' OAuth helper is
        # disabled rather than pointing at a nonexistent flow.
        swagger_ui_oauth2_redirect_url=None,
        contact={"name": "Platform Operations"},
        license_info=None,
    )
    app.state.settings = resolved
    if container is not None:
        app.state.container = container

    register_exception_handlers(app)

    # Order matters — see the module docstring.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origin_list,
        allow_credentials=resolved.cors_allow_credentials,
        allow_methods=_CORS_ALLOW_METHODS,
        allow_headers=_CORS_ALLOW_HEADERS,
        expose_headers=_CORS_EXPOSE_HEADERS,
        max_age=_CORS_MAX_AGE_SECONDS,
    )
    app.add_middleware(
        SecurityHeadersMiddleware,
        # HSTS is only meaningful over TLS; emitting it from a plain-HTTP
        # development instance would be ignored at best and misleading at worst.
        hsts=resolved.is_deployed,
    )
    app.add_middleware(RequestContextMiddleware, service=resolved.service_name)

    app.include_router(root_router)
    app.include_router(health_router)
    app.include_router(metrics_router)
    app.include_router(api_v1_router)

    _logger.info(
        "application created",
        extra={
            "environment": resolved.environment.value,
            "routes": len(app.routes),
            "cors_origins": resolved.cors_origin_list,
        },
    )
    return app
