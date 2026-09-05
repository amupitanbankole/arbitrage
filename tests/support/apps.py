"""Application builders for tests.

Kept out of ``conftest.py`` deliberately: pytest imports ``conftest`` itself, so
``from tests.conftest import ...`` can load the module twice under different
names and produce two distinct fixture registries. Plain helper modules have no
such hazard.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from httpx import ASGITransport, AsyncClient

from arb_api.app import create_app
from arb_api.state import AppState
from arb_core.db.session import Database
from arb_core.events import InProcessEventBus
from arb_core.metrics import Metrics
from arb_core.redis.client import RedisClient

if TYPE_CHECKING:
    from arb_core.config import Settings

#: A port nothing listens on. Connection is refused immediately, so tests do not
#: wait for a TCP timeout; an unroutable address like 10.255.255.1 would hang.
UNREACHABLE_HOST = "127.0.0.1"
UNREACHABLE_PORT = 1

UNREACHABLE_DATABASE_URL = (
    f"postgresql+asyncpg://arb:Sup3rSecret@{UNREACHABLE_HOST}:{UNREACHABLE_PORT}/arb"
)
UNREACHABLE_REDIS_URL = f"redis://{UNREACHABLE_HOST}:{UNREACHABLE_PORT}/0"


def unreachable_database() -> Database:
    """A ``Database`` whose every connection attempt is refused."""
    return Database.create(UNREACHABLE_DATABASE_URL)


def unreachable_redis() -> RedisClient:
    """A ``RedisClient`` whose every command is refused."""
    return RedisClient.create(UNREACHABLE_REDIS_URL, key_prefix="arb_test")


def build_container(
    settings: Settings,
    *,
    database: Database,
    redis: RedisClient,
    events: InProcessEventBus | None = None,
    metrics: Metrics | None = None,
    ready: bool = True,
) -> AppState:
    """An :class:`AppState` assembled from explicit parts."""
    state = AppState(
        settings=settings,
        database=database,
        redis=redis,
        metrics=metrics or Metrics(),
        events=events or InProcessEventBus(),
    )
    state.ready = ready
    return state


def build_app(container: AppState) -> Any:
    """A FastAPI app wired to ``container``."""
    return create_app(settings=container.settings, container=container)


def build_client(app: Any, *, raise_app_exceptions: bool = True) -> AsyncClient:
    """An HTTP client calling the ASGI app in-process, with no open socket.

    ``raise_app_exceptions=False`` lets a test observe the response the platform
    produces for an unhandled exception. Starlette's ``ServerErrorMiddleware``
    sends the 500 envelope *and then re-raises*, so the server can log the
    traceback; with the transport default of ``True`` that re-raise reaches the
    test instead of the response, and the envelope goes unverified.
    """
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions),
        base_url="http://testserver",
    )


async def dispose(*resources: Any) -> None:
    """Release test-owned dependencies, tolerating ones that are already closed."""
    for resource in resources:
        if isinstance(resource, Database):
            await resource.dispose()
        elif isinstance(resource, RedisClient):
            await resource.aclose()
