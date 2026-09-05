"""Application state container and FastAPI dependencies (§115).

One container is built during startup and shared by every request. Creating a
database engine or Redis pool per request is the classic way a trading API
exhausts its connections under load (§81).

Dependencies are thin: they resolve something from the container and nothing
else. Business logic lives in ``services/``, which keeps routers declarative and
services testable without an HTTP layer (§114).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from arb_core.clock import utc_now
from arb_core.config import Settings
from arb_core.db.session import Database
from arb_core.errors import DependencyUnavailableError, ErrorCode
from arb_core.events import InProcessEventBus
from arb_core.metrics import Metrics
from arb_core.redis.client import RedisClient

__all__ = [
    "AppState",
    "SessionDep",
    "StateDep",
    "UnitOfWorkDep",
    "get_database",
    "get_event_bus",
    "get_metrics",
    "get_redis",
    "get_session",
    "get_settings_dep",
    "get_state",
    "get_unit_of_work",
]


@dataclass(slots=True)
class AppState:
    """Process-wide singletons owned by the application lifespan."""

    settings: Settings
    database: Database
    redis: RedisClient
    metrics: Metrics
    events: InProcessEventBus
    started_at: datetime = field(default_factory=utc_now)
    #: Set once startup completes. ``/health/ready`` reports not-ready until then
    #: so nginx does not route traffic to a half-initialised instance.
    ready: bool = False

    @property
    def uptime_seconds(self) -> int:
        """Whole seconds since the process finished starting up."""
        return max(0, int((utc_now() - self.started_at).total_seconds()))


def get_state(request: Request) -> AppState:
    """Resolve the application state container."""
    state = getattr(request.app.state, "container", None)
    if not isinstance(state, AppState):
        # Reaching this means a request arrived outside the lifespan, which only
        # happens when a test client is misconfigured. Fail loudly rather than
        # returning a half-built container.
        msg = "application state is not initialised"
        raise DependencyUnavailableError(msg, code=ErrorCode.SERVICE_UNAVAILABLE)
    return state


StateDep = Annotated[AppState, Depends(get_state)]


def get_settings_dep(state: StateDep) -> Settings:
    """Resolve configuration."""
    return state.settings


def get_database(state: StateDep) -> Database:
    """Resolve the database handle."""
    return state.database


def get_redis(state: StateDep) -> RedisClient:
    """Resolve the Redis handle."""
    return state.redis


def get_metrics(state: StateDep) -> Metrics:
    """Resolve the Prometheus registry owner."""
    return state.metrics


def get_event_bus(state: StateDep) -> InProcessEventBus:
    """Resolve the in-process event bus."""
    return state.events


async def get_session(state: StateDep) -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped database session.

    Read-oriented by default: it does **not** commit (§63). Endpoints that write
    must depend on :func:`get_unit_of_work` instead, so the transaction boundary
    is explicit at the call site rather than implicit in a dependency.
    """
    async with state.database.session() as session:
        yield session


async def get_unit_of_work(state: StateDep) -> AsyncIterator[AsyncSession]:
    """Yield a session inside an atomic transaction that commits on success."""
    async with state.database.unit_of_work() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]
UnitOfWorkDep = Annotated[AsyncSession, Depends(get_unit_of_work)]
