"""Route-level dependencies wiring services to requests (§115).

Kept separate from :mod:`arb_api.state` because services import ``AppState``;
resolving them here rather than there avoids a circular import between the state
container and the service layer.

Dependencies construct a service per request. Services are stateless wrappers
around a session and the shared container, so this costs an object allocation
and nothing else — while making lifetime and transaction scope explicit at the
call site.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from arb_api.services.feature_flag_service import FeatureFlagService
from arb_api.services.health_service import HealthService
from arb_api.services.system_service import SystemService
from arb_api.state import SessionDep, StateDep

__all__ = [
    "FeatureFlagDep",
    "HealthServiceDep",
    "SystemServiceDep",
    "get_feature_flag_service",
    "get_health_service",
    "get_system_service",
]


def get_health_service(state: StateDep) -> HealthService:
    """Resolve the health aggregation service."""
    return HealthService(state)


def get_feature_flag_service(state: StateDep, session: SessionDep) -> FeatureFlagService:
    """Resolve feature-flag evaluation backed by the database and Redis cache."""
    return FeatureFlagService(settings=state.settings, session=session, redis=state.redis)


def get_system_service(
    state: StateDep,
    flags: Annotated[FeatureFlagService, Depends(get_feature_flag_service)],
) -> SystemService:
    """Resolve the system status service."""
    return SystemService(state, flags)


HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
FeatureFlagDep = Annotated[FeatureFlagService, Depends(get_feature_flag_service)]
SystemServiceDep = Annotated[SystemService, Depends(get_system_service)]
