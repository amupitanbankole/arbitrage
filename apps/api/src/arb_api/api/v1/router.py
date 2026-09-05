"""Version 1 API router (§67).

Every user-facing resource is mounted under ``/api/v1``. Administrative routes
are mounted separately under ``/api/v1/admin`` (Phase 9) with their own
permission-gated dependencies, so that a routing mistake cannot accidentally
place an admin endpoint behind ordinary user authorization (§41, §102).

Routers are included here rather than in the app factory so the URL tree is
described in one reviewable place.

This router carries **no prefix of its own**. Each included router spells its
complete path instead — see :mod:`arb_api.api.paths`, which explains why a
prefix declared here would be missing from ``scope["route"].path`` and therefore
from every access log line and Prometheus ``route`` label.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter

from arb_api.api.paths import API_V1_PREFIX
from arb_api.api.v1 import system
from arb_api.schemas.common import ApiIndex, ResourceGroup
from arb_api.state import StateDep

__all__ = ["api_v1_router"]

api_v1_router = APIRouter()

api_v1_router.include_router(system.router)

#: Implemented label per §151.
_IMPLEMENTED: Final[str] = "IMPLEMENTED"
_NOT_IMPLEMENTED: Final[str] = "NOT IMPLEMENTED"

#: Every resource group this API version is expected to expose, with the phase
#: that delivers it. Listed whether or not it exists yet, so the index cannot be
#: misread as "this is everything" (§151). Phases match
#: ``arb_api.services.health_service.INFORMATIONAL_COMPONENTS``.
_RESOURCE_GROUPS: Final[tuple[ResourceGroup, ...]] = (
    ResourceGroup(name="system", path="/api/v1/system", status=_IMPLEMENTED, phase="Phase 1"),
    ResourceGroup(name="auth", status=_NOT_IMPLEMENTED, phase="Phase 2"),
    ResourceGroup(name="users", status=_NOT_IMPLEMENTED, phase="Phase 2"),
    ResourceGroup(name="exchanges", status=_NOT_IMPLEMENTED, phase="Phase 3"),
    ResourceGroup(name="markets", status=_NOT_IMPLEMENTED, phase="Phase 4"),
    ResourceGroup(name="opportunities", status=_NOT_IMPLEMENTED, phase="Phase 5"),
    ResourceGroup(name="strategies", status=_NOT_IMPLEMENTED, phase="Phase 5"),
    ResourceGroup(name="risk", status=_NOT_IMPLEMENTED, phase="Phase 6"),
    ResourceGroup(name="bots", status=_NOT_IMPLEMENTED, phase="Phase 7"),
    ResourceGroup(name="trades", status=_NOT_IMPLEMENTED, phase="Phase 7"),
    ResourceGroup(name="orders", status=_NOT_IMPLEMENTED, phase="Phase 7"),
    ResourceGroup(name="portfolio", status=_NOT_IMPLEMENTED, phase="Phase 8"),
    ResourceGroup(name="notifications", status=_NOT_IMPLEMENTED, phase="Phase 9"),
    ResourceGroup(name="admin", status=_NOT_IMPLEMENTED, phase="Phase 9"),
    ResourceGroup(name="backtests", status=_NOT_IMPLEMENTED, phase="Phase 10"),
    ResourceGroup(name="rebalancing", status=_NOT_IMPLEMENTED, phase="Phase 12"),
)


@api_v1_router.get(
    API_V1_PREFIX,
    response_model=ApiIndex,
    summary="API index",
    description=(
        "What this API version actually offers. Every resource group is listed "
        "with its delivery status and phase, so `NOT IMPLEMENTED` is "
        "distinguishable from `built and broken` without reading the changelog."
    ),
    tags=["meta"],
)
async def api_index(state: StateDep) -> ApiIndex:
    """Describe the mounted resource groups and those still to come."""
    settings = state.settings
    return ApiIndex(
        api_version="v1",
        service=settings.service_name,
        environment=settings.environment.value,
        resources=list(_RESOURCE_GROUPS),
    )


# Phase 2 onward adds, in this order:
#   auth, users, exchanges, markets, opportunities, strategies, bots, trades,
#   orders, portfolio, risk, backtests, notifications, settings, admin/*
# Each arrives with the phase that implements it (§147); none is stubbed here,
# because an empty router mounted at a documented path advertises a capability
# that does not exist (§151).
