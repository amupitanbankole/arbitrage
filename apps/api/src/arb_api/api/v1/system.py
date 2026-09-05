"""Versioned system status endpoints (§67).

Unauthenticated in Phase 1 because the values are public-safe and the UI needs
them before login to render the trading-mode banner (§31). Administrative
endpoints that expose more — worker hostnames, exchange configuration, user
data — live under ``/api/v1/admin/*`` and are permission-gated in Phase 9
(§41, §43). Authorization is always enforced server-side; nothing here relies on
the client hiding a button.
"""

from __future__ import annotations

from fastapi import APIRouter

from arb_api.api.dependencies import SystemServiceDep
from arb_api.schemas.system import SystemInfo, WorkersResponse

__all__ = ["router"]

router = APIRouter(prefix="/system", tags=["system"])


@router.get(
    "/info",
    response_model=SystemInfo,
    summary="Platform status and trading safety gates",
    description=(
        "Returns the service identity, server clock, and the state of the global "
        "trading gates. `trading_mode_label` is computed server-side and should be "
        "rendered verbatim so a client cannot derive an incorrect safety banner."
    ),
)
async def system_info(service: SystemServiceDep) -> SystemInfo:
    """Report platform status."""
    return await service.info()


@router.get(
    "/workers",
    response_model=WorkersResponse,
    summary="Worker fleet liveness",
    description=(
        "Live worker heartbeats. Hostnames and process identifiers are omitted "
        "from this public view; the permission-gated admin API returns them."
    ),
    responses={503: {"description": "Worker status could not be read."}},
)
async def workers(service: SystemServiceDep) -> WorkersResponse:
    """Report worker heartbeat status (§55)."""
    return await service.workers()
