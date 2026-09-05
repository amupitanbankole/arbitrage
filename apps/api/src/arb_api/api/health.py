"""Health endpoints (§111).

Three endpoints with deliberately different semantics:

``/health/live``
    Process liveness. Touches **no** dependency. An orchestrator uses this to
    decide whether to restart the container; coupling it to the database would
    turn a database outage into a fleet-wide restart storm.

``/health/ready``
    Readiness. Probes PostgreSQL and Redis and returns ``503`` when a required
    dependency is unavailable, which is what makes nginx stop routing to this
    instance instead of serving users errors.

``/health``
    Human/monitoring view. Adds subsystems that are not implemented yet, marked
    ``DISABLED`` with the phase that introduces them, so the endpoint cannot be
    misread as "everything is fine" during a phased rollout (§151).

All three are unauthenticated by necessity and therefore expose no hostnames,
ports, driver versions or exception messages (§111, §124).
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Response, status

from arb_api.api.dependencies import HealthServiceDep
from arb_api.schemas.health import HealthResponse, LivenessResponse
from arb_core.health import HealthState

__all__ = ["router"]

router = APIRouter(tags=["health"])

#: Readiness fails only on a required dependency being unavailable. DEGRADED
#: (reachable but slow) still accepts traffic: withdrawing an instance because
#: the database is merely slow removes capacity exactly when it is most needed.
_NOT_READY_STATES: Final[frozenset[HealthState]] = frozenset({HealthState.UNAVAILABLE})


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description="Returns 200 whenever the process can serve requests. Does not check dependencies.",
)
async def liveness(service: HealthServiceDep) -> LivenessResponse:
    """Report process liveness."""
    return service.liveness()


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness probe",
    description=(
        "Probes PostgreSQL and Redis. Returns 503 when a required dependency is "
        "unavailable, so load balancers stop routing to this instance."
    ),
)
async def readiness(service: HealthServiceDep, response: Response) -> HealthResponse:
    """Report readiness against required dependencies."""
    report = await service.readiness()
    if report.status in _NOT_READY_STATES:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return report


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Full health report",
    description=(
        "Readiness plus subsystems that are not yet implemented, reported as "
        "DISABLED with the phase that introduces them."
    ),
)
async def health(service: HealthServiceDep, response: Response) -> HealthResponse:
    """Report the full dependency and subsystem picture."""
    report = await service.full()
    if report.status in _NOT_READY_STATES:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return report
