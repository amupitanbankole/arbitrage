"""Health aggregation service (§111).

Components are split into two groups, and the distinction is load-bearing:

**Required** — the API cannot serve traffic without them (database, Redis).
These determine ``/health/ready`` and therefore whether nginx routes to this
instance.

**Informational** — subsystems that do not exist yet or are switched off. They
are reported as ``DISABLED`` with the phase that introduces them, so an operator
looking at ``/health`` can tell the difference between "not built yet" and
"built and broken". They never affect readiness: a platform that reported
not-ready because Phase 5 had not shipped would never start.

Reporting absent subsystems explicitly is a deliberate application of §151 —
the health endpoint must distinguish ``IMPLEMENTED``, ``DISABLED`` and
``NOT IMPLEMENTED`` rather than silently omitting them and looking healthy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from arb_api.schemas.health import ComponentHealth, HealthResponse, LivenessResponse
from arb_core.clock import utc_now
from arb_core.health import (
    ComponentCheck,
    HealthProbe,
    HealthState,
    run_probes,
    worst_state,
)

if TYPE_CHECKING:
    from arb_api.state import AppState

__all__ = ["INFORMATIONAL_COMPONENTS", "HealthService"]

#: Subsystems reported as DISABLED until the phase that implements them ships.
#: The value is the phase, surfaced in ``detail`` so the report is self-explaining.
INFORMATIONAL_COMPONENTS: Final[dict[str, str]] = {
    "exchanges": "Phase 3",
    "market_data": "Phase 4",
    "arbitrage": "Phase 5",
    "risk": "Phase 6",
    "execution": "Phase 7",
    "notifications": "Phase 9",
}


class HealthService:
    """Builds health responses from dependency probes."""

    def __init__(self, state: AppState) -> None:
        self._state = state

    def liveness(self) -> LivenessResponse:
        """Dependency-free liveness (§111)."""
        return LivenessResponse(status="alive", uptime_seconds=self._state.uptime_seconds)

    def _required_probes(self) -> dict[str, HealthProbe]:
        async def _api() -> ComponentCheck:
            # The API is definitionally healthy if it is able to answer.
            return ComponentCheck(name="api", state=HealthState.HEALTHY, latency_ms=0)

        return {
            "api": _api,
            "database": self._state.database.probe,
            "redis": self._state.redis.probe,
        }

    async def readiness(self) -> HealthResponse:
        """Probe required dependencies only.

        Reports ``UNAVAILABLE`` — without probing — while the process is still
        starting up or is draining for shutdown. ``AppState.ready`` is the only
        signal that distinguishes those windows from steady state, and ignoring
        it would tell nginx to route traffic to a half-initialised instance (or
        keep routing to one that is closing its connections). Probing is skipped
        rather than merely overridden: during startup the pool may not exist yet,
        and a probe that blocks would delay the very answer an orchestrator is
        waiting for.
        """
        if not self._state.ready:
            return HealthResponse(
                status=HealthState.UNAVAILABLE,
                components={
                    "api": ComponentHealth(
                        state=HealthState.UNAVAILABLE,
                        latency_ms=None,
                        detail="startup incomplete or shutting down",
                    )
                },
            )

        results = await run_probes(self._required_probes())
        return HealthResponse(
            status=worst_state(results),
            components={name: self._to_schema(check) for name, check in results.items()},
        )

    async def full(self) -> HealthResponse:
        """Readiness plus informational components.

        ``status`` is still computed from required components only, so the
        presence of not-yet-shipped subsystems cannot make the platform look
        unhealthy.
        """
        required = await self.readiness()
        informational = {
            name: ComponentHealth(
                state=HealthState.DISABLED,
                latency_ms=None,
                detail=f"not implemented yet ({phase})",
            )
            for name, phase in INFORMATIONAL_COMPONENTS.items()
        }
        return HealthResponse(
            status=required.status,
            components={**required.components, **informational},
        )

    async def snapshot_components(self) -> dict[str, object]:
        """Serialisable component map for persisting a health snapshot (§10)."""
        report = await self.full()
        return {
            "status": report.status.value,
            "observed_at": utc_now().isoformat(),
            "components": {
                name: {
                    "state": check.state.value,
                    "latency_ms": check.latency_ms,
                    "detail": check.detail,
                }
                for name, check in report.components.items()
            },
        }

    @staticmethod
    def _to_schema(check: ComponentCheck) -> ComponentHealth:
        return ComponentHealth(state=check.state, latency_ms=check.latency_ms, detail=check.detail)
