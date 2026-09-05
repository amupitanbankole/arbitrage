"""Health reporting primitives (§78, §111).

Three endpoints are built on top of this module:

``/health/live``
    Liveness. The process is running and can serve traffic. Must **not** touch
    dependencies — a database outage should not make the orchestrator kill and
    restart an otherwise healthy API in a loop.

``/health/ready``
    Readiness. Dependencies required to serve traffic are reachable. Used by
    nginx and the orchestrator to decide whether to route to this instance.

``/health``
    Full detail for humans and monitoring, with internals omitted (§111).

States mirror the exchange-health vocabulary used elsewhere in the platform so
that one enum describes both a component and an exchange (§78): ``HEALTHY``,
``DEGRADED``, ``UNAVAILABLE``, ``DISABLED``.

Probes are time-boxed: a hung dependency must delay the health response by at
most ``timeout_seconds``, never indefinitely, otherwise a stalled database
connection makes the load balancer consider the whole fleet unhealthy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from arb_core.clock import duration_ms, utc_now

__all__ = [
    "ComponentCheck",
    "HealthProbe",
    "HealthReport",
    "HealthState",
    "run_probes",
    "worst_state",
]

_PROBE_TIMEOUT_SECONDS = 5.0


class HealthState(StrEnum):
    """Observed state of a component or dependency (§78)."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"

    @property
    def severity(self) -> int:
        """Ranking used to reduce many component states to one overall state."""
        return _SEVERITY[self]


_SEVERITY: dict[HealthState, int] = {
    HealthState.HEALTHY: 0,
    HealthState.DISABLED: 1,
    HealthState.DEGRADED: 2,
    HealthState.UNAVAILABLE: 3,
}


class ComponentCheck(BaseModel):
    """The result of probing one dependency."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    name: str
    state: HealthState
    #: Round-trip probe duration; ``None`` when the probe never completed.
    latency_ms: int | None = None
    #: Short, **non-sensitive** description. Never include connection strings,
    #: credentials or stack traces here — this reaches clients (§111).
    detail: str | None = None


HealthProbe = Callable[[], Awaitable[ComponentCheck]]


class HealthReport(BaseModel):
    """Aggregated health for a service instance."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    status: HealthState
    service: str
    environment: str
    version: str
    checked_at: str = Field(default_factory=lambda: utc_now().isoformat())
    uptime_seconds: int | None = None
    components: dict[str, ComponentCheck] = Field(default_factory=dict)

    def to_public(self, *, include_components: bool = True) -> dict[str, object]:
        """Serialise for an HTTP response.

        Exposes state, latency and the safe ``detail`` string only. Hostnames,
        ports, driver versions and pool statistics are deliberately excluded so
        that an unauthenticated ``/health`` request cannot be used to map the
        internal network (§111, §124).
        """
        payload: dict[str, object] = {"status": self.status.value}
        if include_components:
            payload["components"] = {
                name: {
                    "state": check.state.value,
                    "latency_ms": check.latency_ms,
                    "detail": check.detail,
                }
                for name, check in self.components.items()
            }
        return payload


def worst_state(states: Mapping[str, ComponentCheck]) -> HealthState:
    """Reduce component results to a single overall state."""
    if not states:
        return HealthState.HEALTHY
    return max((check.state for check in states.values()), key=lambda state: state.severity)


async def _run_probe(name: str, probe: HealthProbe, timeout_seconds: float) -> ComponentCheck:
    """Run one probe with a hard timeout, converting failure into a state."""
    started = utc_now()
    try:
        result = await asyncio.wait_for(probe(), timeout=timeout_seconds)
    except TimeoutError:
        return ComponentCheck(
            name=name,
            state=HealthState.UNAVAILABLE,
            latency_ms=duration_ms(started),
            detail=f"probe timed out after {timeout_seconds:.1f}s",
        )
    except asyncio.CancelledError:
        # Shutdown in progress: propagate so the caller stops cleanly rather
        # than reporting a healthy system on the way out.
        raise
    except Exception as exc:  # noqa: BLE001 - a probe must never crash the report
        return ComponentCheck(
            name=name,
            state=HealthState.UNAVAILABLE,
            latency_ms=duration_ms(started),
            # Exception *type* only. The message can contain a DSN with a
            # password (asyncpg and redis-py both do this) and must not be
            # exposed through a health endpoint (§111, §133).
            detail=f"probe failed: {type(exc).__name__}",
        )
    return result


async def run_probes(
    probes: Mapping[str, HealthProbe],
    *,
    timeout_seconds: float = _PROBE_TIMEOUT_SECONDS,
) -> dict[str, ComponentCheck]:
    """Run every probe concurrently and return results keyed by name."""
    if not probes:
        return {}
    results = await asyncio.gather(
        *(_run_probe(name, probe, timeout_seconds) for name, probe in probes.items())
    )
    return {result.name: result for result in results}
