"""Health endpoint contracts (§111).

The schemas encode the important omission as much as the inclusion: there is no
field for a hostname, port, driver version, pool statistic or error message from
a dependency. ``/health`` is unauthenticated by design so that nginx and the
orchestrator can probe it, which means anything it returns is public.

``detail`` is a short, hand-written, non-sensitive string. It is never a
verbatim exception message, because driver exceptions routinely embed the
connection string — including the password (§133).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from arb_core.health import HealthState

__all__ = ["ComponentHealth", "HealthResponse", "LivenessResponse"]


class ComponentHealth(BaseModel):
    """Public view of one dependency."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    state: HealthState = Field(description="HEALTHY | DEGRADED | UNAVAILABLE | DISABLED")
    latency_ms: int | None = Field(
        default=None, description="Probe round-trip in milliseconds, if measured."
    )
    detail: str | None = Field(
        default=None, description="Short non-sensitive explanation. Never an exception message."
    )


class HealthResponse(BaseModel):
    """Aggregated readiness / health payload."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    status: HealthState = Field(description="Worst state across all components.")
    components: dict[str, ComponentHealth] = Field(default_factory=dict)


class LivenessResponse(BaseModel):
    """``/health/live`` — deliberately dependency-free (§111).

    Reporting liveness from dependency state would cause an orchestrator to
    restart a healthy process during a database outage, turning a partial outage
    into a full one.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    status: str = Field(default="alive")
    uptime_seconds: int = Field(ge=0)
