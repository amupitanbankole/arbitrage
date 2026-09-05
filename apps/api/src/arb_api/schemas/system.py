"""System status contracts (§44, §48, §55).

These endpoints are unauthenticated in Phase 1 and therefore expose only values
that are safe to publish: the service name, version, environment, clock and the
state of the trading safety gates. The gates are public because the UI must show
``LIVE TRADING ACTIVE`` or ``GLOBAL KILL SWITCH`` banners before a user logs in
(§31, §48).

Worker summaries deliberately omit ``host``, ``pid`` and the ``host:pid``
identity. Those map the internal network and process topology, which is exactly
what §124 says not to expose. The admin API (Phase 9, permission-gated) will
return the fuller view to authorized operators.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from arb_persistence.models.enums import WorkerStatus

__all__ = ["SystemInfo", "WorkerSummary", "WorkersResponse"]


class SystemInfo(BaseModel):
    """Public platform status."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    service: str
    version: str
    environment: str
    server_time: str = Field(description="Current server time, ISO-8601 UTC (§75).")
    uptime_seconds: int = Field(ge=0)

    # --- Trading safety gates (§31, §48) ---
    live_trading_enabled: bool = Field(
        description=(
            "Global master gate. When false, no live order can be submitted "
            "anywhere in the platform regardless of any per-bot setting."
        )
    )
    global_kill_switch_enabled: bool = Field(
        description="When true, no new orders are submitted (§26)."
    )
    paper_trading_enabled: bool
    demo_mode: bool = Field(
        description="Simulated exchanges and market data; never touches real funds (§109)."
    )

    #: Human-readable label the UI renders verbatim, so the safety banner cannot
    #: be derived incorrectly by a client (§31).
    trading_mode_label: str


class WorkerSummary(BaseModel):
    """Public view of one worker instance (§55)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    role: str
    status: WorkerStatus
    last_heartbeat_at: str | None = None
    age_seconds: int | None = Field(default=None, description="Seconds since the last heartbeat.")
    jobs_processed: int = Field(ge=0, default=0)
    jobs_failed: int = Field(ge=0, default=0)
    stale: bool = Field(description="True when the heartbeat is older than the staleness window.")


class WorkersResponse(BaseModel):
    """Worker fleet summary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    items: list[WorkerSummary] = Field(default_factory=list)
    total: int = Field(ge=0)
    stale_after_seconds: int = Field(
        description="A worker missing heartbeats for this long is considered gone."
    )
