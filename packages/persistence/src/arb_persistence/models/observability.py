"""Operational observability tables (§10, §54, §55).

Redis holds the *live* worker heartbeat so staleness is detectable in
milliseconds and survives a database blip (:mod:`arb_core.worker`). These tables
hold the *durable* record, which Redis cannot: history for the admin workers
page, capacity trends, and evidence of what was running when an incident
occurred (§128).

Retention differs by table (§83): heartbeats and health snapshots are high-volume
operational data and are pruned on a short window; audit logs are not pruned by
application code at all.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from arb_core.clock import utc_now
from arb_core.db import Base, JSONType, UTCDateTime, UUIDPrimaryKeyMixin
from arb_core.health import HealthState
from arb_persistence.models.enums import WorkerStatus, enum_column

__all__ = ["SystemHealthSnapshot", "WorkerHeartbeat"]


class WorkerHeartbeat(Base, UUIDPrimaryKeyMixin):
    """A durable snapshot of one worker's liveness and counters (§55)."""

    __tablename__ = "worker_heartbeats"
    __table_args__ = (
        # "latest heartbeat per role" — the admin workers page query.
        Index("ix_worker_heartbeats_role_last_heartbeat_at", "role", "last_heartbeat_at"),
        Index("ix_worker_heartbeats_last_heartbeat_at", "last_heartbeat_at"),
    )

    #: Registered role name, e.g. ``market-data``, ``execution``.
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    #: ``host:pid`` — distinguishes replicas of the same role.
    identity: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    pid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="")

    status: Mapped[WorkerStatus] = mapped_column(
        enum_column(WorkerStatus, name="worker_status"), nullable=False
    )

    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utc_now
    )

    #: Monotonic since process start; a reset indicates a restart (§140).
    jobs_processed: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    jobs_failed: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    #: Role-specific detail. Must not contain secrets (§133).
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    @property
    def uptime_seconds(self) -> int | None:
        """Seconds the worker has been running, or ``None`` if unknown."""
        if self.started_at is None:
            return None
        return max(0, int((utc_now() - self.started_at).total_seconds()))

    def __repr__(self) -> str:
        return f"<WorkerHeartbeat {self.role} {self.identity} {self.status}>"


class SystemHealthSnapshot(Base, UUIDPrimaryKeyMixin):
    """A point-in-time dependency health report for one service (§10, §111)."""

    __tablename__ = "system_health_snapshots"
    __table_args__ = (
        Index("ix_system_health_snapshots_service_observed_at", "service", "observed_at"),
        Index("ix_system_health_snapshots_observed_at", "observed_at"),
    )

    service: Mapped[str] = mapped_column(String(64), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)

    #: Worst component state at observation time (§78).
    status: Mapped[HealthState] = mapped_column(
        enum_column(HealthState, name="health_state"), nullable=False
    )

    #: Per-component detail. Mirrors the *public* health payload — state,
    #: latency and a safe description only. Connection strings, hostnames and
    #: driver versions are excluded because this data is surfaced in the admin
    #: UI and must not map the internal network (§111, §124).
    components: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)

    def __repr__(self) -> str:
        return f"<SystemHealthSnapshot {self.service} {self.status} @ {self.observed_at}>"
