"""Worker heartbeat and system health persistence (§10, §54, §55, §83).

Live staleness detection reads Redis (:mod:`arb_core.worker`), which is fast and
survives a database blip. These repositories hold the durable history behind the
admin workers page and the retention sweep.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import and_, delete, func, select

from arb_persistence.models.observability import SystemHealthSnapshot, WorkerHeartbeat
from arb_persistence.repositories.base import PaginatedResult, Repository

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.pagination import PaginationParams
    from arb_persistence.models.enums import WorkerStatus

__all__ = ["SystemHealthRepository", "WorkerHeartbeatRepository"]


class WorkerHeartbeatRepository(Repository[WorkerHeartbeat]):
    """Durable worker liveness history."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, WorkerHeartbeat)

    async def latest_per_worker(self, *, limit: int = 200) -> Sequence[WorkerHeartbeat]:
        """Newest heartbeat for each ``role``/``identity`` pair (§55).

        Implemented with a grouped subquery join rather than PostgreSQL's
        ``DISTINCT ON`` so the identical query runs on SQLite in the test-suite.
        """
        latest = (
            select(
                WorkerHeartbeat.role.label("role"),
                WorkerHeartbeat.identity.label("identity"),
                func.max(WorkerHeartbeat.last_heartbeat_at).label("max_heartbeat"),
            )
            .group_by(WorkerHeartbeat.role, WorkerHeartbeat.identity)
            .subquery()
        )
        statement = (
            select(WorkerHeartbeat)
            .join(
                latest,
                and_(
                    WorkerHeartbeat.role == latest.c.role,
                    WorkerHeartbeat.identity == latest.c.identity,
                    WorkerHeartbeat.last_heartbeat_at == latest.c.max_heartbeat,
                ),
            )
            .order_by(WorkerHeartbeat.role, WorkerHeartbeat.identity)
            .limit(limit)
        )
        result = await self._session.execute(statement)
        rows = list(result.scalars().all())

        # Ties on identical timestamps can produce duplicates; collapse them so
        # the admin page never shows one worker twice.
        deduped: dict[tuple[str, str], WorkerHeartbeat] = {}
        for row in rows:
            deduped.setdefault((row.role, row.identity), row)
        return list(deduped.values())

    async def list_for_role(
        self,
        role: str,
        params: PaginationParams,
        *,
        status: WorkerStatus | None = None,
    ) -> PaginatedResult[WorkerHeartbeat]:
        """Paginated history for one role."""
        criteria: list[Any] = [WorkerHeartbeat.role == role]
        if status is not None:
            criteria.append(WorkerHeartbeat.status == status)
        return await self.paginate(
            params, criteria=criteria, order_by=(WorkerHeartbeat.last_heartbeat_at.desc(),)
        )

    async def prune_before(self, cutoff: datetime) -> int:
        """Delete heartbeats older than ``cutoff`` (§83). Returns rows removed."""
        statement = delete(WorkerHeartbeat).where(WorkerHeartbeat.last_heartbeat_at < cutoff)
        # A DML statement resolves to CursorResult at runtime, which is the type
        # that carries rowcount; AsyncSession.execute is annotated as the
        # read-oriented Result, so the narrowing is explicit here.
        result = cast("CursorResult[Any]", await self._session.execute(statement))
        return int(result.rowcount or 0)


class SystemHealthRepository(Repository[SystemHealthSnapshot]):
    """Durable dependency-health history."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, SystemHealthSnapshot)

    async def latest_for_service(self, service: str) -> SystemHealthSnapshot | None:
        """Most recent snapshot for one service."""
        statement = (
            select(SystemHealthSnapshot)
            .where(SystemHealthSnapshot.service == service)
            .order_by(SystemHealthSnapshot.observed_at.desc())
            .limit(1)
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def history(
        self, service: str, params: PaginationParams
    ) -> PaginatedResult[SystemHealthSnapshot]:
        """Paginated snapshot history, newest first."""
        return await self.paginate(
            params,
            criteria=(SystemHealthSnapshot.service == service,),
            order_by=(SystemHealthSnapshot.observed_at.desc(),),
        )

    async def prune_before(self, cutoff: datetime) -> int:
        """Delete snapshots older than ``cutoff`` (§83). Returns rows removed."""
        statement = delete(SystemHealthSnapshot).where(SystemHealthSnapshot.observed_at < cutoff)
        result = cast("CursorResult[Any]", await self._session.execute(statement))
        return int(result.rowcount or 0)
