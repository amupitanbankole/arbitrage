"""Audit-log persistence (§53).

**This repository has no ``update`` or ``delete`` method.** That is deliberate
and is the application-level half of the append-only guarantee; the database
trigger installed by the migration is the other half. Adding a mutation method
here would silently defeat both (§53, §83).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import Select, and_, select

from arb_persistence.models.audit import AuditLog
from arb_persistence.models.enums import AuditResult
from arb_persistence.repositories.base import PaginatedResult, Repository

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.pagination import PaginationParams

__all__ = ["AuditRepository"]


class AuditRepository(Repository[AuditLog]):
    """Write and query audit entries."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AuditLog)

    async def latest_for_resource(
        self,
        resource_type: str,
        resource_id: str,
        *,
        limit: int = 50,
    ) -> Sequence[AuditLog]:
        """Full history of one object, newest first (§50 execution timeline)."""
        statement = (
            select(AuditLog)
            .where(
                and_(
                    AuditLog.resource_type == resource_type,
                    AuditLog.resource_id == resource_id,
                )
            )
            .order_by(AuditLog.occurred_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(statement)
        return list(result.scalars().all())

    async def search(
        self,
        params: PaginationParams,
        *,
        action: str | None = None,
        actor_id: UUID | None = None,
        actor_type: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        result: AuditResult | None = None,
        occurred_from: datetime | None = None,
        occurred_to: datetime | None = None,
    ) -> PaginatedResult[AuditLog]:
        """Filter audit entries for the admin audit view (§45, §53, §97)."""
        criteria: list[Any] = []
        if action is not None:
            criteria.append(AuditLog.action == action)
        if actor_id is not None:
            criteria.append(AuditLog.actor_id == actor_id)
        if actor_type is not None:
            criteria.append(AuditLog.actor_type == actor_type)
        if resource_type is not None:
            criteria.append(AuditLog.resource_type == resource_type)
        if resource_id is not None:
            criteria.append(AuditLog.resource_id == resource_id)
        if result is not None:
            criteria.append(AuditLog.result == result)
        if occurred_from is not None:
            criteria.append(AuditLog.occurred_at >= occurred_from)
        if occurred_to is not None:
            criteria.append(AuditLog.occurred_at <= occurred_to)

        return await self.paginate(
            params, criteria=criteria, order_by=(AuditLog.occurred_at.desc(),)
        )

    async def count_denied_since(self, since: datetime) -> int:
        """Number of denied actions since ``since``.

        Feeds abnormal-activity detection: a burst of denials is the signature of
        privilege probing (§130).
        """
        return await self.count(
            and_(AuditLog.result == AuditResult.DENIED, AuditLog.occurred_at >= since)
        )

    def _base_select(self) -> Select[Any]:  # pragma: no cover - reserved for subclasses
        return select(AuditLog)
