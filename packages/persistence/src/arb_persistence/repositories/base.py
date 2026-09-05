"""Repository base and pagination result (§114, §115).

Repositories are the only layer that builds SQLAlchemy statements. Routers and
services call them by name, which keeps query logic reviewable in one place,
makes it mockable in unit tests, and stops N+1 access patterns from spreading
across the codebase.

A repository never commits. Transaction boundaries belong to the caller via
:func:`arb_core.db.Database.unit_of_work`, so a service can compose several
repository writes into one atomic operation (§63) — essential when a trade, its
orders, its P&L rows and its audit entry must all land together or not at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from sqlalchemy import Select, func, select

from arb_core.db import Base

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.pagination import PaginationParams

__all__ = ["PaginatedResult", "Repository"]

ModelT = TypeVar("ModelT", bound=Base)


@dataclass(frozen=True, slots=True)
class PaginatedResult(Generic[ModelT]):
    """ORM rows plus the total match count.

    Deliberately not a Pydantic model: it carries ORM entities. Services map it
    onto :class:`arb_core.pagination.Page` of a response schema, which keeps
    persistence types out of the API contract (§115).
    """

    items: Sequence[ModelT]
    total: int
    params: PaginationParams

    @property
    def has_more(self) -> bool:
        """``True`` when rows remain beyond this page."""
        return self.params.offset + len(self.items) < self.total


class Repository(Generic[ModelT]):
    """Common persistence operations for one model."""

    def __init__(self, session: AsyncSession, model: type[ModelT]) -> None:
        self._session = session
        self._model = model

    @property
    def session(self) -> AsyncSession:
        """The session this repository writes through."""
        return self._session

    @property
    def model(self) -> type[ModelT]:
        """The mapped class this repository manages."""
        return self._model

    def add(self, entity: ModelT) -> ModelT:
        """Stage ``entity`` for insertion. Does not flush or commit."""
        self._session.add(entity)
        return entity

    def add_all(self, entities: Sequence[ModelT]) -> None:
        """Stage several entities in one call (batched insert path, §81)."""
        self._session.add_all(list(entities))

    async def flush(self) -> None:
        """Emit pending SQL so server defaults and identities are populated."""
        await self._session.flush()

    async def get_by_id(self, entity_id: UUID) -> ModelT | None:
        """Fetch by primary key, or ``None`` when absent."""
        return await self._session.get(self._model, entity_id)

    async def count(self, *criteria: Any) -> int:
        """Count rows matching ``criteria``."""
        statement = select(func.count()).select_from(self._model)
        if criteria:
            statement = statement.where(*criteria)
        result = await self._session.execute(statement)
        return int(result.scalar_one())

    async def paginate(
        self,
        params: PaginationParams,
        *,
        criteria: Sequence[Any] = (),
        order_by: Sequence[Any] = (),
    ) -> PaginatedResult[ModelT]:
        """Fetch one page and the total match count (§97).

        The count and the page are two queries. They are not wrapped in a
        repeatable-read transaction, so on a busy table ``total`` can drift
        slightly from the returned page. That is an acceptable trade for list
        endpoints: forcing a stricter isolation level here would hold locks on
        the highest-volume tables in the system.
        """
        total = await self.count(*criteria)

        statement: Select[Any] = select(self._model)
        if criteria:
            statement = statement.where(*criteria)
        if order_by:
            statement = statement.order_by(*order_by)
        statement = statement.offset(params.offset).limit(params.limit)

        result = await self._session.execute(statement)
        items = list(result.scalars().all())
        return PaginatedResult(items=items, total=total, params=params)
