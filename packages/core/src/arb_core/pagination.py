"""Server-side pagination (§97).

Every list endpoint in the platform paginates in the database. Loading a full
table into the browser is not acceptable for ``orders``, ``order_fills``,
``opportunities`` or ``audit_logs``, which grow without bound on a running
system — millions of rows within weeks.

The cap on ``page_size`` is a denial-of-service control as much as a UX one: an
unbounded limit lets any authenticated caller force an arbitrarily large query
and result serialisation.

``Page`` is generic over the item schema so a single implementation serves every
list endpoint and the OpenAPI document shows a consistent envelope (§67, §68).
"""

from __future__ import annotations

from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, computed_field

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "Page",
    "PaginationParams",
]

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Validated pagination request parameters."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    page: int = Field(default=1, ge=1, description="1-based page number.")
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Rows per page. Capped at {MAX_PAGE_SIZE}.",
    )

    @property
    def offset(self) -> int:
        """Row offset for a SQL ``OFFSET`` clause."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Row limit for a SQL ``LIMIT`` clause."""
        return self.page_size


class Page(BaseModel, Generic[T]):
    """One page of results plus the totals needed to render a pager."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    items: list[T] = Field(default_factory=list)
    total: int = Field(ge=0, description="Total matching rows across all pages.")
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_pages(self) -> int:
        """Number of pages available, at least 1."""
        if self.page_size <= 0:
            return 1
        return max(1, -(-self.total // self.page_size))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_more(self) -> bool:
        """``True`` when a further page exists."""
        return self.page < self.total_pages

    @classmethod
    def create(
        cls,
        items: list[Any],
        *,
        total: int,
        params: PaginationParams,
    ) -> Page[Any]:
        """Build a page from already-serialised items."""
        return cls(items=items, total=total, page=params.page, page_size=params.page_size)

    @classmethod
    def empty(cls, params: PaginationParams) -> Page[Any]:
        """An empty page with correct metadata."""
        return cls(items=[], total=0, page=params.page, page_size=params.page_size)
