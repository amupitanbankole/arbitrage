"""Server-side pagination (§97).

``MAX_PAGE_SIZE`` is a denial-of-service control as much as a UX one: without it
any authenticated caller can request the entire ``orders`` table in one query.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from arb_core.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Page, PaginationParams


class Item(BaseModel):
    name: str


class TestPaginationParams:
    def test_defaults(self) -> None:
        params = PaginationParams()
        assert params.page == 1
        assert params.page_size == DEFAULT_PAGE_SIZE
        assert params.offset == 0
        assert params.limit == DEFAULT_PAGE_SIZE

    @pytest.mark.parametrize(
        ("page", "page_size", "offset"),
        [(1, 10, 0), (2, 10, 10), (3, 25, 50), (100, 200, 19800)],
    )
    def test_offset_arithmetic(self, page: int, page_size: int, offset: int) -> None:
        params = PaginationParams(page=page, page_size=page_size)
        assert params.offset == offset
        assert params.limit == page_size

    @pytest.mark.parametrize("page", [0, -1, -100])
    def test_rejects_non_positive_page(self, page: int) -> None:
        with pytest.raises(ValidationError):
            PaginationParams(page=page)

    @pytest.mark.parametrize("page_size", [0, -1])
    def test_rejects_non_positive_page_size(self, page_size: int) -> None:
        with pytest.raises(ValidationError):
            PaginationParams(page_size=page_size)

    def test_rejects_page_size_above_the_cap(self) -> None:
        """Unbounded limits are how a list endpoint becomes an outage."""
        with pytest.raises(ValidationError):
            PaginationParams(page_size=MAX_PAGE_SIZE + 1)
        with pytest.raises(ValidationError):
            PaginationParams(page_size=1_000_000)

    def test_accepts_the_cap_itself(self) -> None:
        assert PaginationParams(page_size=MAX_PAGE_SIZE).limit == MAX_PAGE_SIZE

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            PaginationParams(page=1, order_by="DROP TABLE users")  # type: ignore[call-arg]

    def test_is_immutable(self) -> None:
        params = PaginationParams()
        with pytest.raises(ValidationError):
            params.page = 5  # type: ignore[misc]


class TestPage:
    def test_total_pages_and_has_more(self) -> None:
        page = Page[Item](items=[], total=95, page=1, page_size=10)
        assert page.total_pages == 10
        assert page.has_more is True

        last = Page[Item](items=[], total=95, page=10, page_size=10)
        assert last.has_more is False

    def test_exact_multiple(self) -> None:
        page = Page[Item](items=[], total=100, page=10, page_size=10)
        assert page.total_pages == 10
        assert page.has_more is False

    def test_empty_result_still_reports_one_page(self) -> None:
        page = Page[Item](items=[], total=0, page=1, page_size=50)
        assert page.total_pages == 1
        assert page.has_more is False

    def test_create_from_params(self) -> None:
        params = PaginationParams(page=2, page_size=25)
        page = Page.create([Item(name="a")], total=60, params=params)
        assert page.page == 2
        assert page.page_size == 25
        assert page.total == 60
        assert page.total_pages == 3

    def test_empty_helper(self) -> None:
        params = PaginationParams(page=4, page_size=10)
        page = Page.empty(params)
        assert page.items == []
        assert page.total == 0
        assert page.page == 4

    def test_serialises_the_documented_envelope(self) -> None:
        """§97 — clients rely on these exact field names."""
        page = Page.create([Item(name="btc")], total=1, params=PaginationParams())
        payload = page.model_dump()
        assert set(payload) == {
            "items",
            "total",
            "page",
            "page_size",
            "total_pages",
            "has_more",
        }

    def test_negative_total_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Page[Item](items=[], total=-1, page=1, page_size=10)


class TestApiEnvelopeParity:
    def test_matches_the_openapi_contract_shape(self) -> None:
        """The internal Page and the API PaginatedResponse must not drift."""
        from arb_api.schemas.common import PaginatedResponse

        params = PaginationParams(page=1, page_size=10)
        internal = Page.create([{"name": "btc"}], total=42, params=params)
        external = PaginatedResponse[dict[str, str]].from_page(internal)
        assert external.model_dump() == internal.model_dump()
