"""Shared API response contracts (§67, §68, §71, §97).

These schemas exist so the OpenAPI document at ``/docs`` describes the real
wire format. A client that codes against ``/docs`` must not discover an
undocumented envelope at runtime.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from arb_core.pagination import Page

__all__ = [
    "ApiIndex",
    "ErrorDetail",
    "ErrorEnvelope",
    "MessageResponse",
    "PaginatedResponse",
    "ResourceGroup",
]

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """The single error object returned by every failure path (§71)."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(
        description=(
            "Stable machine-readable identifier from arb_core.errors.ErrorCode. "
            "Match on this, never on the message text."
        ),
        examples=["ORDER_SUBMISSION_FAILED"],
    )
    message: str = Field(description="Human-readable and safe to display.")
    request_id: str | None = Field(
        default=None,
        description="Quote this when contacting support; it locates the server log entry.",
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional non-sensitive structured detail, e.g. per-field validation "
            "errors. Never contains submitted values."
        ),
    )


class ErrorEnvelope(BaseModel):
    """Wrapper matching the §71 response shape exactly."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    error: ErrorDetail


class MessageResponse(BaseModel):
    """Simple acknowledgement payload."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    message: str
    code: str | None = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Concrete pagination envelope for OpenAPI (§97).

    ``arb_core.pagination.Page`` is the internal carrier; this is the documented
    API shape. They are structurally identical, which is asserted by a test so
    the two cannot drift apart.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    items: list[T] = Field(default_factory=list)
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total_pages: int = Field(ge=1)
    has_more: bool

    @classmethod
    def from_page(cls, page: Page[Any]) -> PaginatedResponse[Any]:
        """Convert an internal page into the API envelope."""
        return cls(
            items=list(page.items),
            total=page.total,
            page=page.page,
            page_size=page.page_size,
            total_pages=page.total_pages,
            has_more=page.has_more,
        )


class ResourceGroup(BaseModel):
    """One API resource group and its delivery status.

    ``status`` is one of the four labels §151 requires — ``IMPLEMENTED``,
    ``PARTIALLY IMPLEMENTED``, ``MOCKED``, ``NOT IMPLEMENTED`` — so a client (or
    an operator with curl) can tell "not built yet" apart from "built and
    broken" without reading the changelog.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    name: str
    path: str | None = Field(default=None, description="Mounted path, or None while unimplemented.")
    status: str
    phase: str | None = Field(default=None, description="Phase that delivers this group.")


class ApiIndex(BaseModel):
    """``GET /api/v1`` — what this version of the API actually offers.

    The root document advertises ``/api/v1`` as the entry point, so that path
    must answer rather than 404: an operator following the link during an
    incident who gets a 404 concludes the API is down (§128).
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    api_version: str
    service: str
    environment: str
    resources: list[ResourceGroup] = Field(default_factory=list)
