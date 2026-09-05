"""Error taxonomy and safe error serialisation (§71, §77).

Two rules drive this module:

1. **Users and clients never see internals.** No stack traces, no SQL, no
   exchange responses, no file paths. Every API failure is serialised through
   :func:`error_payload`, which emits only a stable machine-readable ``code``,
   a human-readable ``message`` and the ``request_id`` needed to find the
   detailed entry in the server log.

2. **Codes are a contract.** ``ErrorCode`` is the single registry of failure
   identifiers. Frontends, alerting rules and integration tests match on these
   strings, so a code must never be renamed or reused for a different meaning.
   Add new codes; do not repurpose old ones.

Retryability (§77) is expressed in the type hierarchy rather than by inspecting
strings: :class:`RetryableError` and :class:`NonRetryableError` are marker bases
that exchange adapters, DB access and worker loops use to decide whether to
back off and retry or to fail immediately. This matters most for order
submission, where a blind retry after an ambiguous timeout can create a
duplicate live order (§62).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, ClassVar, Final

__all__ = [
    "AppError",
    "AuthenticationError",
    "ConfigurationError",
    "ConflictError",
    "DependencyUnavailableError",
    "ErrorCode",
    "FeatureDisabledError",
    "NotFoundError",
    "PermissionDeniedError",
    "RateLimitedError",
    "RetryableError",
    "ServiceUnavailableError",
    "ValidationError",
    "error_payload",
    "http_status_for",
]


class ErrorCode(StrEnum):
    """Stable, client-visible failure identifiers.

    The value of each member is the string clients match on. Keep names and
    values identical so log searches and API contracts stay in sync.
    """

    # --- Generic ---
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    FEATURE_DISABLED = "FEATURE_DISABLED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"

    # --- Dependency / infrastructure (§111, §139) ---
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    REDIS_UNAVAILABLE = "REDIS_UNAVAILABLE"
    EXCHANGE_UNAVAILABLE = "EXCHANGE_UNAVAILABLE"
    MARKET_DATA_STALE = "MARKET_DATA_STALE"

    # --- Trading safety (§22, §25, §26, §29, §62) ---
    ORDER_SUBMISSION_FAILED = "ORDER_SUBMISSION_FAILED"
    ORDER_STATE_UNKNOWN = "ORDER_STATE_UNKNOWN"
    DUPLICATE_ORDER_PREVENTED = "DUPLICATE_ORDER_PREVENTED"
    INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
    INVALID_ORDER = "INVALID_ORDER"
    RISK_REJECTED = "RISK_REJECTED"
    CIRCUIT_BREAKER_OPEN = "CIRCUIT_BREAKER_OPEN"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    LEG_FAILURE = "LEG_FAILURE"
    RECONCILIATION_FAILED = "RECONCILIATION_FAILED"
    OPPORTUNITY_EXPIRED = "OPPORTUNITY_EXPIRED"
    TRADING_DISABLED = "TRADING_DISABLED"
    LIVE_TRADING_NOT_ACTIVATED = "LIVE_TRADING_NOT_ACTIVATED"


#: Default HTTP status for each code. Overridable per-raise via ``http_status``.
_DEFAULT_STATUS: Final[dict[ErrorCode, int]] = {
    ErrorCode.INTERNAL_ERROR: 500,
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.PERMISSION_DENIED: 403,
    ErrorCode.CONFLICT: 409,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.IDEMPOTENCY_CONFLICT: 409,
    ErrorCode.FEATURE_DISABLED: 403,
    ErrorCode.CONFIGURATION_ERROR: 500,
    ErrorCode.SERVICE_UNAVAILABLE: 503,
    ErrorCode.DATABASE_UNAVAILABLE: 503,
    ErrorCode.REDIS_UNAVAILABLE: 503,
    ErrorCode.EXCHANGE_UNAVAILABLE: 502,
    ErrorCode.MARKET_DATA_STALE: 409,
    ErrorCode.ORDER_SUBMISSION_FAILED: 502,
    ErrorCode.ORDER_STATE_UNKNOWN: 409,
    ErrorCode.DUPLICATE_ORDER_PREVENTED: 409,
    ErrorCode.INSUFFICIENT_BALANCE: 422,
    ErrorCode.INVALID_ORDER: 422,
    ErrorCode.RISK_REJECTED: 422,
    ErrorCode.CIRCUIT_BREAKER_OPEN: 503,
    ErrorCode.KILL_SWITCH_ACTIVE: 503,
    ErrorCode.LEG_FAILURE: 500,
    ErrorCode.RECONCILIATION_FAILED: 500,
    ErrorCode.OPPORTUNITY_EXPIRED: 410,
    ErrorCode.TRADING_DISABLED: 403,
    ErrorCode.LIVE_TRADING_NOT_ACTIVATED: 403,
}


def http_status_for(code: ErrorCode) -> int:
    """Return the default HTTP status code for ``code``."""
    return _DEFAULT_STATUS.get(code, 500)


class AppError(Exception):
    """Base class for every error the platform raises deliberately.

    ``message`` must be safe to show an end user. Put diagnostic detail in
    ``context`` — it is written to the structured log and is **never** returned
    in an API response.
    """

    code: ClassVar[ErrorCode] = ErrorCode.INTERNAL_ERROR
    default_message: ClassVar[str] = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: ErrorCode | None = None,
        http_status: int | None = None,
        details: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        resolved_code = code if code is not None else self.code
        super().__init__(message or self.default_message)
        # `code`/`default_message` are class-level Final constants; per-instance
        # values are stored under distinct names to avoid shadowing them.
        self.error_code: Final[ErrorCode] = resolved_code
        self.message: Final[str] = message or self.default_message
        self.http_status: Final[int] = http_status or http_status_for(resolved_code)
        #: Client-visible, non-sensitive structured detail (e.g. field errors).
        self.details: Final[dict[str, Any]] = details or {}
        #: Server-side only. Logged, never serialised to a client.
        self.context: Final[dict[str, Any]] = context or {}
        self.headers: Final[dict[str, str]] = headers or {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.error_code.value!r}, status={self.http_status})"


class RetryableError(AppError):
    """A transient failure that may succeed if retried with backoff (§77).

    Examples: network timeout, HTTP 429, temporary 5xx, WebSocket disconnect.
    """


class NonRetryableError(AppError):
    """A deterministic failure that will fail again identically (§77).

    Examples: invalid credentials, insufficient balance, unsupported market,
    permission denied. Retrying these wastes rate-limit budget and, for order
    submission, risks duplicate live orders.
    """


class ValidationError(AppError):
    """Request payload or parameters failed validation."""

    code: ClassVar[ErrorCode] = ErrorCode.VALIDATION_ERROR
    default_message: ClassVar[str] = "The request could not be validated."


class NotFoundError(AppError):
    """The requested resource does not exist or is not visible to the caller."""

    code: ClassVar[ErrorCode] = ErrorCode.NOT_FOUND
    default_message: ClassVar[str] = "The requested resource was not found."


class AuthenticationError(AppError):
    """The caller is not authenticated (missing/invalid/expired credentials)."""

    code: ClassVar[ErrorCode] = ErrorCode.UNAUTHENTICATED
    default_message: ClassVar[str] = "Authentication is required."

    def __init__(
        self,
        message: str | None = None,
        *,
        www_authenticate: str = "Bearer",
        **kwargs: Any,
    ) -> None:
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("WWW-Authenticate", www_authenticate)
        super().__init__(message, headers=headers, **kwargs)


class PermissionDeniedError(AppError):
    """The caller is authenticated but lacks the required permission (§43)."""

    code: ClassVar[ErrorCode] = ErrorCode.PERMISSION_DENIED
    default_message: ClassVar[str] = "You do not have permission to perform this action."


class ConflictError(AppError):
    """The request conflicts with current resource state."""

    code: ClassVar[ErrorCode] = ErrorCode.CONFLICT
    default_message: ClassVar[str] = "The request conflicts with the current state."


class RateLimitedError(RetryableError):
    """Too many requests; the client must back off (§61)."""

    code: ClassVar[ErrorCode] = ErrorCode.RATE_LIMITED
    default_message: ClassVar[str] = "Too many requests. Please slow down."


class FeatureDisabledError(NonRetryableError):
    """A feature flag or entitlement blocks this operation (§58)."""

    code: ClassVar[ErrorCode] = ErrorCode.FEATURE_DISABLED
    default_message: ClassVar[str] = "This feature is not enabled."


class ConfigurationError(AppError):
    """The service is misconfigured. Fails closed at startup where possible."""

    code: ClassVar[ErrorCode] = ErrorCode.CONFIGURATION_ERROR
    default_message: ClassVar[str] = "The service is misconfigured."


class DependencyUnavailableError(RetryableError):
    """A backing dependency (DB, Redis, exchange) is unavailable."""

    code: ClassVar[ErrorCode] = ErrorCode.SERVICE_UNAVAILABLE
    default_message: ClassVar[str] = "A required service is temporarily unavailable."


class ServiceUnavailableError(RetryableError):
    """The service itself cannot currently handle the request."""

    code: ClassVar[ErrorCode] = ErrorCode.SERVICE_UNAVAILABLE
    default_message: ClassVar[str] = "The service is temporarily unavailable."


def error_payload(
    exc: BaseException,
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build the client-safe error body described in §71.

    For an :class:`AppError` the stable code, safe message and any client-safe
    ``details`` are included. For anything else the response is deliberately
    generic: leaking an exception class name or message from a third-party
    library can disclose internals (§71, §136).
    """
    if isinstance(exc, AppError):
        payload: dict[str, Any] = {
            "error": {
                "code": exc.error_code.value,
                "message": exc.message,
                "request_id": request_id,
            }
        }
        if exc.details:
            payload["error"]["details"] = exc.details
        return payload

    return {
        "error": {
            "code": ErrorCode.INTERNAL_ERROR.value,
            "message": "An unexpected error occurred.",
            "request_id": request_id,
        }
    }
