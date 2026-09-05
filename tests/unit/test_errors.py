"""Error taxonomy and client-safe serialisation (§71, §77).

The security-relevant assertion here is the last one: an arbitrary exception —
the kind that carries a connection string, a SQL fragment or an exchange
response — must produce a generic payload. That is the difference between an
incident and a disclosure.
"""

from __future__ import annotations

import pytest

from arb_core.errors import (
    AppError,
    AuthenticationError,
    ConfigurationError,
    ConflictError,
    DependencyUnavailableError,
    ErrorCode,
    FeatureDisabledError,
    NonRetryableError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    RetryableError,
    ServiceUnavailableError,
    ValidationError,
    error_payload,
    http_status_for,
)


class TestStatusMapping:
    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            (ErrorCode.VALIDATION_ERROR, 422),
            (ErrorCode.NOT_FOUND, 404),
            (ErrorCode.UNAUTHENTICATED, 401),
            (ErrorCode.PERMISSION_DENIED, 403),
            (ErrorCode.CONFLICT, 409),
            (ErrorCode.RATE_LIMITED, 429),
            (ErrorCode.OPPORTUNITY_EXPIRED, 410),
            (ErrorCode.SERVICE_UNAVAILABLE, 503),
            (ErrorCode.EXCHANGE_UNAVAILABLE, 502),
            (ErrorCode.ORDER_SUBMISSION_FAILED, 502),
            (ErrorCode.KILL_SWITCH_ACTIVE, 503),
            (ErrorCode.INTERNAL_ERROR, 500),
        ],
    )
    def test_codes_map_to_expected_statuses(self, code: ErrorCode, expected: int) -> None:
        assert http_status_for(code) == expected

    def test_every_code_has_a_status(self) -> None:
        """A code without a mapping would silently become a 500."""
        for code in ErrorCode:
            assert 400 <= http_status_for(code) <= 599


class TestErrorClasses:
    @pytest.mark.parametrize(
        ("exc", "code", "status"),
        [
            (ValidationError(), ErrorCode.VALIDATION_ERROR, 422),
            (NotFoundError(), ErrorCode.NOT_FOUND, 404),
            (AuthenticationError(), ErrorCode.UNAUTHENTICATED, 401),
            (PermissionDeniedError(), ErrorCode.PERMISSION_DENIED, 403),
            (ConflictError(), ErrorCode.CONFLICT, 409),
            (RateLimitedError(), ErrorCode.RATE_LIMITED, 429),
            (FeatureDisabledError(), ErrorCode.FEATURE_DISABLED, 403),
            (ConfigurationError(), ErrorCode.CONFIGURATION_ERROR, 500),
            (ServiceUnavailableError(), ErrorCode.SERVICE_UNAVAILABLE, 503),
            (DependencyUnavailableError(), ErrorCode.SERVICE_UNAVAILABLE, 503),
        ],
    )
    def test_defaults(self, exc: AppError, code: ErrorCode, status: int) -> None:
        assert exc.error_code is code
        assert exc.http_status == status
        assert exc.message  # every error has a user-safe message

    def test_custom_message_and_code_override_defaults(self) -> None:
        exc = AppError("Custom", code=ErrorCode.INSUFFICIENT_BALANCE)
        assert exc.message == "Custom"
        assert exc.error_code is ErrorCode.INSUFFICIENT_BALANCE
        assert exc.http_status == 422

    def test_authentication_error_sets_www_authenticate(self) -> None:
        assert AuthenticationError().headers["WWW-Authenticate"] == "Bearer"
        custom = AuthenticationError(www_authenticate='Bearer realm="api"')
        assert custom.headers["WWW-Authenticate"] == 'Bearer realm="api"'

    def test_context_is_kept_separate_from_details(self) -> None:
        """``context`` is for logs; ``details`` is for the client."""
        exc = AppError(
            "Order rejected",
            details={"field": "quantity"},
            context={"exchange_response": "raw payload with a key"},
        )
        assert exc.details == {"field": "quantity"}
        assert "exchange_response" in exc.context
        payload = error_payload(exc)
        assert payload["error"]["details"] == {"field": "quantity"}
        assert "exchange_response" not in str(payload)

    def test_repr_contains_no_message(self) -> None:
        exc = AppError("secret-bearing message")
        assert "secret-bearing message" not in repr(exc)


class TestRetryability:
    """§77: retryable and non-retryable failures must be distinguishable by type."""

    def test_transient_failures_are_retryable(self) -> None:
        assert isinstance(RateLimitedError(), RetryableError)
        assert isinstance(ServiceUnavailableError(), RetryableError)
        assert isinstance(DependencyUnavailableError(), RetryableError)

    def test_deterministic_failures_are_not_retryable(self) -> None:
        assert isinstance(FeatureDisabledError(), NonRetryableError)
        assert not isinstance(FeatureDisabledError(), RetryableError)

    def test_both_are_app_errors(self) -> None:
        assert isinstance(RetryableError(), AppError)
        assert isinstance(NonRetryableError(), AppError)


class TestErrorPayload:
    def test_matches_the_documented_shape(self) -> None:
        """§71 specifies this exact structure."""
        payload = error_payload(
            AppError("The order could not be submitted.", code=ErrorCode.ORDER_SUBMISSION_FAILED),
            request_id="req_123",
        )
        assert payload == {
            "error": {
                "code": "ORDER_SUBMISSION_FAILED",
                "message": "The order could not be submitted.",
                "request_id": "req_123",
            }
        }

    def test_unknown_exception_produces_a_generic_payload(self) -> None:
        """The critical case: internals must never reach a client."""
        exc = RuntimeError(
            "connection to postgresql://arb:sup3rs3cret@db:5432/x failed: "
            'FATAL: password authentication failed for "arb" '
            "Traceback: File '/app/arb_api/services/trading.py', line 42"
        )
        payload = error_payload(exc, request_id="req_9")
        serialised = str(payload)

        assert payload["error"]["code"] == "INTERNAL_ERROR"
        assert payload["error"]["message"] == "An unexpected error occurred."
        assert "sup3rs3cret" not in serialised
        assert "postgresql" not in serialised
        assert "Traceback" not in serialised
        assert "trading.py" not in serialised

    @pytest.mark.parametrize(
        "exc",
        [
            KeyError("api_secret"),
            ValueError("bad value from password=hunter2"),
            OSError("permission denied: /etc/shadow"),
            TypeError("NoneType"),
        ],
    )
    def test_arbitrary_exceptions_are_never_echoed(self, exc: Exception) -> None:
        payload = error_payload(exc)
        assert payload["error"]["code"] == "INTERNAL_ERROR"
        assert str(exc) not in str(payload)

    def test_missing_request_id_is_tolerated(self) -> None:
        payload = error_payload(NotFoundError("x"))
        assert payload["error"]["request_id"] is None

    def test_empty_details_are_omitted(self) -> None:
        payload = error_payload(NotFoundError("x"))
        assert "details" not in payload["error"]
