"""Exception handlers producing client-safe error envelopes (§71, §133).

Every failure — including ones nobody anticipated — leaves the API as::

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

No stack traces, no SQL, no driver messages, no file paths, no exchange
responses. The detail an operator needs is in the structured log, correlated by
``request_id``.

The request-validation handler deserves specific attention. Pydantic's
``errors()`` includes an ``input`` field containing **the value the client
sent**. For a registration or credential-connection payload that is a password
or an exchange API secret. Those entries are stripped here so a mistyped field
cannot cause a secret to be echoed back into a response, a log or a browser
network panel (§133).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, TypeAlias, cast

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from arb_api.middleware.request_context import REQUEST_ID_HEADER, request_id_from_scope
from arb_core.errors import AppError, ErrorCode, error_payload
from arb_core.log import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

#: Starlette stores exception handlers in one dict keyed by exception class, so
#: its ``add_exception_handler`` signature is deliberately general. This is the
#: narrowed shape our handlers actually have (see ``register_exception_handlers``).
ExceptionHandler: TypeAlias = "Callable[[Request[Any], Exception], Awaitable[JSONResponse]]"

__all__ = ["register_exception_handlers"]

_logger = get_logger("arb_api.errors")

#: Fields of a pydantic error dict that are safe to return. ``input`` and ``ctx``
#: are excluded on purpose — they can contain submitted secrets.
_SAFE_VALIDATION_FIELDS: Final[tuple[str, ...]] = ("loc", "msg", "type")

_MAX_VALIDATION_ERRORS: Final[int] = 50


def _request_id(request: Request) -> str | None:
    return request_id_from_scope(request.scope)


def _json_response(
    request: Request,
    exc: BaseException,
    *,
    status_code: int | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build the standard error response, echoing the request identifier."""
    request_id = _request_id(request)
    resolved_status = status_code
    if resolved_status is None:
        # AppError carries `http_status`, derived from its ErrorCode. There is no
        # `status_code` attribute: reading one here would raise AttributeError
        # *inside* the error handler, replacing a clean JSON envelope with an
        # opaque 500 at exactly the moment a client needs the real error.
        resolved_status = exc.http_status if isinstance(exc, AppError) else 500

    response_headers = dict(headers or {})
    if isinstance(exc, AppError) and exc.headers:
        response_headers.update(exc.headers)
    if request_id:
        response_headers[REQUEST_ID_HEADER] = request_id

    return JSONResponse(
        status_code=resolved_status,
        content=error_payload(exc, request_id=request_id),
        headers=response_headers,
    )


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Handle every deliberate platform error."""
    if exc.http_status >= 500:
        _logger.error(
            exc.message,
            extra={
                "error_code": exc.error_code.value,
                "path": request.url.path,
                "context": exc.context,
            },
        )
    elif exc.http_status >= 400:
        _logger.warning(
            exc.message,
            extra={
                "error_code": exc.error_code.value,
                "path": request.url.path,
                "context": exc.context,
            },
        )
    return _json_response(request, exc, status_code=exc.http_status)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Normalise framework-level HTTP errors into the same envelope."""
    code = _code_for_status(exc.status_code)
    message = exc.detail if isinstance(exc.detail, str) else code.default_message
    normalised = AppError(message, code=code, http_status=exc.status_code)
    return _json_response(
        request, normalised, status_code=exc.status_code, headers=dict(exc.headers or {})
    )


async def request_validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return field errors without echoing submitted values (§133)."""
    errors: list[dict[str, Any]] = []
    for raw in exc.errors()[:_MAX_VALIDATION_ERRORS]:
        safe: dict[str, Any] = {}
        for field in _SAFE_VALIDATION_FIELDS:
            if field in raw:
                value = raw[field]
                if field == "loc":
                    # Locations can contain an integer index; stringify for JSON.
                    value = [str(part) for part in value]
                safe[field] = value
        errors.append(safe)

    truncated = len(exc.errors()) > _MAX_VALIDATION_ERRORS
    _logger.warning(
        "request validation failed",
        extra={
            "path": request.url.path,
            "error_count": len(exc.errors()),
            "error_fields": [str(e.get("loc")) for e in errors],
        },
    )

    normalised = AppError(
        "The request could not be validated.",
        code=ErrorCode.VALIDATION_ERROR,
        http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        details={"errors": errors, "truncated": truncated},
    )
    return _json_response(request, normalised, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


async def unhandled_exception_handler(
    request: Request,
    # FastAPI calls every exception handler with (request, exc); the signature is
    # not ours to narrow, and the exception is logged with full context by
    # _logger.exception above rather than being interpolated into the response.
    exc: Exception,  # noqa: ARG001
) -> JSONResponse:
    """Last resort: log everything, reveal nothing (§71)."""
    _logger.exception(
        "unhandled exception while processing request",
        extra={"path": request.url.path, "method": request.method},
    )
    normalised = AppError(
        "An unexpected error occurred.",
        code=ErrorCode.INTERNAL_ERROR,
        http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
    return _json_response(request, normalised, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _code_for_status(status_code: int) -> ErrorCode:
    """Map an HTTP status to the closest stable error code."""
    mapping: dict[int, ErrorCode] = {
        400: ErrorCode.VALIDATION_ERROR,
        401: ErrorCode.UNAUTHENTICATED,
        403: ErrorCode.PERMISSION_DENIED,
        404: ErrorCode.NOT_FOUND,
        409: ErrorCode.CONFLICT,
        410: ErrorCode.OPPORTUNITY_EXPIRED,
        422: ErrorCode.VALIDATION_ERROR,
        429: ErrorCode.RATE_LIMITED,
        502: ErrorCode.EXCHANGE_UNAVAILABLE,
        503: ErrorCode.SERVICE_UNAVAILABLE,
    }
    return mapping.get(status_code, ErrorCode.INTERNAL_ERROR)


def register_exception_handlers(app: FastAPI) -> None:
    """Install every handler on ``app``.

    Starlette types ``add_exception_handler`` as taking
    ``Callable[[Request, Exception], ...]`` because it stores handlers in one
    dict keyed by exception class. Each handler here declares the *narrow* type
    it is registered for, which is what makes the mapping reviewable; the cast at
    registration is the boundary between our precise signatures and Starlette's
    general one, and is safe because Starlette only ever calls a handler with an
    instance of the class it was registered against.
    """
    app.add_exception_handler(AppError, cast("ExceptionHandler", app_error_handler))
    app.add_exception_handler(
        StarletteHTTPException, cast("ExceptionHandler", http_exception_handler)
    )
    app.add_exception_handler(
        RequestValidationError, cast("ExceptionHandler", request_validation_handler)
    )
    app.add_exception_handler(Exception, unhandled_exception_handler)
