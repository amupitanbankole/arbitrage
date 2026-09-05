"""HTTP middleware and exception handlers (§61, §71)."""

from __future__ import annotations

from arb_api.middleware.error_handlers import register_exception_handlers
from arb_api.middleware.request_context import (
    REQUEST_ID_HEADER,
    RequestContextMiddleware,
    is_valid_request_id,
    request_id_from_scope,
)
from arb_api.middleware.security_headers import (
    SecurityHeadersMiddleware,
    build_security_headers,
)

__all__ = [
    "REQUEST_ID_HEADER",
    "RequestContextMiddleware",
    "SecurityHeadersMiddleware",
    "build_security_headers",
    "is_valid_request_id",
    "register_exception_handlers",
    "request_id_from_scope",
]
