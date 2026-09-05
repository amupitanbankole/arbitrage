"""Request correlation, access logging and API metrics (§61, §66, §112).

Implemented as pure ASGI middleware rather than ``BaseHTTPMiddleware``. The
``BaseHTTPMiddleware`` wrapper buffers the response body through a memory stream
and detaches the request from the surrounding task, which breaks streaming
responses and makes ``contextvars`` set inside a route invisible to middleware.
Both matter here: the WebSocket/SSE streaming endpoints (§40, §69) and the
request-scoped context this middleware establishes.

Every request gets an identifier that is:

* returned in ``X-Request-ID`` so a user can quote it to support,
* bound into the logging context so every log line for that request carries it,
* written into ``scope`` so exception handlers can include it even after this
  middleware has unwound (an unhandled exception is handled by Starlette's
  ``ServerErrorMiddleware``, which sits *outside* user middleware).

A client-supplied ``X-Request-ID`` is honoured — that is what makes end-to-end
tracing from the browser through the API to a worker possible — but only if it
matches a strict character allow-list. Accepting arbitrary bytes would allow log
injection: a header containing a newline can forge log lines (§61, §136).

Metric cardinality: the ``route`` label is the FastAPI route *template*, never
the concrete path, so unbounded per-object series cannot be created (§112). An
unmatched request is recorded as ``_unmatched``, which also stops a 404 scan from
inflating cardinality.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Any, Final

from starlette.datastructures import MutableHeaders

from arb_core.context import reset, set_value
from arb_core.identifiers import uuid7
from arb_core.log import get_logger

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["REQUEST_ID_HEADER", "REQUEST_ID_SCOPE_KEY", "RequestContextMiddleware"]

_logger = get_logger("arb_api.access")

REQUEST_ID_HEADER: Final[str] = "X-Request-ID"
#: Scope key used so exception handlers can recover the identifier after this
#: middleware has already reset its contextvar.
REQUEST_ID_SCOPE_KEY: Final[str] = "arb_request_id"

_MAX_REQUEST_ID_LENGTH: Final[int] = 128
_REQUEST_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def is_valid_request_id(value: str) -> bool:
    """Return ``True`` when a client-supplied identifier is safe to reuse."""
    return (
        bool(value)
        and len(value) <= _MAX_REQUEST_ID_LENGTH
        and bool(_REQUEST_ID_PATTERN.match(value))
    )


def request_id_from_scope(scope: Scope) -> str | None:
    """Read the request identifier recorded by this middleware."""
    value = scope.get(REQUEST_ID_SCOPE_KEY)
    return str(value) if value is not None else None


class RequestContextMiddleware:
    """Bind a request identifier, then log and meter the completed request."""

    def __init__(self, app: ASGIApp, *, service: str = "api") -> None:
        self.app = app
        self.service = service

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle one ASGI event stream."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = self._resolve_request_id(scope)
        scope[REQUEST_ID_SCOPE_KEY] = request_id

        method = str(scope.get("method", ""))
        path = str(scope.get("path", ""))
        client = scope.get("client")
        client_host = client[0] if isinstance(client, tuple) and client else None

        started = time.perf_counter()
        response_status = 500
        context_token = set_value("request_id", request_id)

        async def send_wrapper(message: Message) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            duration = time.perf_counter() - started
            self._record(
                scope=scope,
                method=method,
                path=path,
                status=500,
                duration=duration,
                client_host=client_host,
                request_id=request_id,
                exc_info=True,
            )
            raise
        else:
            duration = time.perf_counter() - started
            self._record(
                scope=scope,
                method=method,
                path=path,
                status=response_status,
                duration=duration,
                client_host=client_host,
                request_id=request_id,
            )
        finally:
            reset(context_token)

    def _resolve_request_id(self, scope: Scope) -> str:
        """Use a valid client-supplied identifier, otherwise mint one."""
        headers: list[tuple[bytes, bytes]] = list(scope.get("headers") or [])
        for raw_name, raw_value in headers:
            if raw_name.decode("latin-1").lower() != REQUEST_ID_HEADER.lower():
                continue
            candidate = raw_value.decode("latin-1").strip()
            if is_valid_request_id(candidate):
                return candidate
            _logger.warning(
                "rejected client-supplied request id; generated a new one",
                extra={"reason": "invalid_characters_or_length"},
            )
            break
        return str(uuid7())

    def _record(
        self,
        *,
        scope: Scope,
        method: str,
        path: str,
        status: int,
        duration: float,
        client_host: str | None,
        request_id: str,
        exc_info: bool = False,
    ) -> None:
        """Emit the access log line and the Prometheus observations."""
        route = getattr(scope.get("route"), "path", None)

        container = getattr(getattr(scope.get("app"), "state", None), "container", None)
        metrics = getattr(container, "metrics", None)
        if metrics is not None:
            metrics.observe_request(
                method=method, route=route, status=status, duration_seconds=duration
            )

        extra: dict[str, Any] = {
            "method": method,
            "path": path,
            "route": route or "_unmatched",
            "status": status,
            "duration_ms": round(duration * 1000, 3),
            "client_ip": client_host,
            # Passed explicitly rather than left to the ambient context: the
            # access log is the record an operator searches by request id (§66),
            # and a correlation field that silently vanishes when a contextvar is
            # cleared is worse than one that is merely redundant.
            "request_id": request_id,
        }
        message = "request completed"
        if status >= 500:
            _logger.error(message, extra=extra, exc_info=exc_info)
        elif status >= 400:
            _logger.warning(message, extra=extra)
        else:
            _logger.info(message, extra=extra)
