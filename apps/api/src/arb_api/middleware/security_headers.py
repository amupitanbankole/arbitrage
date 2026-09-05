"""Security response headers (§61, §87).

Applied to every response produced inside the middleware stack, including the
error envelopes for ``AppError``, ``HTTPException`` and validation failures,
because an error page that lacks ``X-Content-Type-Options`` is still a response
an attacker can try to reinterpret.

One case cannot be covered from here: Starlette installs ``ServerErrorMiddleware``
above every user middleware, so the 500 for a genuinely unhandled exception is
sent from outside this class. Those headers are attached by
:mod:`arb_api.middleware.error_handlers` instead, and a security test asserts the
union of the two paths.

``Strict-Transport-Security`` is emitted only when the deployment is actually
behind TLS. Sending HSTS over plain HTTP is ignored by browsers, but emitting it
conditionally keeps the intent explicit and prevents a development instance from
pinning a browser to HTTPS for a domain it does not own.

Headers are added with *setdefault* semantics: an individual route may override
(for example a future download endpoint needing a different ``Cache-Control``),
but the platform default is always the safe one.

``Cache-Control: no-store`` is not a formality here. Responses contain balances,
open orders and P&L. Without it, a shared proxy or a browser back-button cache
can disclose one user's financial position to the next (§132, §133).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.datastructures import MutableHeaders

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["SecurityHeadersMiddleware", "build_security_headers"]

#: Two years, per current browser preload-list requirements.
_HSTS_VALUE: Final[str] = "max-age=63072000; includeSubDomains; preload"

#: This API serves JSON only. A policy that permits nothing is strictly safer
#: than a permissive one and cannot break a JSON client. The Next.js frontend
#: sets its own policy, tuned for a document that loads scripts and styles.
_DEFAULT_CSP: Final[str] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

_PERMISSIONS_POLICY: Final[str] = (
    "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()"
)


def build_security_headers(
    *,
    hsts: bool = False,
    content_security_policy: str = _DEFAULT_CSP,
) -> dict[str, str]:
    """Return the header set for this deployment."""
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": content_security_policy,
        "Permissions-Policy": _PERMISSIONS_POLICY,
        "X-Permitted-Cross-Domain-Policies": "none",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        # Financial data must never be cached by a browser or intermediary.
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
    }
    if hsts:
        headers["Strict-Transport-Security"] = _HSTS_VALUE
    return headers


class SecurityHeadersMiddleware:
    """Attach security headers to every HTTP response."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts: bool = False,
        content_security_policy: str = _DEFAULT_CSP,
    ) -> None:
        self.app = app
        self.headers = build_security_headers(
            hsts=hsts, content_security_policy=content_security_policy
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Intercept ``http.response.start`` to inject headers."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                for name, value in self.headers.items():
                    # setdefault: a route-level value wins over the platform
                    # default, but the default is never simply absent.
                    if name not in response_headers:
                        response_headers[name] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)
