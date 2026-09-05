"""Uvicorn entrypoint for the API service (§86).

Run via the ``arb-api`` console script, or ``python -m arb_api.main``.

``log_config=None`` is important: uvicorn's default logging configuration calls
``dictConfig``, which **replaces** the handlers installed by
:func:`arb_core.log.configure_logging`. Without this, production logs would
silently revert to uvicorn's unstructured format and lose secret redaction
(§127). ``access_log=False`` follows for the same reason — every request is
already logged with a request identifier, route template and latency by
:class:`~arb_api.middleware.request_context.RequestContextMiddleware`, so
uvicorn's access log would duplicate it in a less useful format.
"""

from __future__ import annotations

import uvicorn

from arb_core.config import get_settings
from arb_core.log import get_logger

__all__ = ["run"]

_logger = get_logger("arb_api.main")

#: Seconds to let in-flight requests finish after SIGTERM. Long enough for a
#: request that is mid-transaction to commit, short enough that an orchestrator's
#: own kill timeout is not reached first (§140).
_GRACEFUL_SHUTDOWN_SECONDS = 30


def run() -> None:
    """Start the API server using configuration from the environment."""
    settings = get_settings()

    _logger.info(
        "starting api server",
        extra={
            "host": settings.api_host,
            "port": settings.api_port,
            "environment": settings.environment.value,
            "trust_proxy_headers": settings.trust_proxy_headers,
        },
    )

    uvicorn.run(
        "arb_api.app:create_app",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,
        access_log=False,
        # Do not advertise the server software (§124 minimal information).
        server_header=False,
        date_header=True,
        proxy_headers=settings.trust_proxy_headers,
        forwarded_allow_ips=settings.forwarded_allow_ips,
        timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_SECONDS,
    )


if __name__ == "__main__":
    run()
