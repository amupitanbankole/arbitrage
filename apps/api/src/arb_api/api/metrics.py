"""Prometheus scrape endpoint (§54, §112).

Excluded from the OpenAPI document: it returns the Prometheus text exposition
format, not JSON, so documenting it as an API operation would be misleading.

Two protections:

* **Disabled means hidden.** When ``METRICS_ENABLED`` is false the endpoint
  returns 404 rather than 403, so its existence is not disclosed.
* **Constant-time token comparison.** When ``METRICS_AUTH_TOKEN`` is set the
  bearer token is compared with :func:`secrets.compare_digest`. A ``==``
  comparison short-circuits on the first differing byte, which leaks token
  content through response timing.

Metrics contain no user data and no secrets, but they do reveal traffic shape,
error rates and which exchanges are in use — useful reconnaissance, which is why
production should either set a token or restrict scraping to the internal
network (§124).
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Request, Response

from arb_api.state import StateDep
from arb_core.errors import AuthenticationError, NotFoundError

__all__ = ["router"]

router = APIRouter(tags=["monitoring"])

_METRICS_DISABLED_MESSAGE = "Not found."


@router.get("/metrics", include_in_schema=False)
async def metrics(state: StateDep, request: Request) -> Response:
    """Return Prometheus metrics for this process."""
    settings = state.settings

    if not settings.metrics_enabled:
        # Same shape as any other unknown path: do not confirm the endpoint exists.
        raise NotFoundError(_METRICS_DISABLED_MESSAGE)

    expected = settings.metrics_auth_token.get_secret_value()
    if expected:
        presented = request.headers.get("authorization", "")
        if not secrets.compare_digest(presented, f"Bearer {expected}"):
            raise AuthenticationError("A valid bearer token is required for metrics.")

    return Response(content=state.metrics.render(), media_type=state.metrics.content_type())
