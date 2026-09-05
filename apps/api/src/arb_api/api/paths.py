"""Public URL prefixes (§67).

The version segment is declared once, here — but it is applied on the router that
*owns* each route, never on an ancestor. That distinction is not stylistic.

When a router is included inside another router, FastAPI resolves the ancestor's
prefix at match time and the route object keeps only its own relative path. So
``scope["route"].path`` reports ``/system/info`` for a request that was actually
made to ``/api/v1/system/info`` — and ``scope["route"].path`` is precisely what
the access log and the Prometheus ``route`` label are built from
(:mod:`arb_api.middleware.request_context`).

Two consequences make that a correctness problem rather than a cosmetic one:

* An operator cannot join a metric series or a log line to an nginx access log,
  because the label names a path that cannot be requested.
* Routers nested under different ancestors collide. ``/api/v1/users/{user_id}``
  and the Phase 9 ``/api/v1/admin/users/{user_id}`` would both label as
  ``/users/{user_id}``, silently merging two unrelated endpoints into one series
  — and the admin one is exactly the series an operator would want to watch.

Hence: leaf routers spell their complete prefix, using these constants so the
version segment still has a single source of truth.
"""

from __future__ import annotations

from typing import Final

__all__ = ["API_V1_ADMIN_PREFIX", "API_V1_PREFIX"]

#: Version 1 of the public API. Every user-facing resource lives below it.
API_V1_PREFIX: Final[str] = "/api/v1"

#: Administrative resources (§41, §102). Mounted separately from the public tree
#: with its own permission-gated dependencies, so that a routing mistake cannot
#: place an admin endpoint behind ordinary user authorization. The prefix is
#: spelled out in full for the reason described in this module's docstring.
API_V1_ADMIN_PREFIX: Final[str] = f"{API_V1_PREFIX}/admin"
