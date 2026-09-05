"""The Prometheus scrape endpoint (§54, §112).

Verified against the *injected* registry rather than the process-wide default.
That distinction is the point: a ``Metrics`` instance bound to the global
``REGISTRY`` would accumulate counters from every app built during a test run
and, in production, from any library that registers its own collectors — so
``/metrics`` would report numbers that no single service produced.

The security-facing behaviour of this endpoint (hidden when disabled, bearer
token required) lives in ``tests/security/test_endpoint_security.py``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest
from prometheus_client import REGISTRY, Counter

from arb_core.metrics import Metrics
from tests.support.apps import build_app, build_client, build_container

if TYPE_CHECKING:
    from httpx import AsyncClient

    from arb_core.config import Settings
    from arb_core.db.session import Database
    from arb_core.redis.client import RedisClient


async def _scrape(client: AsyncClient) -> str:
    """GET /metrics and return the decoded exposition text."""
    response = await client.get("/metrics")
    assert response.status_code == 200
    return response.text


@pytest.fixture
async def metrics_client(
    settings: Settings, database: Database, redis_client: RedisClient, metrics: Metrics
) -> Any:
    """A client whose container carries an explicit, isolated registry."""
    container = build_container(settings, database=database, redis=redis_client, metrics=metrics)
    async with build_client(build_app(container)) as client:
        yield client


class TestExposition:
    async def test_returns_the_prometheus_content_type(self, metrics_client: AsyncClient) -> None:
        response = await metrics_client.get("/metrics")

        assert response.status_code == 200
        assert response.headers["content-type"] == Metrics.content_type()
        assert response.headers["content-type"].startswith("text/plain")

    async def test_body_is_valid_text_exposition_format(self, metrics_client: AsyncClient) -> None:
        body = await _scrape(metrics_client)

        assert "# HELP" in body
        assert "# TYPE" in body
        # Every collector is namespaced, so unnamespaced platform metrics cannot
        # collide with a library's own (§112).
        assert "arb_api_requests_total" in body
        assert "arb_api_request_latency_seconds" in body

    async def test_histogram_buckets_are_exposed(self, metrics_client: AsyncClient) -> None:
        """Buckets appear once a label set has been observed.

        A labelled histogram has no children until ``.labels()`` is called, so a
        freshly started process advertises only ``# HELP``/``# TYPE`` for it.
        That is prometheus_client behaviour, not a missing metric — asserting it
        explicitly stops someone "fixing" the endpoint by pre-warming label
        sets, which would create series for routes never served.
        """
        before = await _scrape(metrics_client)
        assert "# TYPE arb_api_request_latency_seconds histogram" in before
        assert 'arb_api_request_latency_seconds_bucket{le="' not in before

        await metrics_client.get("/health/live")
        body = await _scrape(metrics_client)

        assert 'arb_api_request_latency_seconds_bucket{le="' in body
        assert 'le="+Inf"' in body

    async def test_security_headers_are_present(self, metrics_client: AsyncClient) -> None:
        """A scraper is still a client; the platform defaults apply (§87)."""
        response = await metrics_client.get("/metrics")

        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store, max-age=0"

    async def test_excluded_from_the_openapi_document(self, metrics_client: AsyncClient) -> None:
        """It serves text, not JSON, so documenting it as an operation misleads."""
        document = (await metrics_client.get("/openapi.json")).json()

        assert "/metrics" not in document["paths"]


class TestRegistryIsolation:
    async def test_reflects_the_injected_registry(
        self, metrics_client: AsyncClient, metrics: Metrics
    ) -> None:
        metrics.api_requests_total.labels(method="GET", route="/health/live", status="200").inc()

        body = await _scrape(metrics_client)

        assert 'arb_api_requests_total{method="GET",route="/health/live",status="200"} 1.0' in body

    async def test_ignores_the_process_wide_default_registry(
        self, metrics_client: AsyncClient
    ) -> None:
        """A collector on the global REGISTRY must not leak into this service."""
        counter = Counter(
            "test_only_global_collector_total",
            "Registered on the process-wide default registry.",
            registry=REGISTRY,
        )
        counter.inc()

        body = await _scrape(metrics_client)

        assert "test_only_global_collector_total" not in body

    async def test_two_apps_do_not_share_counters(
        self,
        settings: Settings,
        database: Database,
        redis_client: RedisClient,
    ) -> None:
        """Each container gets its own registry, so counts stay attributable."""
        first = Metrics()
        second = Metrics()
        first.api_requests_total.labels(method="GET", route="/first", status="200").inc()

        first_client = build_client(
            build_app(
                build_container(settings, database=database, redis=redis_client, metrics=first)
            )
        )
        second_client = build_client(
            build_app(
                build_container(settings, database=database, redis=redis_client, metrics=second)
            )
        )
        async with first_client as a, second_client as b:
            first_body = await _scrape(a)
            second_body = await _scrape(b)

        assert 'route="/first"' in first_body
        assert 'route="/first"' not in second_body


class TestRouteLabels:
    async def test_a_nested_v1_route_reports_its_full_public_path(
        self, metrics_client: AsyncClient
    ) -> None:
        """Regression guard for a truncated ``route`` label.

        FastAPI resolves an *ancestor* router's prefix at match time, so a route
        declared on a router nested inside ``APIRouter(prefix="/api/v1")`` kept
        only its relative path: ``scope["route"].path`` was ``/system/info`` for
        a request actually made to ``/api/v1/system/info``. Since that value
        feeds both the Prometheus label and the access log, the platform was
        labelling its traffic with a path nobody can request — and two routers
        nested under different ancestors (``/api/v1/users/{id}`` and the Phase 9
        ``/api/v1/admin/users/{id}``) would have collapsed into one series.

        Leaf routers now spell their complete prefix; see
        :mod:`arb_api.api.paths`.
        """
        await metrics_client.get("/api/v1/system/info")
        await metrics_client.get("/api/v1/system/workers")
        await metrics_client.get("/api/v1")

        body = await _scrape(metrics_client)

        for expected in ("/api/v1/system/info", "/api/v1/system/workers"):
            assert f'route="{expected}"' in body, f"{expected} was not labelled with its full path"
        # The truncated form must not exist at all, not merely alongside.
        assert 'route="/system/info"' not in body
        assert 'route="/system/workers"' not in body

    async def test_labels_match_the_paths_a_client_actually_requests(
        self, metrics_client: AsyncClient
    ) -> None:
        """Every labelled route must be a path in the OpenAPI document.

        This is the property that was broken, expressed so it cannot silently
        break again under a different router shape: if a label cannot be
        requested, an operator cannot correlate a metric with an access log.
        """
        document = (await metrics_client.get("/openapi.json")).json()
        documented = set(document["paths"])

        for path in sorted(documented):
            await metrics_client.get(path)

        body = await _scrape(metrics_client)
        labelled = set(re.findall(r'arb_api_requests_total\{[^}]*route="([^"]+)"', body))

        assert labelled, "no request was recorded"
        for label in labelled:
            assert label in documented or label == "_unmatched", (
                f"route label {label!r} is not a requestable path"
            )


class TestObservedRequests:
    async def test_handled_requests_are_counted(self, metrics_client: AsyncClient) -> None:
        await metrics_client.get("/health/live")

        body = await _scrape(metrics_client)

        assert 'arb_api_requests_total{method="GET",route="/health/live",status="200"}' in body

    async def test_unknown_paths_collapse_to_one_label(self, metrics_client: AsyncClient) -> None:
        """§112 — probing random URLs must not inflate Prometheus cardinality.

        Recording the concrete path would let an unauthenticated caller create
        an unbounded number of time series, which degrades the scrape and can
        exhaust the TSDB. Every miss shares the ``_unmatched`` label instead.
        """
        for path in ("/nope", "/also-nope", "/admin/secret-thing", "/a/b/c/d/e"):
            await metrics_client.get(path)

        body = await _scrape(metrics_client)

        assert 'route="_unmatched"' in body
        for path in ("/nope", "/also-nope", "/admin/secret-thing", "/a/b/c/d/e"):
            assert f'route="{path}"' not in body
        # The four misses are one series with a count, not four series.
        assert 'arb_api_requests_total{method="GET",route="_unmatched",status="404"} 4.0' in body

    async def test_error_responses_are_counted_too(self, metrics_client: AsyncClient) -> None:
        """Error rates are the signal that matters most during an incident."""
        await metrics_client.get("/does-not-exist")

        body = await _scrape(metrics_client)

        assert 'status="404"' in body

    async def test_latency_is_observed_for_handled_requests(
        self, metrics_client: AsyncClient
    ) -> None:
        await metrics_client.get("/health/live")

        body = await _scrape(metrics_client)

        assert (
            'arb_api_request_latency_seconds_count{method="GET",route="/health/live",status="200"}'
            in body
        )
        assert (
            'arb_api_request_latency_seconds_sum{method="GET",route="/health/live",status="200"}'
            in body
        )
