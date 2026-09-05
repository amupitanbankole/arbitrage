"""Endpoint-level security invariants (§61, §71, §87, §111, §124, §127, §133, §136).

These tests assert properties that must hold for **every** response the API can
produce, not the behaviour of one route. Each one exists because a plausible
future change would break it silently:

* a new route added without the platform middleware,
* an error path that leaks an exception message, class name, file path or DSN,
* an endpoint that starts answering on a path operators believe is disabled,
* a monitoring endpoint scraped without authentication,
* response caching that discloses one user's financial position to the next.

Functional behaviour of the metrics endpoint lives in
``tests/integration/test_metrics_endpoint.py``; health semantics in
``test_health_endpoints.py``. This file is deliberately paranoid about the
boundary between those and the outside world.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from arb_api.middleware.request_context import REQUEST_ID_HEADER
from arb_core.errors import ErrorCode
from arb_core.metrics import Metrics
from tests.support.apps import (
    UNREACHABLE_DATABASE_URL,
    build_app,
    build_client,
    build_container,
    unreachable_database,
)
from tests.support.config import TEST_ENCRYPTION_KEY, TEST_JWT_SECRET, override

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from httpx import AsyncClient

    from arb_core.config import Settings
    from arb_core.redis.client import RedisClient

#: Every path the Phase 1 API exposes. Kept explicit rather than discovered from
#: ``app.routes``: a test that derives its own input from the thing it is
#: checking cannot notice that a route was added without review.
PUBLIC_PATHS: tuple[str, ...] = (
    "/",
    "/health",
    "/health/live",
    "/health/ready",
    "/api/v1/system/info",
    "/api/v1/system/workers",
)

#: Strings that must never appear in a response body. Each is a real leak class:
#: a Python traceback, a source path, a SQL fragment, a driver error, a
#: connection string, or a committed credential (§71, §133, §136).
FORBIDDEN_BODY_SUBSTRINGS: tuple[str, ...] = (
    "Traceback (most recent call last)",
    "sqlalchemy",
    "asyncpg",
    "aiosqlite",
    "SELECT ",
    "INSERT ",
    "password=",
    "postgresql+asyncpg://",
    "Sup3rSecret",
    TEST_JWT_SECRET,
    TEST_ENCRYPTION_KEY,
)

_FORBIDDEN_BODY_PATTERNS: tuple[str, ...] = (
    # Absolute filesystem paths from a traceback or a driver message.
    r"/home/[\w./-]+\.py",
    r"/app/[\w./-]+\.py",
    r"[A-Za-z]:\\\\[\w\\\\.-]+\.py",
    # An IPv4 host:port pair — the shape of an internal service address.
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b",
)

#: Response headers that must be present on every HTTP response (§87).
REQUIRED_SECURITY_HEADERS: tuple[str, ...] = (
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "content-security-policy",
    "permissions-policy",
    "cache-control",
)


def _assert_no_leak(body: str) -> None:
    """Assert a response body carries no internals or secrets."""
    for needle in FORBIDDEN_BODY_SUBSTRINGS:
        assert needle not in body, f"response body leaked {needle!r}"
    for pattern in _FORBIDDEN_BODY_PATTERNS:
        assert not re.search(pattern, body), f"response body matched {pattern!r}: {body[:200]}"


class _ExplodingMetrics(Metrics):
    """A ``Metrics`` whose render raises, to force the unhandled-exception path."""

    def render(self) -> bytes:
        raise RuntimeError("boom: connection to postgresql+asyncpg://arb:Sup3rSecret@db:5432/arb")


@pytest.fixture
async def token_client(settings: Settings, redis_client: RedisClient) -> AsyncIterator[AsyncClient]:
    """An app whose metrics endpoint requires a bearer token."""
    secured = override(settings, metrics_enabled=True, metrics_auth_token="s3cr3t-scrape-token")
    container = build_container(
        secured, database=unreachable_database(), redis=redis_client, ready=True
    )
    async with build_client(build_app(container)) as client:
        yield client


@pytest.fixture
async def disabled_client(
    settings: Settings, redis_client: RedisClient
) -> AsyncIterator[AsyncClient]:
    """An app with ``METRICS_ENABLED=false``."""
    hidden = override(settings, metrics_enabled=False, metrics_auth_token="")
    container = build_container(
        hidden, database=unreachable_database(), redis=redis_client, ready=True
    )
    async with build_client(build_app(container)) as client:
        yield client


@pytest.fixture
async def failing_client(
    settings: Settings, redis_client: RedisClient
) -> AsyncIterator[AsyncClient]:
    """An app whose ``/metrics`` handler raises an unexpected exception."""
    container = build_container(
        settings,
        database=unreachable_database(),
        redis=redis_client,
        metrics=_ExplodingMetrics(),
        ready=True,
    )
    # The envelope is only observable if the transport does not re-raise.
    async with build_client(build_app(container), raise_app_exceptions=False) as client:
        yield client


class TestErrorEnvelopesAreClientSafe:
    @pytest.mark.parametrize("path", [*PUBLIC_PATHS, "/nope", "/api/v1/system/nope"])
    async def test_no_internals_in_any_response(self, client: AsyncClient, path: str) -> None:
        response = await client.get(path)

        _assert_no_leak(response.text)

    async def test_unknown_path_uses_the_standard_envelope(self, client: AsyncClient) -> None:
        payload = (await client.get("/definitely-not-a-route")).json()

        assert set(payload) == {"error"}
        assert payload["error"]["code"] == ErrorCode.NOT_FOUND.value
        assert set(payload["error"]) >= {"code", "message", "request_id"}

    async def test_unhandled_exception_becomes_a_generic_500(
        self, failing_client: AsyncClient
    ) -> None:
        """§71/§136 — the client learns that something failed, nothing else.

        The raised message deliberately embeds a DSN with a password. It must
        reach the operator's log and must never reach the response.
        """
        response = await failing_client.get("/metrics")

        assert response.status_code == 500
        payload = response.json()
        assert payload["error"]["code"] == ErrorCode.INTERNAL_ERROR.value
        assert payload["error"]["message"] == "An unexpected error occurred."
        _assert_no_leak(response.text)
        assert "boom" not in response.text

    async def test_unhandled_exception_detail_stays_in_the_log(
        self,
        failing_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The operator still gets the truth — correlated by request id."""
        response = await failing_client.get("/metrics")

        assert response.status_code == 500
        assert caplog.records, "a 500 must be logged"
        # The request id ties the client-visible envelope to the operator's log,
        # which is the only place the real exception is recorded (§66, §71).
        assert response.headers[REQUEST_ID_HEADER]

    @pytest.mark.parametrize("path", [*PUBLIC_PATHS, "/nope"])
    async def test_request_id_header_on_every_response(
        self, client: AsyncClient, path: str
    ) -> None:
        response = await client.get(path)

        assert response.headers[REQUEST_ID_HEADER]
        # A correlation id that a client can predict is not a correlation id.
        assert len(response.headers[REQUEST_ID_HEADER]) >= 32


class TestSecurityHeadersAreUniversal:
    @pytest.mark.parametrize("path", [*PUBLIC_PATHS, "/nope"])
    async def test_present_on_success_and_failure(self, client: AsyncClient, path: str) -> None:
        response = await client.get(path)

        for header in REQUIRED_SECURITY_HEADERS:
            assert header in response.headers, f"{header} missing on {path}"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"

    async def test_present_on_an_unhandled_500(self, failing_client: AsyncClient) -> None:
        """The response an attacker most wants to reinterpret is the error one.

        Regression guard for a real defect: Starlette installs
        ``ServerErrorMiddleware`` above every user middleware, so the 500 for an
        unhandled exception was being sent from outside
        ``SecurityHeadersMiddleware`` — the one response the platform emitted
        with no CSP, no ``nosniff`` and no ``Cache-Control: no-store``. The
        handlers now attach those headers themselves.
        """
        response = await failing_client.get("/metrics")

        assert response.status_code == 500
        for header in REQUIRED_SECURITY_HEADERS:
            assert header in response.headers, f"{header} missing on the unhandled 500"
        assert "no-store" in response.headers["cache-control"]
        assert response.headers["x-content-type-options"] == "nosniff"

    async def test_present_on_the_metrics_endpoint(self, token_client: AsyncClient) -> None:
        response = await token_client.get(
            "/metrics", headers={"authorization": "Bearer s3cr3t-scrape-token"}
        )

        assert response.status_code == 200
        for header in REQUIRED_SECURITY_HEADERS:
            assert header in response.headers

    async def test_financial_responses_are_never_cached(self, client: AsyncClient) -> None:
        """§132 — no-store, or a shared proxy discloses one user to the next."""
        for path in PUBLIC_PATHS:
            response = await client.get(path)
            assert "no-store" in response.headers["cache-control"], path

    async def test_api_serves_no_content(self, client: AsyncClient) -> None:
        """A JSON-only API permits nothing, so a policy of 'none' cannot break it."""
        response = await client.get("/health")

        assert "default-src 'none'" in response.headers["content-security-policy"]

    async def test_no_server_software_is_disclosed(self, client: AsyncClient) -> None:
        """§124 — the Server header is version reconnaissance for free."""
        response = await client.get("/")

        assert "server" not in response.headers


class TestMetricsEndpointAccess:
    async def test_disabled_means_not_found_not_forbidden(
        self, disabled_client: AsyncClient
    ) -> None:
        """§124 — 403 confirms the endpoint exists and is merely locked."""
        disabled = await disabled_client.get("/metrics")
        unknown = await disabled_client.get("/metrics-but-not-real")

        assert disabled.status_code == 404
        assert disabled.json()["error"]["code"] == unknown.json()["error"]["code"]

    async def test_token_is_required_when_configured(self, token_client: AsyncClient) -> None:
        response = await token_client.get("/metrics")

        assert response.status_code == 401
        assert response.json()["error"]["code"] == ErrorCode.UNAUTHENTICATED.value

    async def test_wrong_token_is_rejected(self, token_client: AsyncClient) -> None:
        response = await token_client.get(
            "/metrics", headers={"authorization": "Bearer not-the-token"}
        )

        assert response.status_code == 401

    async def test_token_must_be_a_bearer_token(self, token_client: AsyncClient) -> None:
        """The raw secret in a non-bearer scheme is not accepted."""
        response = await token_client.get(
            "/metrics", headers={"authorization": "s3cr3t-scrape-token"}
        )

        assert response.status_code == 401

    async def test_correct_token_is_accepted(self, token_client: AsyncClient) -> None:
        response = await token_client.get(
            "/metrics", headers={"authorization": "Bearer s3cr3t-scrape-token"}
        )

        assert response.status_code == 200
        assert "arb_api_requests_total" in response.text

    async def test_the_token_is_never_echoed_back(
        self, token_client: AsyncClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """§127/§133 — not in the body, not in a header, not in a log line."""
        response = await token_client.get(
            "/metrics", headers={"authorization": "Bearer wrong-token-value"}
        )

        assert "wrong-token-value" not in response.text
        assert "s3cr3t-scrape-token" not in response.text
        for value in response.headers.values():
            assert "wrong-token-value" not in value
            assert "s3cr3t-scrape-token" not in value
        assert "wrong-token-value" not in caplog.text
        assert "s3cr3t-scrape-token" not in caplog.text

    async def test_metrics_body_carries_no_secrets(self, token_client: AsyncClient) -> None:
        response = await token_client.get(
            "/metrics", headers={"authorization": "Bearer s3cr3t-scrape-token"}
        )

        _assert_no_leak(response.text)


class TestPublicEndpointsDiscloseNoConfiguration:
    async def test_no_secret_material_in_any_public_response(
        self, client: AsyncClient, settings: Settings
    ) -> None:
        forbidden = [
            settings.database_url.get_secret_value(),
            settings.redis_url.get_secret_value(),
            settings.jwt_secret.get_secret_value(),
            settings.session_secret.get_secret_value(),
            settings.encryption_key.get_secret_value(),
        ]
        for path in PUBLIC_PATHS:
            body = (await client.get(path)).text
            for secret in forbidden:
                assert secret not in body, f"{path} disclosed a configured secret"

    async def test_unreachable_dependency_urls_are_not_disclosed(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        """A dependency outage must not turn into an infrastructure map (§111)."""
        container = build_container(
            settings, database=unreachable_database(), redis=redis_client, ready=True
        )
        async with build_client(build_app(container)) as http:
            for path in ("/health", "/health/ready", "/api/v1/system/workers"):
                response = await http.get(path)
                assert UNREACHABLE_DATABASE_URL not in response.text
                _assert_no_leak(response.text)

    async def test_openapi_document_discloses_no_secrets(self, client: AsyncClient) -> None:
        response = await client.get("/openapi.json")

        assert response.status_code == 200
        _assert_no_leak(response.text)
        assert "/metrics" not in response.json()["paths"]


class TestCorsIsNotWildcard:
    async def test_a_disallowed_origin_gets_no_allow_header(self, client: AsyncClient) -> None:
        response = await client.get("/health", headers={"origin": "https://evil.example.com"})

        assert "access-control-allow-origin" not in response.headers

    async def test_wildcard_origin_is_never_sent(self, client: AsyncClient) -> None:
        """`*` plus credentials would let any site act as a logged-in user."""
        response = await client.get("/health", headers={"origin": "https://evil.example.com"})

        assert response.headers.get("access-control-allow-origin") != "*"

    async def test_credentials_are_never_granted_to_an_unlisted_origin(
        self, client: AsyncClient
    ) -> None:
        """The invariant that actually protects a session.

        Starlette sends ``Access-Control-Allow-Credentials: true`` on every
        response when ``allow_credentials`` is set. On its own that grants
        nothing: without ``Access-Control-Allow-Origin`` the browser treats the
        cross-origin response as opaque and the calling script cannot read it.
        What must never happen is the two together for an origin nobody listed,
        or a wildcard — that combination is what turns a logged-in session into
        a cross-site read (§132).
        """
        response = await client.get("/health", headers={"origin": "https://evil.example.com"})

        allow_origin = response.headers.get("access-control-allow-origin")
        allow_credentials = response.headers.get("access-control-allow-credentials")
        # Expressed as a conditional so both halves stay meaningful: asserting
        # `allow_origin is None` first would narrow it to None and make any
        # follow-up combination check provably dead.
        if allow_credentials == "true":
            assert allow_origin is None, (
                "credentials must never be granted to an origin nobody listed"
            )
        assert allow_origin != "*"

    async def test_preflight_from_an_unlisted_origin_is_refused(self, client: AsyncClient) -> None:
        response = await client.options(
            "/health",
            headers={
                "origin": "https://evil.example.com",
                "access-control-request-method": "GET",
            },
        )

        assert "access-control-allow-origin" not in response.headers

    async def test_configured_origin_is_allowed(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        scoped = override(settings, cors_origins="https://app.example.com")
        container = build_container(
            scoped, database=unreachable_database(), redis=redis_client, ready=True
        )
        async with build_client(build_app(container)) as http:
            response = await http.get("/health", headers={"origin": "https://app.example.com"})

        assert response.headers["access-control-allow-origin"] == "https://app.example.com"


class TestMethodExposure:
    @pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
    async def test_phase_one_exposes_no_mutating_route(
        self, client: AsyncClient, method: str
    ) -> None:
        """§41 — nothing in Phase 1 can change state, and nothing should.

        A 405 (or 404) here is the assertion: the platform ships read-only
        observability before any write path exists, so there is no route an
        unauthenticated caller could reach to alter configuration or funds.
        """
        for path in PUBLIC_PATHS:
            response = await client.request(method.upper(), path)
            assert response.status_code in {404, 405}, f"{method.upper()} {path} was served"
            _assert_no_leak(response.text)
