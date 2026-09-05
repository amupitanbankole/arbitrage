"""Health endpoints (§111, §124, §151).

Three properties matter more than the happy path, and each has a test here:

1. **``/health/live`` touches nothing.** Coupling liveness to the database turns
   a database outage into a fleet-wide restart storm.
2. **``/health/ready`` returns 503 on a required outage.** That status code is
   the mechanism by which nginx stops routing to a broken instance. A 200 with a
   sad-looking body achieves nothing, because nothing reads the body.
3. **A degraded dependency still accepts traffic.** Withdrawing capacity because
   the database is merely slow removes it exactly when it is most needed.

Every response is also asserted free of hostnames, ports, driver names,
credentials and exception text, because these endpoints are unauthenticated.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest

from arb_core.health import HealthState
from arb_core.redis.client import RedisClient
from tests.support.apps import (
    UNREACHABLE_DATABASE_URL,
    build_app,
    build_client,
    build_container,
    dispose,
    unreachable_database,
    unreachable_redis,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from httpx import AsyncClient

    from arb_core.config import Settings
    from arb_core.db.session import Database

#: Substrings that must never appear in an unauthenticated health response.
#:
#: Note what is *not* here: an exception **type** name such as
#: ``ConnectionRefusedError``. Both probes emit the type and nothing else, which
#: is the documented design (§133) — a type name discloses no host, port, driver
#: or credential, and the ``UNAVAILABLE`` state already says the connection
#: failed. What must never appear is a driver *message*, because those embed the
#: DSN, and the DSN embeds the password.
FORBIDDEN_SUBSTRINGS = (
    "Sup3rSecret",
    "asyncpg",
    "aiosqlite",
    "psycopg",
    "127.0.0.1",
    "localhost",
    "5432",
    "6379",
    "Traceback",
    "sqlalchemy",
    "redis.exceptions",
    "://",
)

#: The exact shapes a component ``detail`` may take. Anything else — most
#: importantly a verbatim exception message — fails the test.
_ALLOWED_DETAIL = re.compile(
    r"^(?:"
    r"probe failed: [A-Za-z_][A-Za-z0-9_]*"
    r"|probe latency \d+ms exceeds \d+ms"
    r"|not implemented yet \(Phase \d+\)"
    r"|startup incomplete or shutting down"
    r")$"
)

INFORMATIONAL = ("exchanges", "market_data", "arbitrage", "risk", "execution", "notifications")


@pytest.fixture
async def broken_client(settings: Settings) -> AsyncIterator[AsyncClient]:
    """An app whose database *and* Redis are unreachable."""
    database = unreachable_database()
    redis = unreachable_redis()
    app = build_app(build_container(settings, database=database, redis=redis))
    async with build_client(app) as client:
        yield client
    await dispose(database, redis)


@pytest.fixture
async def database_down_client(settings: Settings) -> AsyncIterator[AsyncClient]:
    """An app with a working Redis and an unreachable database."""
    import fakeredis

    database = unreachable_database()
    raw = fakeredis.aioredis.FakeRedis(server=fakeredis.FakeServer())
    redis = RedisClient(raw, key_prefix=settings.redis_key_prefix, url_safe="redis://fakeredis")
    app = build_app(build_container(settings, database=database, redis=redis))
    async with build_client(app) as client:
        yield client
    await dispose(database, redis)


@pytest.fixture
async def redis_down_client(settings: Settings, database: Database) -> AsyncIterator[AsyncClient]:
    """An app with a working database and an unreachable Redis."""
    redis = unreachable_redis()
    app = build_app(build_container(settings, database=database, redis=redis))
    async with build_client(app) as client:
        yield client
    await dispose(redis)


@pytest.fixture
async def starting_client(
    settings: Settings, database: Database, redis_client: RedisClient
) -> AsyncIterator[AsyncClient]:
    """An app that has not finished starting up."""
    app = build_app(build_container(settings, database=database, redis=redis_client, ready=False))
    async with build_client(app) as client:
        yield client


def _assert_no_leakage(body: str) -> None:
    lowered = body.lower()
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden.lower() not in lowered, f"health response leaked {forbidden!r}: {body}"


def _assert_details_are_well_formed(payload: dict[str, Any]) -> None:
    """Every ``detail`` must match a known hand-written shape.

    This is the assertion that actually protects §133: a future change that
    substitutes ``str(exc)`` for ``type(exc).__name__`` breaks it immediately,
    whereas a substring blocklist would only catch leaks it anticipated.
    """
    for name, component in payload["components"].items():
        detail = component.get("detail")
        assert detail is None or _ALLOWED_DETAIL.match(detail), (
            f"{name}: unexpected detail shape {detail!r}"
        )


class TestLiveness:
    async def test_reports_alive(self, client: AsyncClient) -> None:
        response = await client.get("/health/live")
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "alive"
        assert payload["uptime_seconds"] >= 0
        assert set(payload) == {"status", "uptime_seconds"}

    async def test_still_alive_when_every_dependency_is_down(
        self, broken_client: AsyncClient
    ) -> None:
        """The single most important assertion in this module (§111)."""
        response = await broken_client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    async def test_alive_while_starting(self, starting_client: AsyncClient) -> None:
        """A starting or draining process must not be restarted by the orchestrator."""
        response = await starting_client.get("/health/live")
        assert response.status_code == 200

    async def test_carries_a_request_id(self, client: AsyncClient) -> None:
        response = await client.get("/health/live")
        assert response.headers.get("x-request-id")


class TestReadiness:
    async def test_healthy(self, client: AsyncClient) -> None:
        response = await client.get("/health/ready")
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == HealthState.HEALTHY.value
        assert set(payload["components"]) == {"api", "database", "redis"}
        for component in payload["components"].values():
            assert component["state"] == HealthState.HEALTHY.value
            assert component["latency_ms"] is not None

    async def test_503_when_the_database_is_down(self, database_down_client: AsyncClient) -> None:
        """The status code, not the body, is what makes nginx drain the instance."""
        response = await database_down_client.get("/health/ready")
        assert response.status_code == 503
        payload = response.json()
        assert payload["status"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["database"]["state"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["redis"]["state"] == HealthState.HEALTHY.value
        _assert_no_leakage(response.text)
        _assert_details_are_well_formed(payload)

    async def test_503_when_redis_is_down(self, redis_down_client: AsyncClient) -> None:
        response = await redis_down_client.get("/health/ready")
        assert response.status_code == 503
        payload = response.json()
        assert payload["status"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["redis"]["state"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["database"]["state"] == HealthState.HEALTHY.value
        _assert_no_leakage(response.text)
        _assert_details_are_well_formed(payload)

    async def test_503_when_everything_is_down(self, broken_client: AsyncClient) -> None:
        response = await broken_client.get("/health/ready")
        assert response.status_code == 503
        payload = response.json()
        assert payload["components"]["database"]["state"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["redis"]["state"] == HealthState.UNAVAILABLE.value
        # The API itself is healthy — it answered. Misreporting that would hide
        # the fact that the outage is in the dependencies, not the process.
        assert payload["components"]["api"]["state"] == HealthState.HEALTHY.value

    async def test_503_before_startup_completes(self, starting_client: AsyncClient) -> None:
        """Regression guard for a real defect.

        ``AppState.ready`` was written by the lifespan but never read, so
        ``/health/ready`` reported HEALTHY during the startup window and nginx
        routed traffic to a half-initialised instance.
        """
        response = await starting_client.get("/health/ready")
        assert response.status_code == 503
        payload = response.json()
        assert payload["status"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["api"]["state"] == HealthState.UNAVAILABLE.value
        assert payload["components"]["api"]["detail"] == "startup incomplete or shutting down"

    async def test_degraded_database_still_accepts_traffic(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """Slow is not down; withdrawing capacity here makes the outage worse."""
        real_probe = database.probe

        async def slow_probe(**kwargs: Any) -> Any:
            return await real_probe(degraded_after_ms=-1)

        database.probe = slow_probe  # type: ignore[method-assign]
        try:
            app = build_app(build_container(settings, database=database, redis=redis_client))
            async with build_client(app) as degraded_client:
                response = await degraded_client.get("/health/ready")
        finally:
            database.probe = real_probe  # type: ignore[method-assign]

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == HealthState.DEGRADED.value
        assert payload["components"]["database"]["state"] == HealthState.DEGRADED.value


class TestFullHealth:
    async def test_lists_unshipped_subsystems_as_disabled(self, client: AsyncClient) -> None:
        """§151 — 'not built yet' must not be indistinguishable from 'healthy'."""
        response = await client.get("/health")
        assert response.status_code == 200
        components = response.json()["components"]
        for name in INFORMATIONAL:
            assert name in components, name
            assert components[name]["state"] == HealthState.DISABLED.value
            assert components[name]["detail"] is not None
            assert "not implemented yet" in components[name]["detail"]
            assert "Phase" in components[name]["detail"]

    async def test_disabled_subsystems_do_not_affect_readiness(self, client: AsyncClient) -> None:
        """A platform that reported not-ready because Phase 5 had not shipped
        would never start."""
        response = await client.get("/health")
        assert response.json()["status"] == HealthState.HEALTHY.value

    async def test_503_when_a_required_dependency_is_down(
        self, database_down_client: AsyncClient
    ) -> None:
        response = await database_down_client.get("/health")
        assert response.status_code == 503
        payload = response.json()
        assert payload["status"] == HealthState.UNAVAILABLE.value
        # Informational components are still reported during an outage: an
        # operator reading /health mid-incident needs the full picture.
        assert "arbitrage" in payload["components"]

    async def test_no_sensitive_detail_in_any_component(self, broken_client: AsyncClient) -> None:
        response = await broken_client.get("/health")
        _assert_no_leakage(response.text)
        payload = response.json()
        _assert_details_are_well_formed(payload)
        for component in payload["components"].values():
            detail = component.get("detail") or ""
            assert len(detail) < 200
            assert UNREACHABLE_DATABASE_URL not in detail

    async def test_informational_details_name_their_phase(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        payload = response.json()
        _assert_details_are_well_formed(payload)
        assert payload["components"]["arbitrage"]["detail"] == "not implemented yet (Phase 5)"


class TestSecurityHeadersOnHealthResponses:
    """Health endpoints are the most-scraped unauthenticated surface there is."""

    @pytest.mark.parametrize("path", ["/health/live", "/health/ready", "/health"])
    async def test_headers_present_on_success(self, client: AsyncClient, path: str) -> None:
        response = await client.get(path)
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") in {"DENY", "SAMEORIGIN"}
        assert "referrer-policy" in response.headers

    @pytest.mark.parametrize("path", ["/health/live", "/health/ready", "/health"])
    async def test_headers_present_on_503(self, broken_client: AsyncClient, path: str) -> None:
        """SecurityHeadersMiddleware sits outside the router, so error responses
        are covered too."""
        response = await broken_client.get(path)
        assert response.status_code in {200, 503}
        assert response.headers.get("x-content-type-options") == "nosniff"

    async def test_no_hsts_in_the_test_environment(self, client: AsyncClient) -> None:
        """HSTS over plain HTTP is ignored at best, misleading at worst."""
        response = await client.get("/health/live")
        assert "strict-transport-security" not in response.headers

    async def test_hsts_present_when_deployed(
        self, production_settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        app = build_app(build_container(production_settings, database=database, redis=redis_client))
        async with build_client(app) as deployed_client:
            response = await deployed_client.get("/health/live")
        header = response.headers.get("strict-transport-security", "")
        assert "max-age=" in header
        assert "includeSubDomains" in header


class TestStartupTolerance:
    async def test_startup_does_not_fail_when_dependencies_are_down(
        self, settings: Settings
    ) -> None:
        """§111 — a hard failure here becomes a restart loop during an outage,
        taking down the very endpoints needed to diagnose it."""
        database = unreachable_database()
        redis = unreachable_redis()
        app = build_app(build_container(settings, database=database, redis=redis))
        try:
            # ASGITransport does not run the lifespan; drive it explicitly so the
            # startup path itself is under test.
            async with app.router.lifespan_context(app), build_client(app) as started:
                live = await started.get("/health/live")
                ready = await started.get("/health/ready")
            assert live.status_code == 200
            assert ready.status_code == 503
        finally:
            await dispose(database, redis)
