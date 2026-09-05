"""Root, system-info and worker-fleet endpoints (§31, §48, §55, §67, §124).

Two things are worth testing hard here:

* **``trading_mode_label`` is computed server-side** and must be rendered
  verbatim by clients. If a client could derive the banner itself it could derive
  it *wrongly*, which is how a user ends up believing paper trading is live.
* **Live trading is gated twice.** ``LIVE_TRADING_ENABLED`` alone must not be
  enough; the database flag has to agree. And the database row wins over the
  bootstrap default, so a restart cannot re-enable what an operator disabled
  (§91, §110).
"""

from __future__ import annotations

import socket
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest

from arb_core.clock import isoformat, utc_now
from arb_core.worker import FOUNDATION_ROLE, WorkerRuntime
from arb_persistence.models.feature_flags import FeatureFlag
from tests.support.apps import build_app, build_client, build_container, unreachable_redis
from tests.support.config import override

if TYPE_CHECKING:
    from httpx import AsyncClient

    from arb_core.config import Settings
    from arb_core.db.session import Database
    from arb_core.redis.client import RedisClient

_INFO_PATH = "/api/v1/system/info"
_WORKERS_PATH = "/api/v1/system/workers"

#: Fields that must never appear in the public worker view (§124).
FORBIDDEN_WORKER_FIELDS = ("host", "pid", "identity")


async def _seed_heartbeat(
    redis: RedisClient,
    *,
    role: str,
    status: str = "running",
    age_seconds: int = 0,
    host: str = "worker-host-1",
    pid: str = "4242",
    jobs_processed: int = 0,
    jobs_failed: int = 0,
    last_heartbeat_at: str | None = None,
    include_topology: bool = True,
) -> str:
    """Write one heartbeat hash in exactly the shape ``WorkerRuntime`` writes."""
    key = redis.key("worker", "heartbeat", role, host, pid)
    # redis-py's `hset` mapping is invariant in its key type, so dict[str, str]
    # is not assignable to it even though every value here really is a str.
    payload: dict[Any, Any] = {
        "role": role,
        "status": status,
        "environment": "test",
        "version": "0.1.0-test",
        "started_at": isoformat(utc_now() - timedelta(seconds=age_seconds + 60)),
        "last_heartbeat_at": last_heartbeat_at
        or isoformat(utc_now() - timedelta(seconds=age_seconds)),
        "jobs_processed": str(jobs_processed),
        "jobs_failed": str(jobs_failed),
    }
    if include_topology:
        # Present in Redis, and deliberately absent from the public response.
        payload["host"] = host
        payload["pid"] = pid
        payload["identity"] = f"{host}:{pid}"
    await redis.raw.hset(key, mapping=payload)
    return key


async def _seed_flag(
    database: Database, key: str, *, enabled: bool, rollout_percentage: int = 100
) -> None:
    async with database.unit_of_work() as session:
        session.add(
            FeatureFlag(
                key=key,
                description="seeded by test",
                enabled=enabled,
                rollout_percentage=rollout_percentage,
            )
        )


async def _client_for(settings: Settings, **parts: Any) -> Any:
    """Build a client over an explicitly assembled container."""
    return build_client(build_app(build_container(settings, **parts)))


class TestRootEndpoint:
    async def test_describes_the_service(self, client: AsyncClient, settings: Settings) -> None:
        response = await client.get("/")
        assert response.status_code == 200
        payload = response.json()
        assert payload["service"] == settings.service_name
        assert payload["version"] == settings.app_version
        assert payload["environment"] == settings.environment.value

    async def test_links_the_entry_points(self, client: AsyncClient) -> None:
        """§128 — the first thing an operator does is curl the API root."""
        payload = (await client.get("/")).json()
        assert payload["api"] == "/api/v1"
        assert payload["health"]["live"] == "/health/live"
        assert payload["health"]["ready"] == "/health/ready"
        assert payload["documentation"]["openapi"] == "/openapi.json"
        # Every advertised path must actually resolve.
        for path in (
            payload["api"],
            payload["health"]["live"],
            payload["health"]["ready"],
            payload["health"]["full"],
            payload["documentation"]["openapi"],
        ):
            response = await client.get(path)
            assert response.status_code != 404, path

    async def test_exposes_the_trading_gates(self, client: AsyncClient) -> None:
        """§31 — a deployment mistake is most often found by curling the root."""
        payload = (await client.get("/")).json()
        assert payload["trading"]["live_trading_enabled"] is False
        assert payload["trading"]["global_kill_switch_enabled"] is False

    async def test_exposes_no_secrets(self, client: AsyncClient, settings: Settings) -> None:
        body = (await client.get("/")).text
        for secret in (
            settings.jwt_secret.get_secret_value(),
            settings.session_secret.get_secret_value(),
            settings.encryption_key.get_secret_value(),
        ):
            assert secret not in body


class TestTradingModeLabel:
    async def test_paper_trading_is_the_default(self, client: AsyncClient) -> None:
        payload = (await client.get(_INFO_PATH)).json()
        assert payload["trading_mode_label"] == "PAPER TRADING"
        assert payload["live_trading_enabled"] is False
        assert payload["paper_trading_enabled"] is True

    async def test_kill_switch_dominates_everything(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """§26 — with the kill switch on, no other gate matters."""
        await _seed_flag(database, "live_trading", enabled=True)
        escalated = override(
            settings,
            live_trading_enabled=True,
            feature_flag_live_trading=True,
            global_kill_switch_enabled=True,
        )
        async with await _client_for(
            escalated, database=database, redis=redis_client
        ) as escalated_client:
            payload = (await escalated_client.get(_INFO_PATH)).json()
        assert payload["global_kill_switch_enabled"] is True
        assert payload["trading_mode_label"] == "GLOBAL KILL SWITCH ACTIVE"

    async def test_live_trading_requires_both_gates(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """§31 — the environment master switch alone is not sufficient."""
        # Database flag disabled: settings alone must not enable live trading.
        await _seed_flag(database, "live_trading", enabled=False)
        half_open = override(settings, live_trading_enabled=True, feature_flag_live_trading=True)
        async with await _client_for(
            half_open, database=database, redis=redis_client
        ) as half_client:
            payload = (await half_client.get(_INFO_PATH)).json()
        assert payload["live_trading_enabled"] is False
        assert payload["trading_mode_label"] == "PAPER TRADING"

    async def test_live_trading_when_both_gates_are_open(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        await _seed_flag(database, "live_trading", enabled=True)
        both_open = override(settings, live_trading_enabled=True, feature_flag_live_trading=True)
        async with await _client_for(
            both_open, database=database, redis=redis_client
        ) as live_client:
            payload = (await live_client.get(_INFO_PATH)).json()
        assert payload["live_trading_enabled"] is True
        assert payload["trading_mode_label"] == "LIVE TRADING ACTIVE"

    async def test_environment_switch_off_overrides_an_enabled_flag(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """The reverse direction: a flag cannot override the master switch."""
        await _seed_flag(database, "live_trading", enabled=True)
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as flag_only_client:
            payload = (await flag_only_client.get(_INFO_PATH)).json()
        assert payload["live_trading_enabled"] is False

    async def test_trading_disabled_when_nothing_is_on(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        await _seed_flag(database, "paper_trading", enabled=False)
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as disabled_client:
            payload = (await disabled_client.get(_INFO_PATH)).json()
        assert payload["paper_trading_enabled"] is False
        assert payload["trading_mode_label"] == "TRADING DISABLED"

    async def test_database_row_wins_over_the_bootstrap_default(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """§91, §110 — a restart must not re-enable what an operator disabled.

        ``feature_flag_paper_trading`` defaults to True in configuration, so a
        disabled database row proving the flag off shows precedence, not default.
        """
        await _seed_flag(database, "paper_trading", enabled=False)
        assert settings.feature_flag_paper_trading is True
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as precedence_client:
            payload = (await precedence_client.get(_INFO_PATH)).json()
        assert payload["paper_trading_enabled"] is False


class TestSystemInfo:
    async def test_reports_a_utc_server_clock(self, client: AsyncClient) -> None:
        """§75 — clients convert for display only."""
        payload = (await client.get(_INFO_PATH)).json()
        server_time = payload["server_time"]
        assert server_time.endswith(("+00:00", "Z"))
        from arb_core.clock import parse_isoformat

        parsed = parse_isoformat(server_time)
        assert parsed.tzinfo is not None
        assert abs((utc_now() - parsed).total_seconds()) < 5

    async def test_uptime_is_non_negative(self, client: AsyncClient) -> None:
        payload = (await client.get(_INFO_PATH)).json()
        assert payload["uptime_seconds"] >= 0

    async def test_contract_is_complete(self, client: AsyncClient) -> None:
        payload = (await client.get(_INFO_PATH)).json()
        assert set(payload) == {
            "service",
            "version",
            "environment",
            "server_time",
            "uptime_seconds",
            "live_trading_enabled",
            "global_kill_switch_enabled",
            "paper_trading_enabled",
            "demo_mode",
            "trading_mode_label",
        }

    async def test_demo_mode_reflects_configuration(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """§109 — demo mode never touches real funds, and says so publicly."""
        demo = override(settings, next_public_demo_mode=True)
        async with await _client_for(demo, database=database, redis=redis_client) as demo_client:
            payload = (await demo_client.get(_INFO_PATH)).json()
        assert payload["demo_mode"] is True


class TestWorkersEndpoint:
    async def test_empty_fleet(self, client: AsyncClient, settings: Settings) -> None:
        payload = (await client.get(_WORKERS_PATH)).json()
        assert payload == {
            "items": [],
            "total": 0,
            "stale_after_seconds": settings.worker_stale_after_seconds,
        }

    async def test_reports_a_live_worker(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        await _seed_heartbeat(redis_client, role="market_data", jobs_processed=120, jobs_failed=2)
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()

        assert payload["total"] == 1
        worker = payload["items"][0]
        assert worker["role"] == "market_data"
        assert worker["status"] == "RUNNING"
        assert worker["stale"] is False
        assert worker["jobs_processed"] == 120
        assert worker["jobs_failed"] == 2
        assert worker["age_seconds"] is not None
        assert 0 <= worker["age_seconds"] <= 5

    async def test_never_exposes_internal_topology(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """§124 — hostnames and pids map the internal network."""
        await _seed_heartbeat(redis_client, role="market_data", host="prod-worker-07", pid="31337")
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            response = await seeded_client.get(_WORKERS_PATH)

        for field in FORBIDDEN_WORKER_FIELDS:
            assert field not in response.json()["items"][0]
        assert "prod-worker-07" not in response.text
        assert "31337" not in response.text

    async def test_a_worker_past_the_staleness_window_is_stale(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """§55 — a silently dead worker must be visible as such."""
        await _seed_heartbeat(
            redis_client,
            role="arbitrage",
            age_seconds=settings.worker_stale_after_seconds + 30,
        )
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()

        worker = payload["items"][0]
        assert worker["stale"] is True
        assert worker["age_seconds"] > settings.worker_stale_after_seconds

    @pytest.mark.parametrize("terminal_status", ["stopped", "failed"])
    async def test_terminal_states_are_stale_regardless_of_age(
        self,
        settings: Settings,
        database: Database,
        redis_client: RedisClient,
        terminal_status: str,
    ) -> None:
        """A worker that announced its own shutdown is not live, however fresh
        its last heartbeat is."""
        await _seed_heartbeat(redis_client, role="risk", status=terminal_status, age_seconds=0)
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()
        assert payload["items"][0]["stale"] is True

    async def test_unparseable_timestamp_degrades_rather_than_failing(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """A corrupt record must not take the whole fleet view down with it."""
        await _seed_heartbeat(redis_client, role="execution", last_heartbeat_at="not-a-timestamp")
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            response = await seeded_client.get(_WORKERS_PATH)
        assert response.status_code == 200
        worker = response.json()["items"][0]
        assert worker["age_seconds"] is None
        assert worker["stale"] is False

    async def test_unknown_status_is_reported_as_degraded(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """A newer worker writing an unknown state must not be shown as RUNNING."""
        await _seed_heartbeat(redis_client, role="future_role", status="QUANTUM_TUNNELLING")
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()
        assert payload["items"][0]["status"] == "DEGRADED"

    async def test_missing_status_defaults_to_starting(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        key = redis_client.key("worker", "heartbeat", "booting", "h", "1")
        await redis_client.raw.hset(key, mapping={"role": "booting"})
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()
        assert payload["items"][0]["status"] == "STARTING"

    async def test_records_without_a_role_are_ignored(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """A malformed hash under the scan pattern must not produce a phantom worker."""
        key = redis_client.key("worker", "heartbeat", "broken", "h", "1")
        await redis_client.raw.hset(key, mapping={"status": "running"})
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()
        assert payload["items"] == []
        assert payload["total"] == 0

    async def test_negative_counters_are_clamped(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """The schema declares ``ge=0``; a corrupt value must not become a 422."""
        key = await _seed_heartbeat(redis_client, role="clamped")
        await redis_client.raw.hset(key, mapping={"jobs_processed": "-5", "jobs_failed": "abc"})
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            response = await seeded_client.get(_WORKERS_PATH)
        assert response.status_code == 200
        worker = response.json()["items"][0]
        assert worker["jobs_processed"] == 0
        assert worker["jobs_failed"] == 0

    async def test_fleet_is_sorted_by_role_then_age(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """Deterministic ordering keeps the admin view stable between refreshes."""
        await _seed_heartbeat(redis_client, role="zeta", age_seconds=1)
        await _seed_heartbeat(redis_client, role="alpha", age_seconds=5, pid="1")
        await _seed_heartbeat(redis_client, role="alpha", age_seconds=1, pid="2")
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            payload = (await seeded_client.get(_WORKERS_PATH)).json()
        assert [(item["role"], item["age_seconds"]) for item in payload["items"]] == [
            ("alpha", 1),
            ("alpha", 5),
            ("zeta", 1),
        ]

    async def test_scan_is_bounded(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """A runaway fleet must not turn the status endpoint into an unbounded scan."""
        for index in range(205):
            await _seed_heartbeat(redis_client, role=f"role_{index:03d}", pid=str(index))
        async with await _client_for(
            settings, database=database, redis=redis_client
        ) as seeded_client:
            response = await seeded_client.get(_WORKERS_PATH)
        assert response.status_code == 200
        assert response.json()["total"] <= 200

    async def test_503_when_redis_is_unreachable(
        self, settings: Settings, database: Database
    ) -> None:
        """§128 — an empty list is indistinguishable from 'no workers running',
        so an unreadable Redis must be an error, not an empty success."""
        redis = unreachable_redis()
        async with await _client_for(settings, database=database, redis=redis) as down_client:
            response = await down_client.get(_WORKERS_PATH)
        assert response.status_code == 503
        body = response.json()
        assert body["error"]["code"] == "REDIS_UNAVAILABLE"
        assert "127.0.0.1" not in response.text


class TestWorkersFromARealRuntime:
    async def test_a_running_worker_appears_in_the_fleet_view(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """Writer and reader verified as a pair, with no hand-built payload."""
        import asyncio

        runtime = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
        )
        task = asyncio.create_task(runtime.run())
        try:
            async with await _client_for(
                settings, database=database, redis=redis_client
            ) as live_client:
                payload: dict[str, Any] = {"total": 0}
                for _ in range(100):
                    payload = (await live_client.get(_WORKERS_PATH)).json()
                    if payload["total"]:
                        break
                    await asyncio.sleep(0.02)

            assert payload["total"] == 1
            worker = payload["items"][0]
            assert worker["role"] == FOUNDATION_ROLE
            assert worker["status"] == "RUNNING"
            assert worker["stale"] is False
            assert socket.gethostname() not in str(worker)
        finally:
            await runtime.stop()
            if not task.done():
                task.cancel()
