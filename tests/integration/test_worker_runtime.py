"""Worker runtime: roles, heartbeats and graceful shutdown (§55, §140).

These tests run the real :class:`WorkerRuntime` against fakeredis and read the
result back through the real Redis keys the API's :class:`SystemService` scans,
so writer and reader are verified as a pair. A heartbeat format the fleet view
cannot parse is worse than no heartbeat at all, and only an end-to-end test
catches it.

Shutdown pattern used throughout: ``run()`` blocks until a role returns, so the
runtime is started as a task, exercised, then stopped. ``task.cancel()`` after
``stop()`` is belt-and-braces — ``stop()`` already cancels the role tasks, and
leaving an un-awaited task behind would emit "Task was destroyed but it is
pending" noise into unrelated tests.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from typing import TYPE_CHECKING, Any

import pytest

from arb_core import worker as worker_module
from arb_core.clock import parse_isoformat, utc_now
from arb_core.events import Event, EventType, InProcessEventBus
from arb_core.metrics import Metrics
from arb_core.worker import (
    FOUNDATION_ROLE,
    WorkerContext,
    WorkerRuntime,
    available_roles,
    register_role,
    run_periodically,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from arb_core.config import Settings
    from arb_core.db.session import Database
    from arb_core.redis.client import RedisClient


def _context(settings: Settings, **overrides: Any) -> WorkerContext:
    """A standalone context for testing role bodies directly."""
    kwargs: dict[str, Any] = {
        "role": FOUNDATION_ROLE,
        "settings": settings,
        "database": None,
        "redis": None,
        "events": InProcessEventBus(),
        "metrics": Metrics(),
        "stop_event": asyncio.Event(),
        "identity": "testhost:1234",
    }
    kwargs.update(overrides)
    return WorkerContext(**kwargs)


async def _wait_for(
    predicate: Callable[[], Awaitable[object]], *, within_seconds: float = 3.0
) -> bool:
    """Poll ``predicate`` until its result is truthy; returns whether it ever was.

    The awaited value is typed ``object`` rather than ``bool`` because the
    predicates used here are Redis calls whose natural results are counts —
    ``EXISTS`` returns an int, not a flag — and truthiness is exactly the
    condition being polled for.

    A hand-rolled deadline rather than ``asyncio.timeout``: the point is to poll
    until a side effect becomes visible and report whether it ever did, not to
    cancel the caller on expiry.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within_seconds
    while loop.time() < deadline:
        if await predicate():
            return True
        await asyncio.sleep(0.01)
    return bool(await predicate())


def _runtime(runtime: WorkerRuntime, redis: RedisClient) -> tuple[str, str]:
    """The ``(heartbeat_key, alive_key)`` this runtime writes to."""
    return runtime._heartbeat_key(FOUNDATION_ROLE), runtime._alive_key(FOUNDATION_ROLE)


async def _fields(redis: RedisClient, key: str) -> dict[str, str]:
    """Read a heartbeat hash and decode it the way ``SystemService`` does."""
    payload = await redis.raw.hgetall(key)
    return {
        (k.decode() if isinstance(k, bytes) else str(k)): (
            v.decode() if isinstance(v, bytes) else str(v)
        )
        for k, v in payload.items()
    }


async def _teardown(runtime: WorkerRuntime, task: asyncio.Task[int]) -> None:
    """Stop a runtime and settle its task without asserting how it ended.

    ``stop()`` sets the stop event, the role returns normally and ``run()``
    completes with an exit code — so the task is usually already done and
    ``cancel()`` is a no-op. Awaiting it inside ``pytest.raises(CancelledError)``
    would fail for a reason unrelated to the test.
    """
    await runtime.stop()
    if not task.done():
        task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.fixture
async def runtime(settings: Settings, redis_client: RedisClient) -> Any:
    """A started foundation runtime, stopped and cleaned up afterwards."""
    instance = WorkerRuntime(
        [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
    )
    task = asyncio.create_task(instance.run())
    heartbeat_key, _ = _runtime(instance, redis_client)
    assert await _wait_for(lambda: redis_client.raw.exists(heartbeat_key))
    try:
        yield instance
    finally:
        await _teardown(instance, task)


class TestRoleRegistry:
    def test_foundation_role_is_registered(self) -> None:
        """Regression guard for a real startup-blocking defect.

        ``FOUNDATION_ROLE`` was declared and documented as always present but
        never registered, so ``arb-worker`` failed immediately on the default
        ``WORKER_ROLES=foundation`` with "unknown worker role(s)".
        """
        assert FOUNDATION_ROLE in available_roles()

    def test_default_configuration_runs_a_known_role(self, settings: Settings) -> None:
        """The shipped default must be runnable without editing configuration."""
        assert settings.worker_role_list, "WORKER_ROLES must not default to empty"
        unknown = [role for role in settings.worker_role_list if role not in available_roles()]
        assert unknown == []

    def test_unknown_role_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="unknown worker role"):
            WorkerRuntime(["not_a_real_role"])

    def test_empty_role_list_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least one worker role"):
            WorkerRuntime([])

    def test_duplicate_registration_is_rejected(self) -> None:
        """A silent override would mean the process runs code nobody deployed."""

        async def first(context: WorkerContext) -> None:
            return None

        async def second(context: WorkerContext) -> None:
            return None

        register_role("test_duplicate_role")(first)
        try:
            with pytest.raises(ValueError, match="already registered"):
                register_role("test_duplicate_role")(second)
            # Re-registering the *same* function is idempotent, so a module
            # imported twice cannot break startup.
            register_role("test_duplicate_role")(first)
        finally:
            worker_module._role_registry.pop("test_duplicate_role", None)


class TestRunPeriodically:
    async def test_counts_successful_cycles(self, settings: Settings) -> None:
        context = _context(settings)
        calls = 0

        async def job(ctx: WorkerContext) -> None:
            nonlocal calls
            calls += 1
            if calls >= 3:
                ctx.stop_event.set()

        await run_periodically(context, interval_seconds=0.01, fn=job)
        assert calls == 3
        assert context.jobs_processed == 3
        assert context.jobs_failed == 0

    async def test_survives_a_failing_cycle(self, settings: Settings) -> None:
        """One bad cycle must not kill the role (§140)."""
        context = _context(settings)
        calls = 0

        async def job(ctx: WorkerContext) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("transient")
            if calls >= 3:
                ctx.stop_event.set()

        await run_periodically(context, interval_seconds=0.01, fn=job)
        assert context.jobs_failed == 1
        assert context.jobs_processed == 2

    async def test_failures_are_counted_in_metrics(self, settings: Settings) -> None:
        metrics = Metrics()
        context = _context(settings, metrics=metrics)
        calls = 0

        async def job(ctx: WorkerContext) -> None:
            nonlocal calls
            calls += 1
            if calls >= 2:
                ctx.stop_event.set()
            raise ValueError("always fails")

        await run_periodically(context, interval_seconds=0.01, fn=job)
        rendered = metrics.render().decode()
        assert "worker_jobs_total" in rendered
        assert 'result="failure"' in rendered

    async def test_rejects_a_non_positive_interval(self, settings: Settings) -> None:
        context = _context(settings)

        async def job(ctx: WorkerContext) -> None:
            return None

        with pytest.raises(ValueError, match="interval_seconds must be positive"):
            await run_periodically(context, interval_seconds=0, fn=job)

    async def test_cancellation_propagates(self, settings: Settings) -> None:
        """Graceful shutdown depends on CancelledError not being swallowed."""
        context = _context(settings)

        async def job(ctx: WorkerContext) -> None:
            await asyncio.sleep(10)

        task = asyncio.create_task(run_periodically(context, interval_seconds=0.01, fn=job))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


class TestHeartbeatContents:
    async def test_payload_carries_every_field_the_api_reads(
        self, settings: Settings, redis_client: RedisClient, runtime: WorkerRuntime
    ) -> None:
        key, _ = _runtime(runtime, redis_client)
        fields = await _fields(redis_client, key)
        # These are exactly the keys SystemService._to_summary looks up.
        assert fields["role"] == FOUNDATION_ROLE
        assert fields["status"] == "running"
        assert fields["host"] == socket.gethostname()
        assert fields["pid"] == str(os.getpid())
        assert fields["environment"] == settings.environment.value
        assert fields["version"] == settings.app_version
        assert fields["jobs_processed"] == "0"
        assert fields["jobs_failed"] == "0"
        assert fields["started_at"]
        assert fields["last_heartbeat_at"]

    async def test_status_value_parses_into_the_worker_enum(
        self, redis_client: RedisClient, runtime: WorkerRuntime
    ) -> None:
        """The worker writes lowercase; the API uppercases before lookup."""
        from arb_persistence.models.enums import WorkerStatus

        key, _ = _runtime(runtime, redis_client)
        fields = await _fields(redis_client, key)
        assert WorkerStatus(fields["status"].upper()) is WorkerStatus.RUNNING

    async def test_timestamps_are_aware_utc(
        self, redis_client: RedisClient, runtime: WorkerRuntime
    ) -> None:
        """§75 — a naive timestamp in Redis cannot be compared to ``utc_now()``."""
        key, _ = _runtime(runtime, redis_client)
        fields = await _fields(redis_client, key)
        for name in ("started_at", "last_heartbeat_at"):
            parsed = parse_isoformat(fields[name])
            assert parsed.tzinfo is not None, name
            assert parsed.utcoffset() == utc_now().utcoffset(), name

    async def test_alive_key_expires_so_staleness_is_observable(
        self, settings: Settings, redis_client: RedisClient, runtime: WorkerRuntime
    ) -> None:
        """The heartbeat record outlives the liveness marker on purpose (§55)."""
        _, alive_key = _runtime(runtime, redis_client)
        assert await redis_client.raw.exists(alive_key)
        ttl = await redis_client.raw.ttl(alive_key)
        assert 0 < ttl <= settings.worker_stale_after_seconds


class TestHeartbeatKeyScheme:
    async def test_replicas_of_one_role_do_not_collide(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        """Regression guard for a real observability defect.

        Keys used to be role-only, so two replicas of the same role overwrote
        each other and a crashed replica stayed invisible for as long as any
        sibling kept writing — the fleet view reported healthy while capacity was
        silently gone.
        """
        first = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
        )
        second = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
        )
        # Both run in this process, so give the second a distinct pid to model a
        # second replica rather than spawning one.
        second._pid = "99999"
        second._identity = f"{second._host}:99999"

        tasks = [asyncio.create_task(first.run()), asyncio.create_task(second.run())]
        try:
            assert first._heartbeat_key(FOUNDATION_ROLE) != second._heartbeat_key(FOUNDATION_ROLE)
            assert await _wait_for(
                lambda: redis_client.raw.exists(first._heartbeat_key(FOUNDATION_ROLE))
            )
            assert await _wait_for(
                lambda: redis_client.raw.exists(second._heartbeat_key(FOUNDATION_ROLE))
            )

            pattern = redis_client.key("worker", "heartbeat", "*")
            keys = [key async for key in redis_client.raw.scan_iter(match=pattern)]
            assert len(keys) == 2, "each replica must own a distinct record"

            # Both are readable as separate fleet members.
            roles = [(await _fields(redis_client, key.decode()))["role"] for key in keys]
            assert roles == [FOUNDATION_ROLE, FOUNDATION_ROLE]
        finally:
            await _teardown(first, tasks[0])
            await _teardown(second, tasks[1])

    async def test_key_is_scannable_by_the_api_pattern(
        self, redis_client: RedisClient, runtime: WorkerRuntime
    ) -> None:
        """``SystemService`` finds workers by scanning ``worker:heartbeat:*``."""
        key, _ = _runtime(runtime, redis_client)
        pattern = redis_client.key("worker", "heartbeat", "*")
        found = [k async for k in redis_client.raw.scan_iter(match=pattern)]
        assert key.encode() in found


class TestShutdown:
    async def test_worker_is_marked_stopped(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        runtime = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
        )
        key, alive_key = _runtime(runtime, redis_client)
        task = asyncio.create_task(runtime.run())
        assert await _wait_for(lambda: redis_client.raw.exists(key))

        await _teardown(runtime, task)

        fields = await _fields(redis_client, key)
        assert fields["status"] == "stopped"
        assert not await redis_client.raw.exists(alive_key)

    async def test_exit_code_is_zero_on_clean_shutdown(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        runtime = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
        )
        task = asyncio.create_task(runtime.run())
        await asyncio.sleep(0.05)
        await runtime.stop()
        assert await task == 0

    async def test_failing_role_sets_a_non_zero_exit_code(self, settings: Settings) -> None:
        """A crashed role must be visible to the supervisor, not swallowed."""

        async def exploding(context: WorkerContext) -> None:
            raise RuntimeError("role failed")

        register_role("test_exploding_role")(exploding)
        try:
            runtime = WorkerRuntime(["test_exploding_role"], settings=settings, database=None)
            assert await runtime.run() == 1
        finally:
            worker_module._role_registry.pop("test_exploding_role", None)

    async def test_injected_dependencies_are_not_closed(
        self, settings: Settings, redis_client: RedisClient, database: Database
    ) -> None:
        """Whoever passed a dependency in still owns it.

        The API lifespan applies the same rule to an injected container; the two
        must not disagree, or an embedding host loses its handles mid-run — and
        every assertion after ``stop()`` in this suite would fail for a reason
        unrelated to what it tests.
        """
        runtime = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=database
        )
        task = asyncio.create_task(runtime.run())
        await asyncio.sleep(0.05)
        await _teardown(runtime, task)

        assert await redis_client.ping() is True
        probe = await database.probe()
        assert probe.latency_ms is not None
        assert probe.latency_ms >= 0

    async def test_stop_is_idempotent(self, settings: Settings, redis_client: RedisClient) -> None:
        runtime = WorkerRuntime(
            [FOUNDATION_ROLE], settings=settings, redis=redis_client, database=None
        )
        task = asyncio.create_task(runtime.run())
        await asyncio.sleep(0.05)
        await runtime.stop()
        await runtime.stop()
        await _teardown(runtime, task)


class TestResilience:
    async def test_heartbeat_failure_does_not_kill_the_worker(self, settings: Settings) -> None:
        """A Redis outage must not take the worker down with it (§140)."""
        from tests.support.apps import unreachable_redis

        redis = unreachable_redis()
        runtime = WorkerRuntime([FOUNDATION_ROLE], settings=settings, redis=redis, database=None)
        task = asyncio.create_task(runtime.run())
        try:
            await asyncio.sleep(0.2)
            assert not task.done(), "the runtime must survive an unreachable Redis"
            assert runtime._exit_code == 0
        finally:
            await _teardown(runtime, task)

    async def test_run_without_redis_skips_heartbeats(self, settings: Settings) -> None:
        runtime = WorkerRuntime([FOUNDATION_ROLE], settings=settings, database=None)
        task = asyncio.create_task(runtime.run())
        try:
            await asyncio.sleep(0.1)
            assert not task.done()
        finally:
            await _teardown(runtime, task)

    async def test_heartbeat_event_is_published(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        events = InProcessEventBus()
        seen: list[Event] = []

        async def handler(event: Event) -> None:
            seen.append(event)

        events.subscribe(EventType.WORKER_HEARTBEAT, handler)
        runtime = WorkerRuntime(
            [FOUNDATION_ROLE],
            settings=settings,
            redis=redis_client,
            events=events,
            database=None,
        )
        task = asyncio.create_task(runtime.run())
        try:

            async def observed() -> bool:
                return bool(seen)

            assert await _wait_for(observed)
            assert seen[0].event_type is EventType.WORKER_HEARTBEAT
            assert seen[0].payload["role"] == FOUNDATION_ROLE
        finally:
            await _teardown(runtime, task)
