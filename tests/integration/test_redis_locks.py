"""Redis client and distributed locks (§63, §71, §81, §111).

The lock is the mechanism that makes trading operations idempotent across
replicas: two workers must not both execute the same opportunity. That makes
*ownership* the property under test, not merely "a key gets set":

* release must be compare-and-delete, or a worker whose TTL expired deletes a
  lock another worker now holds, and two workers execute the same trade;
* renewal must stop when ownership is lost, not keep extending someone else's;
* a lock with no TTL can wedge the platform permanently if its holder dies.

Lua scripting is exercised for real: fakeredis runs the scripts through ``lupa``
rather than stubbing them, so the compare-and-delete logic itself is under test.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from arb_core.errors import ConflictError, ErrorCode
from arb_core.health import HealthState
from arb_core.redis.client import RedisClient, decode
from arb_core.redis.locks import LockNotAcquiredError, RedisLock
from tests.support.apps import unreachable_redis

if TYPE_CHECKING:
    from arb_core.config import Settings


class TestKeyNamespacing:
    def test_keys_are_prefixed(self, redis_client: RedisClient, settings: Settings) -> None:
        """§71 — one Redis instance must be safely shared between environments."""
        assert redis_client.key("lock", "orders") == f"{settings.redis_key_prefix}:lock:orders"

    def test_different_prefixes_do_not_collide(self, settings: Settings) -> None:
        import fakeredis

        server = fakeredis.FakeServer()
        first = RedisClient(
            fakeredis.aioredis.FakeRedis(server=server),
            key_prefix="env_a",
            url_safe="redis://fakeredis",
        )
        second = RedisClient(
            fakeredis.aioredis.FakeRedis(server=server),
            key_prefix="env_b",
            url_safe="redis://fakeredis",
        )
        assert first.key("lock", "x") != second.key("lock", "x")
        assert first.key("lock", "x").startswith("env_a:")

    def test_url_safe_never_carries_a_password(self) -> None:
        client = RedisClient.create("redis://:Sup3rSecret@localhost:6379/0")
        assert "Sup3rSecret" not in client.url_safe


class TestDecode:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [(b"text", "text"), ("text", "text"), (None, None), (b"", ""), (b"1", "1"), (1, 1)],
    )
    def test_normalises_replies(self, value: Any, expected: Any) -> None:
        """``decode_responses=False`` means bytes reach callers; comparing
        ``b'1'`` against ``'1'`` in a trading decision is how bugs hide."""
        assert decode(value) == expected


class TestProbe:
    async def test_healthy(self, redis_client: RedisClient) -> None:
        check = await redis_client.probe()
        assert check.name == "redis"
        assert check.state is HealthState.HEALTHY
        assert check.detail is None

    async def test_ping_round_trip(self, redis_client: RedisClient) -> None:
        assert await redis_client.ping() is True

    async def test_degraded_on_slow_probe(self, redis_client: RedisClient) -> None:
        """-1 rather than 0: an in-memory PING can legitimately take 0ms."""
        check = await redis_client.probe(degraded_after_ms=-1)
        assert check.state is HealthState.DEGRADED

    async def test_unavailable_when_unreachable(self) -> None:
        redis = unreachable_redis()
        try:
            check = await redis.probe()
            assert check.state is HealthState.UNAVAILABLE
            assert check.detail is not None
            assert await redis.ping() is False
        finally:
            await redis.aclose()

    async def test_unavailable_detail_leaks_nothing(self) -> None:
        redis = RedisClient.create("redis://:Sup3rSecret@127.0.0.1:1/0")
        try:
            check = await redis.probe()
        finally:
            await redis.aclose()
        assert check.state is HealthState.UNAVAILABLE
        assert "Sup3rSecret" not in (check.detail or "")


class TestAcquireAndRelease:
    async def test_acquire_sets_the_owner_token_with_a_ttl(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "orders:123", ttl_seconds=30)
        assert await lock.acquire() is True
        assert lock.held is True

        stored = decode(await redis_client.raw.get(lock.key))
        assert stored == lock.owner
        ttl = await redis_client.raw.pttl(lock.key)
        assert 0 < ttl <= 30_000

        await lock.release()

    async def test_a_lock_without_expiry_is_refused(self, redis_client: RedisClient) -> None:
        """A TTL-less lock wedges the platform permanently if its holder dies."""
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            RedisLock(redis_client, "wedge", ttl_seconds=0)
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            RedisLock(redis_client, "wedge", ttl_seconds=-5)

    async def test_release_by_the_owner_removes_the_key(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "released", ttl_seconds=30)
        await lock.acquire()
        assert await lock.release() is True
        assert lock.held is False
        assert await redis_client.raw.exists(lock.key) == 0

    async def test_release_by_a_non_owner_is_refused(self, redis_client: RedisClient) -> None:
        """The property that stops duplicated trade execution (§63)."""
        holder = RedisLock(redis_client, "contended", ttl_seconds=30)
        impostor = RedisLock(redis_client, "contended", ttl_seconds=30)
        await holder.acquire()
        impostor._held = True  # simulate a stale belief that it owns the lock

        assert await impostor.release() is False
        # The real holder's lock must be untouched.
        assert decode(await redis_client.raw.get(holder.key)) == holder.owner
        assert await holder.release() is True

    async def test_release_when_never_held_is_false(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "never", ttl_seconds=30)
        assert await lock.release() is False

    async def test_owners_are_unique_per_acquisition(self, redis_client: RedisClient) -> None:
        owners = {RedisLock(redis_client, "unique", ttl_seconds=5).owner for _ in range(50)}
        assert len(owners) == 50

    async def test_explicit_owner_is_honoured(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "explicit", ttl_seconds=5, owner="worker-42")
        assert lock.owner == "worker-42"


class TestMutualExclusion:
    async def test_a_second_holder_cannot_acquire(self, redis_client: RedisClient) -> None:
        first = RedisLock(redis_client, "exclusive", ttl_seconds=30)
        second = RedisLock(redis_client, "exclusive", ttl_seconds=30)
        assert first.key == second.key, "same name must mean same lock"
        assert first.owner != second.owner
        assert await first.acquire() is True
        assert await second.acquire() is False
        assert second.held is False
        await first.release()

    async def test_exactly_one_of_many_concurrent_workers_wins(
        self, redis_client: RedisClient
    ) -> None:
        """The realistic case: a fleet racing on one opportunity."""
        winners: list[str] = []

        async def attempt(index: int) -> None:
            lock = RedisLock(redis_client, "race", ttl_seconds=30)
            if await lock.acquire():
                winners.append(lock.owner)
                await asyncio.sleep(0.01)
                await lock.release()

        await asyncio.gather(*(attempt(index) for index in range(25)))
        assert len(winners) == 1

    async def test_different_lock_names_do_not_contend(self, redis_client: RedisClient) -> None:
        first = RedisLock(redis_client, "opportunity:1", ttl_seconds=30)
        second = RedisLock(redis_client, "opportunity:2", ttl_seconds=30)
        assert await first.acquire() is True
        assert await second.acquire() is True
        await first.release()
        await second.release()

    async def test_acquire_waits_for_a_release_when_given_a_timeout(
        self, redis_client: RedisClient
    ) -> None:
        holder = RedisLock(redis_client, "queued", ttl_seconds=30)
        await holder.acquire()

        async def release_soon() -> None:
            await asyncio.sleep(0.05)
            await holder.release()

        waiter = RedisLock(redis_client, "queued", ttl_seconds=30)
        _, acquired = await asyncio.gather(
            release_soon(), waiter.acquire(timeout_seconds=2, retry_interval_seconds=0.01)
        )
        assert acquired is True
        await waiter.release()

    async def test_acquire_times_out_when_never_released(self, redis_client: RedisClient) -> None:
        holder = RedisLock(redis_client, "held_forever", ttl_seconds=30)
        await holder.acquire()
        waiter = RedisLock(redis_client, "held_forever", ttl_seconds=30)
        assert await waiter.acquire(timeout_seconds=0.05, retry_interval_seconds=0.01) is False
        await holder.release()

    async def test_negative_timeout_is_rejected(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "negative", ttl_seconds=5)
        with pytest.raises(ValueError, match="timeout_seconds must be non-negative"):
            await lock.acquire(timeout_seconds=-1)


class TestExpiry:
    async def test_an_expired_lock_can_be_reacquired(self, redis_client: RedisClient) -> None:
        """A dead holder must not block the platform forever (§140)."""
        first = RedisLock(redis_client, "expiring", ttl_seconds=0.1)
        await first.acquire()
        await asyncio.sleep(0.2)
        assert await redis_client.raw.exists(first.key) == 0

        second = RedisLock(redis_client, "expiring", ttl_seconds=5)
        assert await second.acquire() is True
        await second.release()

    async def test_release_after_expiry_reports_lost_ownership(
        self, redis_client: RedisClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Not benign cleanup: the protected work may have been duplicated."""
        import logging

        first = RedisLock(redis_client, "lost", ttl_seconds=0.1)
        await first.acquire()
        await asyncio.sleep(0.2)

        second = RedisLock(redis_client, "lost", ttl_seconds=5)
        await second.acquire()

        with caplog.at_level(logging.WARNING):
            assert await first.release() is False

        assert first.held is False
        # The new holder's lock must survive the old holder's release attempt.
        assert decode(await redis_client.raw.get(second.key)) == second.owner
        assert any("not owned at release time" in record.message for record in caplog.records)
        await second.release()


class TestExtend:
    async def test_extend_renews_the_ttl(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "extendable", ttl_seconds=5)
        await lock.acquire()
        assert await lock.extend(ttl_seconds=60) is True
        ttl = await redis_client.raw.pttl(lock.key)
        assert 55_000 < ttl <= 60_000
        await lock.release()

    async def test_extend_defaults_to_the_configured_ttl(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "extendable_default", ttl_seconds=30)
        await lock.acquire()
        assert await lock.extend() is True
        assert await redis_client.raw.pttl(lock.key) > 0
        await lock.release()

    async def test_extend_by_a_non_owner_fails_and_clears_held(
        self, redis_client: RedisClient
    ) -> None:
        holder = RedisLock(redis_client, "extend_contended", ttl_seconds=30)
        await holder.acquire()
        impostor = RedisLock(redis_client, "extend_contended", ttl_seconds=30)
        impostor._held = True

        assert await impostor.extend() is False
        assert impostor.held is False, "a lost lock must not keep renewing"
        await holder.release()

    async def test_extend_when_never_held_is_false(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "never_held", ttl_seconds=5)
        assert await lock.extend() is False

    async def test_auto_renew_keeps_a_lock_alive_past_its_ttl(
        self, redis_client: RedisClient
    ) -> None:
        """Renewal at one third of the TTL leaves room for two failed attempts."""
        lock = RedisLock(redis_client, "renewing", ttl_seconds=0.3)
        await lock.acquire(auto_renew=True)
        try:
            await asyncio.sleep(0.8)
            assert lock.held is True
            assert decode(await redis_client.raw.get(lock.key)) == lock.owner
        finally:
            await lock.release()
        assert await redis_client.raw.exists(lock.key) == 0

    async def test_auto_renew_stops_after_release(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "renew_stop", ttl_seconds=0.3)
        await lock.acquire(auto_renew=True)
        await lock.release()
        await asyncio.sleep(0.4)
        assert await redis_client.raw.exists(lock.key) == 0


class TestHoldContextManager:
    async def test_releases_on_normal_exit(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "held", ttl_seconds=30)
        async with lock.hold():
            assert await redis_client.raw.exists(lock.key) == 1
        assert await redis_client.raw.exists(lock.key) == 0

    async def test_releases_on_exception(self, redis_client: RedisClient) -> None:
        """A failed trade attempt must not leave the opportunity locked."""
        lock = RedisLock(redis_client, "held_error", ttl_seconds=30)
        with pytest.raises(RuntimeError, match="boom"):
            async with lock.hold():
                raise RuntimeError("boom")
        assert await redis_client.raw.exists(lock.key) == 0

    async def test_raises_when_contended(self, redis_client: RedisClient) -> None:
        holder = RedisLock(redis_client, "hold_contended", ttl_seconds=30)
        await holder.acquire()
        waiter = RedisLock(redis_client, "hold_contended", ttl_seconds=30)
        with pytest.raises(LockNotAcquiredError):
            async with waiter.hold():
                pytest.fail("the body must not run without the lock")
        await holder.release()

    async def test_contention_error_is_a_409_conflict(self, redis_client: RedisClient) -> None:
        """Mapped to HTTP 409 by the error handlers, not a 500."""
        holder = RedisLock(redis_client, "conflict", ttl_seconds=30)
        await holder.acquire()
        waiter = RedisLock(redis_client, "conflict", ttl_seconds=30)
        with pytest.raises(ConflictError) as excinfo:
            async with waiter.hold():
                pass
        assert excinfo.value.code is ErrorCode.CONFLICT
        assert excinfo.value.details == {"lock": "conflict"}
        await holder.release()

    async def test_async_protocol_acquires_and_releases(self, redis_client: RedisClient) -> None:
        lock = RedisLock(redis_client, "protocol", ttl_seconds=30)
        async with lock as acquired:
            assert acquired is lock
            # Captured in a local: `held` genuinely flips when the block exits,
            # and reading it twice through the attribute lets the type checker
            # narrow it to True and then call the second assertion unreachable.
            held_inside = lock.held
        assert held_inside is True
        assert lock.held is False
        assert await redis_client.raw.exists(lock.key) == 0

    async def test_async_protocol_raises_on_contention(self, redis_client: RedisClient) -> None:
        """Regression guard: ``__aenter__`` once ran the body unprotected when
        acquisition failed, which is the worst possible failure mode for a lock."""
        holder = RedisLock(redis_client, "protocol_contended", ttl_seconds=30)
        await holder.acquire()
        waiter = RedisLock(redis_client, "protocol_contended", ttl_seconds=30)
        with pytest.raises(LockNotAcquiredError):
            async with waiter:
                pytest.fail("the body must not run without the lock")
        assert waiter.held is False
        await holder.release()


class TestBootstrapLockUsage:
    async def test_feature_flag_bootstrap_is_serialised(
        self, redis_client: RedisClient, settings: Settings
    ) -> None:
        """The lock the API lifespan actually uses at startup (§91)."""
        name = "bootstrap:feature-flags"
        order: list[int] = []

        async def replica(index: int) -> None:
            lock = RedisLock(redis_client, name, ttl_seconds=30)
            async with lock.hold(timeout_seconds=2):
                order.append(index)
                await asyncio.sleep(0.01)

        await asyncio.gather(*(replica(index) for index in range(5)))
        assert sorted(order) == list(range(5)), "every replica eventually ran"
        assert await redis_client.raw.exists(redis_client.key("lock", name)) == 0
