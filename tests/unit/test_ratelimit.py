"""Rate limiting (§61).

Run against fakeredis with ``lupa``, so the Lua script itself is under test rather
than a Python reimplementation of it. That matters because the script is where the
atomicity lives: two concurrent requests must not both observe ``limit - 1``.

The behavioural properties worth defending are the ones a naive counter gets wrong:

* a fixed window allows twice the intended rate across a boundary, so the sliding
  window is tested *at* the boundary;
* a limit must count consecutive abuse, so a successful login has to clear the
  bucket or an honest user is throttled by a mistake they made last month;
* when Redis is down the answer depends on what is being protected — auth fails
  closed, bulk reads fail open, and neither may fail silently;
* identifiers are hashed, because Redis is a cache with weaker access controls than
  PostgreSQL and must not become a second store of email addresses and IPs.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest

from arb_core.errors import DependencyUnavailableError, RateLimitedError
from arb_core.security.ratelimit import (
    _SCRIPT,
    API_PER_USER,
    LOGIN_BY_ACCOUNT,
    LOGIN_BY_IP,
    MFA_VERIFY_BY_ACCOUNT,
    PASSWORD_RESET_BY_IP,
    REFRESH_BY_IP,
    REGISTER_BY_IP,
    RateLimit,
    RateLimitDecision,
    RateLimiter,
)
from tests.support.apps import unreachable_redis

if TYPE_CHECKING:
    from arb_core.config import Settings
    from arb_core.redis.client import RedisClient

# A fixed instant keeps every window assertion exact. Timezone-aware, because the
# limiter converts to epoch milliseconds and a naive datetime would be ambiguous.
BASE = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)

IP = "203.0.113.7"
EMAIL = "user@example.com"


@pytest.fixture
def limiter(redis_client: RedisClient) -> RateLimiter:
    return RateLimiter(redis=redis_client, enabled=True)


def _key_names(raw_keys: object) -> list[str]:
    """Normalise ``KEYS`` output to text.

    The driver returns bytes or str depending on ``decode_responses``, and its type
    stubs say ``bytes | str``; asserting on keys should not depend on which.
    """
    return [
        key.decode() if isinstance(key, bytes) else str(key)
        for key in cast("list[object]", raw_keys)
    ]


@pytest.fixture
def small() -> RateLimit:
    """Three requests per fifteen minutes: small enough to exhaust in a test."""
    return RateLimit(scope="test:unit", limit=3, window=timedelta(minutes=15))


class TestAdmission:
    async def test_requests_up_to_the_limit_are_allowed(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit):
            decision = await limiter.check(
                small, identifier=IP, now=BASE + timedelta(seconds=attempt)
            )
            assert decision.allowed, f"attempt {attempt + 1} should be within the limit"
            assert decision.enforced is True
            assert decision.scope == small.scope
            assert decision.limit == small.limit

    async def test_the_request_after_the_limit_is_denied(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit):
            await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=attempt))
        decision = await limiter.check(
            small, identifier=IP, now=BASE + timedelta(seconds=small.limit)
        )
        assert decision.allowed is False
        assert decision.enforced is True

    async def test_remaining_counts_down(self, limiter: RateLimiter, small: RateLimit) -> None:
        seen = [
            (await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=i))).remaining
            for i in range(small.limit)
        ]
        assert seen == [2, 1, 0]

    async def test_remaining_is_zero_once_denied(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit + 2):
            decision = await limiter.check(
                small, identifier=IP, now=BASE + timedelta(seconds=attempt)
            )
        assert decision.remaining == 0

    async def test_a_denial_says_when_to_come_back(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit):
            await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=attempt))
        decision = await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=4))
        assert decision.retry_after is not None
        # The first request was at BASE and the window is fifteen minutes, so the
        # bucket reopens just under fifteen minutes from now.
        assert timedelta(minutes=14) < decision.retry_after <= timedelta(minutes=15)
        assert decision.reset_at is not None
        assert decision.reset_at.tzinfo is not None
        assert decision.reset_at == BASE + timedelta(minutes=15)

    async def test_an_allowed_request_has_no_retry_after(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        decision = await limiter.check(small, identifier=IP, now=BASE)
        assert decision.retry_after is None

    async def test_the_reset_time_is_always_in_the_future(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit + 1):
            moment = BASE + timedelta(seconds=attempt)
            decision = await limiter.check(small, identifier=IP, now=moment)
            assert decision.reset_at is not None
            assert decision.reset_at > moment


class TestTheWindowSlides:
    async def test_no_double_rate_across_a_boundary(self, limiter: RateLimiter) -> None:
        """The failure mode a fixed-window counter has.

        With a limit of two per minute, requests at :59, :60 and :61 straddle a
        boundary. A fixed window admits all but one; a sliding window admits two.
        For a control bounding password attempts, the difference is a limit versus
        a suggestion.
        """
        burst = RateLimit(scope="test:boundary", limit=2, window=timedelta(minutes=1))
        allowed = [
            (
                await limiter.check(burst, identifier=IP, now=BASE + timedelta(seconds=second))
            ).allowed
            for second in (59, 60, 61)
        ]
        assert sum(allowed) == 2

    async def test_the_oldest_request_ages_out(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        """Requests at t=0,1,2s; the window is 15 minutes.

        At t=901s the two oldest (0s and 1s, both at or before ``now - window``)
        have aged out and only the t=2s request remains, so exactly one slot is
        free — ``remaining`` recovers one at a time rather than all at once, which
        is what distinguishes a sliding window from a fixed one.
        """
        for attempt in range(small.limit):
            await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=attempt))
        denied = await limiter.check(small, identifier=IP, now=BASE + timedelta(minutes=1))
        assert denied.allowed is False
        reopened = await limiter.check(
            small, identifier=IP, now=BASE + timedelta(minutes=15, seconds=1)
        )
        assert reopened.allowed is True
        assert reopened.remaining == 1

    async def test_capacity_returns_gradually(self, limiter: RateLimiter) -> None:
        limit = RateLimit(scope="test:gradual", limit=2, window=timedelta(seconds=10))
        assert (await limiter.check(limit, identifier=IP, now=BASE)).allowed
        assert (await limiter.check(limit, identifier=IP, now=BASE + timedelta(seconds=1))).allowed
        assert not (
            await limiter.check(limit, identifier=IP, now=BASE + timedelta(seconds=2))
        ).allowed
        # At t=10s only the t=0s request has aged out, so exactly one slot is free.
        one_slot = await limiter.check(limit, identifier=IP, now=BASE + timedelta(seconds=10))
        assert one_slot.allowed is True
        assert one_slot.remaining == 0
        # Half a second later nothing else has aged out, so it is denied again.
        assert not (
            await limiter.check(
                limit, identifier=IP, now=BASE + timedelta(seconds=10, milliseconds=500)
            )
        ).allowed


class TestIdentifiersAreSeparate:
    async def test_two_ips_do_not_share_a_budget(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit):
            await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=attempt))
        assert not (await limiter.check(small, identifier=IP, now=BASE)).allowed
        other = await limiter.check(small, identifier="198.51.100.9", now=BASE)
        assert other.allowed is True
        assert other.remaining == small.limit - 1

    async def test_an_ip_limit_and_an_account_limit_are_independent(
        self, limiter: RateLimiter
    ) -> None:
        """One IP serving many users, and one user behind many IPs, are both real;
        conflating them punishes the wrong party."""
        for _ in range(LOGIN_BY_IP.limit):
            await limiter.check(LOGIN_BY_IP, identifier=IP, now=BASE)
        assert not (await limiter.check(LOGIN_BY_IP, identifier=IP, now=BASE)).allowed
        assert (await limiter.check(LOGIN_BY_ACCOUNT, identifier=EMAIL, now=BASE)).allowed

    async def test_the_identifier_is_case_and_space_normalised_only_by_hashing(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        """Deliberate: the limiter hashes what it is given and does not decide that
        two email spellings are one account. Case-folding an email is the caller's
        job, and doing it twice in two places is how they disagree."""
        await limiter.check(small, identifier="User@Example.com", now=BASE)
        assert (await limiter.check(small, identifier="user@example.com", now=BASE)).allowed


class TestEnforce:
    async def test_a_breach_raises_429_with_retry_after(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        for attempt in range(small.limit):
            await limiter.enforce(small, identifier=IP, now=BASE + timedelta(seconds=attempt))
        with pytest.raises(RateLimitedError) as excinfo:
            await limiter.enforce(small, identifier=IP, now=BASE + timedelta(seconds=9))
        error = excinfo.value
        assert error.http_status == 429
        header = int(error.headers["Retry-After"])
        # The header and the attribute must agree: a client that trusts one and a
        # test that asserts the other is how the two drift apart.
        assert error.retry_after_seconds == header
        # Rounded up and never zero: "retry in 0 seconds" guarantees another
        # immediate request from a client that obeys it.
        assert header >= 1
        assert error.context == {"scope": small.scope, "limit": small.limit}

    async def test_within_the_limit_enforce_returns_the_decision(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        decision = await limiter.enforce(small, identifier=IP, now=BASE)
        assert decision.allowed is True
        assert decision.enforced is True

    async def test_a_limit_of_one_denies_the_second_request(self, limiter: RateLimiter) -> None:
        once = RateLimit(scope="test:once", limit=1, window=timedelta(minutes=1))
        await limiter.enforce(once, identifier=IP, now=BASE)
        with pytest.raises(RateLimitedError):
            await limiter.enforce(once, identifier=IP, now=BASE + timedelta(seconds=1))


class TestReset:
    async def test_a_successful_login_clears_the_failed_attempts(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        """Without this the limit counts lifetime abuse rather than consecutive
        abuse, and an honest user who once mistyped a password eleven times is
        throttled forever (§61)."""
        for attempt in range(small.limit):
            await limiter.check(small, identifier=EMAIL, now=BASE + timedelta(seconds=attempt))
        assert not (await limiter.check(small, identifier=EMAIL, now=BASE)).allowed
        assert await limiter.reset(small, identifier=EMAIL) is True
        decision = await limiter.check(small, identifier=EMAIL, now=BASE + timedelta(seconds=10))
        assert decision.allowed is True
        assert decision.remaining == small.limit - 1

    async def test_resetting_an_empty_bucket_reports_nothing_to_clear(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        assert await limiter.reset(small, identifier="nobody@else.example") is False

    async def test_reset_does_not_affect_another_identifier(
        self, limiter: RateLimiter, small: RateLimit
    ) -> None:
        """Both buckets are exhausted; clearing one must leave the other denied.

        A reset that cleared the whole scope would let one successful login wipe
        the counters of every other account behind it — a way to lift a limit by
        authenticating once as somebody else.
        """
        for attempt in range(small.limit):
            await limiter.check(small, identifier=IP, now=BASE + timedelta(seconds=attempt))
            await limiter.check(
                small, identifier="198.51.100.9", now=BASE + timedelta(seconds=attempt)
            )
        await limiter.reset(small, identifier=IP)
        assert (await limiter.check(small, identifier=IP, now=BASE)).allowed is True
        assert (await limiter.check(small, identifier="198.51.100.9", now=BASE)).allowed is False

    async def test_reset_is_idempotent(self, limiter: RateLimiter, small: RateLimit) -> None:
        await limiter.check(small, identifier=IP, now=BASE)
        assert await limiter.reset(small, identifier=IP) is True
        assert await limiter.reset(small, identifier=IP) is False


class TestConcurrency:
    async def test_a_burst_cannot_exceed_the_limit(self, limiter: RateLimiter) -> None:
        """Prune-count-admit happens inside one script, so concurrent callers
        cannot both read ``limit - 1`` and both proceed.

        fakeredis serialises commands in-process, so this cannot reproduce a true
        cross-process race; what it does prove is that the limiter's own
        bookkeeping stays exact when twenty coroutines interleave, and that the
        decision is made by the script rather than by a Python read-then-write.
        """
        limit = RateLimit(scope="test:concurrent", limit=5, window=timedelta(minutes=15))
        decisions = await asyncio.gather(
            *(limiter.check(limit, identifier=IP, now=BASE) for _ in range(20))
        )
        assert sum(decision.allowed for decision in decisions) == limit.limit
        assert sum(not decision.allowed for decision in decisions) == 20 - limit.limit

    async def test_concurrent_resets_and_checks_stay_consistent(self, limiter: RateLimiter) -> None:
        """One reset may free at most one full budget, whatever the interleaving.

        The order in which these four coroutines reach Redis is not something the
        test should depend on, so the assertion is the invariant that must hold for
        every possible order: with a limit of two and one reset, at most three
        checks can be admitted.
        """
        limit = RateLimit(scope="test:mixed", limit=2, window=timedelta(minutes=15))
        results = await asyncio.gather(
            limiter.check(limit, identifier=IP, now=BASE),
            limiter.check(limit, identifier=IP, now=BASE),
            limiter.reset(limit, identifier=IP),
            limiter.check(limit, identifier=IP, now=BASE),
        )
        admitted = sum(
            1 for result in results if isinstance(result, RateLimitDecision) and result.allowed
        )
        resets = sum(1 for result in results if isinstance(result, bool) and result)
        assert admitted <= limit.limit + resets


class TestDisabled:
    async def test_a_disabled_limiter_admits_everything(
        self, redis_client: RedisClient, small: RateLimit
    ) -> None:
        off = RateLimiter(redis=redis_client, enabled=False)
        for _ in range(small.limit * 3):
            decision = await off.check(small, identifier=IP, now=BASE)
            assert decision.allowed is True
            assert decision.enforced is False
            assert decision.remaining is None
            assert decision.retry_after is None
            assert decision.reset_at is None

    async def test_a_disabled_limiter_writes_nothing_to_redis(
        self, redis_client: RedisClient, small: RateLimit
    ) -> None:
        """It must not touch Redis at all: the point of disabling it in tests and
        development is that the dependency is not required."""
        off = RateLimiter(redis=redis_client, enabled=False)
        await off.check(small, identifier=IP)
        assert await off.reset(small, identifier=IP) is False
        assert await redis_client.raw.keys("*") == []

    async def test_a_disabled_limiter_never_raises_on_enforce(
        self, redis_client: RedisClient, small: RateLimit
    ) -> None:
        off = RateLimiter(redis=redis_client, enabled=False)
        for _ in range(10):
            assert (await off.enforce(small, identifier=IP)).allowed is True

    async def test_from_settings_honours_the_configuration_flag(
        self, settings: Settings, redis_client: RedisClient
    ) -> None:
        built = RateLimiter.from_settings(settings, redis_client)
        assert built.enabled is settings.rate_limit_enabled

    async def test_from_settings_defaults_to_enabled_for_a_bare_object(
        self, redis_client: RedisClient
    ) -> None:
        class NoFlag:
            pass

        assert RateLimiter.from_settings(NoFlag(), redis_client).enabled is True


class TestStoredKeys:
    async def test_the_identifier_is_never_written_to_redis(
        self, limiter: RateLimiter, redis_client: RedisClient, small: RateLimit
    ) -> None:
        """Redis is a cache with weaker access controls than PostgreSQL (§64), and
        its contents end up in RDB backups, ``MONITOR`` sessions and support
        snapshots. An email address or client IP must not become a second store of
        personal data."""
        await limiter.check(small, identifier=EMAIL, now=BASE)
        await limiter.check(LOGIN_BY_IP, identifier=IP, now=BASE)
        keys = _key_names(await redis_client.raw.keys("*"))
        assert keys
        for key in keys:
            assert EMAIL not in key
            assert "example.com" not in key
            assert IP not in key
            assert "203.0.113" not in key

    async def test_keys_are_namespaced_and_scoped(
        self, limiter: RateLimiter, redis_client: RedisClient, small: RateLimit
    ) -> None:
        await limiter.check(small, identifier=IP, now=BASE)
        (key,) = _key_names(await redis_client.raw.keys("*"))
        assert key.startswith(f"{redis_client.key_prefix}:rl:")
        assert small.scope.replace(":", "-") in key

    async def test_the_same_identifier_always_maps_to_the_same_key(
        self, limiter: RateLimiter, redis_client: RedisClient, small: RateLimit
    ) -> None:
        """A digest that drifted between requests would silently create a fresh
        budget for every call."""
        await limiter.check(small, identifier=EMAIL, now=BASE)
        await limiter.check(small, identifier=EMAIL, now=BASE + timedelta(seconds=1))
        assert len(await redis_client.raw.keys("*")) == 1

    async def test_a_bucket_expires_on_its_own(
        self, limiter: RateLimiter, redis_client: RedisClient, small: RateLimit
    ) -> None:
        """Otherwise one key per identifier accumulates forever."""
        await limiter.check(small, identifier=IP, now=BASE)
        (key,) = _key_names(await redis_client.raw.keys("*"))
        ttl_ms = await redis_client.raw.pttl(key)
        assert 0 < ttl_ms <= small.window_ms + 60_000

    async def test_a_denial_is_logged_as_a_security_event(
        self,
        limiter: RateLimiter,
        small: RateLimit,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.INFO, logger="arb_core.security.ratelimit")
        for attempt in range(small.limit + 1):
            await limiter.check(small, identifier=EMAIL, now=BASE + timedelta(seconds=attempt))
        denied = [
            record
            for record in caplog.records
            if getattr(record, "event", None) == "rate_limit.denied"
        ]
        assert len(denied) == 1
        fields = vars(denied[0])
        assert fields["scope"] == small.scope
        assert fields["limit"] == small.limit
        # The digest, never the address: log lines are shipped off-box (§127).
        assert EMAIL not in fields["identifier"]
        assert len(fields["identifier"]) == 32


class TestWhenRedisIsUnavailable:
    async def test_an_auth_scope_fails_closed(self, small: RateLimit) -> None:
        """Taking Redis down must not remove the credential-stuffing defence.

        An attacker does not have to defeat the limiter, only its dependency, so
        the limiter refuses the request instead of admitting traffic it cannot
        police.
        """
        broken = RateLimiter(redis=unreachable_redis(), enabled=True)
        with pytest.raises(DependencyUnavailableError) as excinfo:
            await broken.check(LOGIN_BY_IP, identifier=IP)
        # 503 and not 429: the client has done nothing wrong, and a 429 would imply
        # their requests were being counted when nothing was counted at all.
        assert excinfo.value.http_status == 503
        assert excinfo.value.context == {"scope": LOGIN_BY_IP.scope, "dependency": "redis"}

    async def test_failing_closed_is_logged_as_an_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A fail-closed refusal produces a 503 the client cannot explain. Without
        this line an operator sees 503s on every login with no cause, and cannot
        tell an outage (ConnectionError) from a defect in the script
        (ResponseError: "Error running script") — which need opposite responses."""
        caplog.set_level(logging.ERROR, logger="arb_core.security.ratelimit")
        broken = RateLimiter(redis=unreachable_redis(), enabled=True)
        with pytest.raises(DependencyUnavailableError):
            await broken.check(LOGIN_BY_IP, identifier=IP)
        events = [
            record
            for record in caplog.records
            if getattr(record, "event", None) == "rate_limit.fail_closed"
        ]
        assert len(events) == 1
        assert events[0].levelno == logging.ERROR
        assert vars(events[0])["scope"] == LOGIN_BY_IP.scope
        assert vars(events[0])["error_type"]

    async def test_a_read_scope_fails_open(self) -> None:
        """The same outage must not take the whole API offline for a control that
        protects capacity rather than credentials."""
        broken = RateLimiter(redis=unreachable_redis(), enabled=True)
        assert API_PER_USER.fail_closed is False
        decision = await broken.check(API_PER_USER, identifier="user-id-1")
        assert decision.allowed is True
        assert decision.enforced is False

    async def test_failing_open_is_loud(self, caplog: pytest.LogCaptureFixture) -> None:
        """§148 forbids silent degradation: an unenforced request must be visible
        in the log, and ``enforced=False`` stops the middleware from publishing
        ``RateLimit-*`` headers that would claim a limit was applied."""
        caplog.set_level(logging.WARNING, logger="arb_core.security.ratelimit")
        broken = RateLimiter(redis=unreachable_redis(), enabled=True)
        await broken.check(API_PER_USER, identifier="user-id-1")
        events = [
            record
            for record in caplog.records
            if getattr(record, "event", None) == "rate_limit.fail_open"
        ]
        assert len(events) == 1
        assert events[0].levelno == logging.WARNING

    async def test_a_failed_reset_does_not_fail_a_login(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Refusing a *successful* login because a cache clear failed would be worse
        than the small over-count it leaves behind; the bucket expires anyway."""
        caplog.set_level(logging.WARNING, logger="arb_core.security.ratelimit")
        broken = RateLimiter(redis=unreachable_redis(), enabled=True)
        assert await broken.reset(LOGIN_BY_ACCOUNT, identifier=EMAIL) is False
        assert any(
            getattr(record, "event", None) == "rate_limit.reset_failed" for record in caplog.records
        )


class TestValidation:
    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"scope": "s", "limit": 0, "window": timedelta(seconds=1)}, "at least 1"),
            ({"scope": "s", "limit": -5, "window": timedelta(seconds=1)}, "at least 1"),
            ({"scope": "s", "limit": 1, "window": timedelta(0)}, "positive"),
            ({"scope": "s", "limit": 1, "window": timedelta(seconds=-1)}, "positive"),
            ({"scope": "", "limit": 1, "window": timedelta(seconds=1)}, "scope"),
            ({"scope": "   ", "limit": 1, "window": timedelta(seconds=1)}, "scope"),
        ],
    )
    def test_a_nonsensical_limit_is_refused(self, kwargs: dict[str, object], match: str) -> None:
        """``limit=0`` would mean "deny everything" — a kill switch wearing a rate
        limiter's clothes. If that is wanted, it should be said explicitly."""
        with pytest.raises(ValueError, match=match):
            RateLimit(**kwargs)  # type: ignore[arg-type]

    def test_an_over_long_scope_is_refused(self) -> None:
        """Scopes are metrics labels and Redis key parts; an unbounded one is how a
        monitoring backend is taken down by the thing monitoring it."""
        with pytest.raises(ValueError, match="scope"):
            RateLimit(scope="a:b:c:d:e", limit=1, window=timedelta(seconds=1))

    @pytest.mark.parametrize("identifier", ["", "   ", "\t\n"])
    async def test_a_blank_identifier_is_refused(
        self, limiter: RateLimiter, small: RateLimit, identifier: str
    ) -> None:
        """Every anonymous request would otherwise share one bucket, and one
        attacker would exhaust it for all of them."""
        with pytest.raises(ValueError, match="identifier"):
            await limiter.check(small, identifier=identifier, now=BASE)

    def test_window_ms_is_exact(self) -> None:
        assert RateLimit(scope="s", limit=1, window=timedelta(minutes=15)).window_ms == 900_000
        assert RateLimit(scope="s", limit=1, window=timedelta(milliseconds=500)).window_ms == 500


class TestScriptPortability:
    def test_the_script_does_not_use_withscores(self) -> None:
        """Real Redis returns ``ZRANGE ... WITHSCORES`` as a flat
        ``[member, score]`` array; fakeredis/lupa — which every test here runs
        against — returns a nested one. Indexing it portably is impossible, so the
        denial path uses ``ZRANGE`` plus ``ZSCORE``, which behave identically in
        both. This guard exists because "simplifying" back to ``WITHSCORES`` looks
        like an improvement and breaks either the tests or production.

        Lua comments are stripped first: the script carries a comment naming
        ``WITHSCORES`` precisely to explain why it is absent, and a guard that
        trips over its own documentation is a guard nobody will keep.
        """
        code = "\n".join(line.split("--", 1)[0] for line in _SCRIPT.splitlines())
        assert "WITHSCORES" not in code.upper()
        assert "ZSCORE" in code.upper()

    def test_the_script_prunes_before_counting(self) -> None:
        """Counting first would include requests that have already left the
        window, throttling users who are within their budget."""
        assert _SCRIPT.index("ZREMRANGEBYSCORE") < _SCRIPT.index("ZCARD")

    def test_the_script_sets_a_key_expiry(self) -> None:
        assert "PEXPIRE" in _SCRIPT


class TestPresetThresholds:
    @pytest.mark.parametrize(
        "preset",
        [
            LOGIN_BY_IP,
            LOGIN_BY_ACCOUNT,
            REGISTER_BY_IP,
            PASSWORD_RESET_BY_IP,
            MFA_VERIFY_BY_ACCOUNT,
            REFRESH_BY_IP,
        ],
    )
    def test_every_auth_preset_fails_closed(self, preset: RateLimit) -> None:
        assert preset.fail_closed is True

    def test_bulk_read_preset_fails_open(self) -> None:
        assert API_PER_USER.fail_closed is False

    def test_the_account_limit_is_looser_than_the_lockout(self) -> None:
        """§59 locks an account after five failures. The rate limit must be looser,
        so a user who mistypes their password meets the lockout — with its
        explanatory message and ``Retry-After`` — rather than an unexplained 429
        from a layer they cannot see."""
        assert LOGIN_BY_ACCOUNT.limit > 5
        assert LOGIN_BY_ACCOUNT.window <= timedelta(minutes=15)

    def test_the_ip_limit_is_looser_still(self) -> None:
        """A household NAT, a university or an office shares one address; punishing
        all of them for one user's behaviour is both unfair and a support burden."""
        assert LOGIN_BY_IP.limit > LOGIN_BY_ACCOUNT.limit

    def test_registration_is_the_tightest_auth_preset(self) -> None:
        """Account creation is what an attacker automates for spam and for farming
        free-tier entitlements, and no legitimate client does it five times an hour."""
        assert REGISTER_BY_IP.limit <= 5

    def test_the_mfa_limit_bounds_a_code_guessing_attack(self) -> None:
        """§59: a TOTP code is six digits, so one million candidates. Ten attempts
        per fifteen minutes puts the expected time to guess a code at over a year,
        which is the actual control — the code length alone is not enough once an
        attacker holds a valid MFA challenge."""
        codes = 10**6
        attempts_per_window = MFA_VERIFY_BY_ACCOUNT.limit
        windows_needed = codes / attempts_per_window
        expected_time = windows_needed * MFA_VERIFY_BY_ACCOUNT.window
        assert expected_time > timedelta(days=30)

    def test_refresh_is_the_loosest_auth_preset(self) -> None:
        """Token refresh is chatty by design: one call per access-token lifetime
        per session, across every open tab."""
        assert REFRESH_BY_IP.limit > LOGIN_BY_IP.limit
        assert REFRESH_BY_IP.limit >= 60

    def test_password_reset_is_limited_because_it_sends_email(self) -> None:
        """Limited twice over: here, and by the delivery provider's own throttling."""
        assert PASSWORD_RESET_BY_IP.limit <= 5
