"""Redis-backed rate limiting (§61).

Two layers defend the authentication endpoints, and it matters that they are not
the same thing:

* **This limiter** is volumetric and cheap. It answers "is this IP or this account
  making an implausible number of attempts?" in one Redis round trip, with no
  database involvement, and it is what stops a credential-stuffing run from ever
  reaching the password hasher — which is the real cost, since a single argon2id
  verification is deliberately tens of milliseconds of CPU (§59).
* **Account lockout** lives in PostgreSQL (``failed_login_count``,
  ``locked_until`` on the user row). It is authoritative, survives a Redis flush,
  and is what produces the explained ``423 ACCOUNT_LOCKED`` with ``Retry-After``.

The limits here are therefore set *looser* than the lockout threshold on purpose:
a user typing their password wrong five times should get the lockout message that
tells them what happened, not a bare 429 from a layer they cannot see.

Sliding window log
------------------

A sorted set per bucket, members scored by request time in milliseconds. One Lua
script prunes the window, counts, and admits — atomically, so two concurrent
requests cannot both observe ``limit - 1`` and both proceed.

The sliding *log* is used rather than a fixed-window counter because a fixed window
permits twice the intended rate across a boundary: five attempts at 12:14:59 and
five at 12:15:01 are ten attempts in two seconds against a limit of five per
fifteen minutes. For a control whose entire job is bounding password attempts, that
is the difference between a limit and a suggestion. The log costs a few hundred
bytes per bucket and the buckets are short-lived.

Identifiers are hashed before they become keys
----------------------------------------------

``login:ip:203.0.113.7`` and ``login:account:user@example.com`` would both be
legible in a ``KEYS`` scan, a ``MONITOR`` session, an RDB backup or a support
snapshot of a misbehaving Redis. Redis is a cache with weaker access controls than
PostgreSQL (§64), so nothing that identifies a person is written to it: the key
carries a SHA-256 digest instead. The digest is stable, so it still groups requests
correctly, and it is what appears in log lines for the same reason.

Failure behaviour
-----------------

If Redis is unreachable the limiter cannot know whether a limit is exceeded. For
authentication scopes that is answered **fail-closed**: :meth:`RateLimiter.enforce`
raises :class:`~arb_core.errors.DependencyUnavailableError` (503) rather than
admitting traffic it cannot police, because the alternative is that taking Redis
down removes the credential-stuffing defence — an attacker does not need to break
the limiter, only its dependency. For high-volume read scopes the same outage would
take the whole API down for a control that is not protecting anything irreplaceable,
so those presets fail **open**, loudly: a warning log and ``enforced=False`` on the
decision, which the middleware surfaces by omitting ``RateLimit-*`` headers rather
than claiming a limit was applied (§148: no silent degradation).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from uuid import uuid4

from arb_core.clock import utc_now
from arb_core.errors import DependencyUnavailableError, RateLimitedError
from arb_core.log import get_logger

if TYPE_CHECKING:
    from arb_core.redis.client import RedisClient

__all__ = [
    "API_PER_USER",
    "LOGIN_BY_ACCOUNT",
    "LOGIN_BY_IP",
    "MFA_VERIFY_BY_ACCOUNT",
    "PASSWORD_RESET_BY_IP",
    "REFRESH_BY_IP",
    "REGISTER_BY_IP",
    "RateLimit",
    "RateLimitDecision",
    "RateLimiter",
]

_logger = get_logger(__name__)

#: Prune, count and admit in one round trip. Returning the numbers as strings
#: avoids Lua's double-precision round trip on millisecond timestamps, which are
#: large enough that a float conversion can lose the last digit.
_SCRIPT: Final[str] = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local ttl_ms = tonumber(ARGV[5])

if limit <= 0 then
  return {0, tostring(window), tostring(now + window)}
end

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)

if count >= limit then
  -- ZRANGE ... WITHSCORES is deliberately not used: real Redis returns a flat
  -- [member, score] array while fakeredis/lupa (which the tests run against)
  -- returns a nested one, so indexing it portably is impossible. ZRANGE plus
  -- ZSCORE returns a member and a bulk-string score in both, identically.
  local oldest = redis.call('ZRANGE', key, 0, 0)
  local oldest_at = tonumber(redis.call('ZSCORE', key, oldest[1]))
  return {0, tostring(oldest_at + window - now), tostring(oldest_at + window)}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, ttl_ms)
return {1, '0', tostring(now + window), tostring(limit - count - 1)}
"""

#: Removes a bucket entirely, so a successful login clears the attempts that
#: preceded it (§61).
_RESET_SCRIPT: Final[str] = """
return redis.call('DEL', KEYS[1])
"""

#: Extra lifetime beyond the window, so an idle bucket disappears on its own
#: instead of accumulating one key per identifier forever.
_KEY_GRACE_MS: Final[int] = 60_000

#: Truncated digest length for keys and log correlation. 128 bits is far past any
#: collision concern here and keeps keys short.
_DIGEST_CHARS: Final[int] = 32


@dataclass(frozen=True, slots=True)
class RateLimit:
    """A limit: at most ``limit`` requests per ``window``, under ``scope``.

    ``scope`` names the control, not the caller — ``auth:login:ip`` — and appears
    in the Redis key, in log lines and in metrics labels, so it must be a fixed
    set of values. Never build a scope from request data: an unbounded label
    cardinality is how a metrics backend is taken down by the thing monitoring it.
    """

    scope: str
    limit: int
    window: timedelta
    #: Deny when Redis is unreachable. ``True`` for anything protecting a
    #: credential; see the module docstring for why reads differ.
    fail_closed: bool = True

    def __post_init__(self) -> None:
        if not self.scope.strip():
            msg = "a rate limit needs a scope"
            raise ValueError(msg)
        if ":" in self.scope and self.scope.count(":") > 3:
            msg = "scope should be a short colon-separated label"
            raise ValueError(msg)
        if self.limit < 1:
            # Zero would mean "deny everything", which is a kill switch wearing a
            # rate limiter's clothes. If that is what is wanted, say so explicitly.
            msg = "limit must be at least 1; use a feature flag to disable an endpoint"
            raise ValueError(msg)
        if self.window <= timedelta(0):
            msg = "window must be positive"
            raise ValueError(msg)

    @property
    def window_ms(self) -> int:
        """The window in milliseconds, as the Lua script wants it."""
        return int(self.window.total_seconds() * 1000)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """The outcome of one check.

    ``enforced`` is ``False`` when no limit was actually applied — the limiter is
    disabled, or Redis was unreachable and the scope fails open. Callers must not
    publish ``RateLimit-*`` headers or count the request against a quota in that
    case, because doing so would tell a client it is being limited when it is not.
    """

    allowed: bool
    enforced: bool
    scope: str
    limit: int
    remaining: int | None
    retry_after: timedelta | None
    reset_at: datetime | None


class RateLimiter:
    """Applies :class:`RateLimit` presets through Redis."""

    def __init__(self, *, redis: RedisClient, enabled: bool = True) -> None:
        self._redis = redis
        self._enabled = enabled
        # register_script() uses EVALSHA with an EVAL fallback, so the script body
        # is not shipped on every request (as in arb_core.redis.locks).
        self._check = redis.raw.register_script(_SCRIPT)
        self._reset = redis.raw.register_script(_RESET_SCRIPT)

    @classmethod
    def from_settings(cls, settings: Any, redis: RedisClient) -> RateLimiter:
        """Build from configuration, honouring ``RATE_LIMIT_ENABLED``.

        ``settings`` is typed loosely here so the limiter can be constructed in
        tests and tools without a full :class:`~arb_core.config.Settings`; the only
        attribute read is ``rate_limit_enabled``.
        """
        return cls(redis=redis, enabled=bool(getattr(settings, "rate_limit_enabled", True)))

    @property
    def enabled(self) -> bool:
        """Whether limits are applied at all."""
        return self._enabled

    async def check(
        self,
        limit: RateLimit,
        *,
        identifier: str,
        now: datetime | None = None,
    ) -> RateLimitDecision:
        """Record one request against ``limit`` and report whether it is allowed.

        ``now`` may be supplied to make the window deterministic; in production it
        comes from :func:`arb_core.clock.utc_now`. Application clocks rather than
        Redis ``TIME`` are used deliberately: every replica then agrees with the
        timestamps it writes into its own logs and metrics, and a few milliseconds
        of NTP skew is immaterial against a fifteen-minute window. It also keeps the
        script free of non-deterministic commands, so it behaves identically under
        script replication and in tests.
        """
        if not identifier.strip():
            msg = "a rate limit identifier is required"
            raise ValueError(msg)
        if not self._enabled:
            return RateLimitDecision(
                allowed=True,
                enforced=False,
                scope=limit.scope,
                limit=limit.limit,
                remaining=None,
                retry_after=None,
                reset_at=None,
            )

        moment = now or utc_now()
        now_ms = int(moment.timestamp() * 1000)
        digest = _digest(identifier)
        key = self._redis.key("rl", limit.scope.replace(":", "-"), digest)
        # Unique per request: ZADD on an existing member would overwrite its score
        # and silently shrink the count, which is exactly the undercount that lets
        # a burst through.
        member = f"{now_ms}:{uuid4().hex}"

        try:
            raw = await self._check(
                keys=[key],
                args=[
                    now_ms,
                    limit.window_ms,
                    limit.limit,
                    member,
                    limit.window_ms + _KEY_GRACE_MS,
                ],
            )
        except Exception as exc:  # noqa: BLE001 - any driver fault means "cannot police"
            return await self._on_redis_failure(limit, digest=digest, cause=exc)

        allowed = bool(int(raw[0]))
        retry_after_ms = int(raw[1])
        reset_at = _from_ms(int(raw[2]))
        remaining = int(raw[3]) if allowed and len(raw) > 3 else 0
        if not allowed:
            _logger.info(
                "rate limit exceeded",
                extra={
                    "event": "rate_limit.denied",
                    "scope": limit.scope,
                    "identifier": digest,
                    "limit": limit.limit,
                    "retry_after_ms": retry_after_ms,
                },
            )
        return RateLimitDecision(
            allowed=allowed,
            enforced=True,
            scope=limit.scope,
            limit=limit.limit,
            remaining=remaining,
            retry_after=timedelta(milliseconds=retry_after_ms) if not allowed else None,
            reset_at=reset_at,
        )

    async def enforce(
        self,
        limit: RateLimit,
        *,
        identifier: str,
        now: datetime | None = None,
    ) -> RateLimitDecision:
        """Check a limit and raise :class:`RateLimitedError` if it is exceeded.

        The raised error carries ``Retry-After``, so a client can back off exactly
        instead of retrying on a guess.
        """
        decision = await self.check(limit, identifier=identifier, now=now)
        if not decision.allowed:
            retry_after = decision.retry_after
            seconds = max(1, int(retry_after.total_seconds()) + 1) if retry_after else None
            raise RateLimitedError(
                retry_after_seconds=seconds,
                context={"scope": limit.scope, "limit": limit.limit},
            )
        return decision

    async def reset(self, limit: RateLimit, *, identifier: str) -> bool:
        """Clear a bucket, so a successful login forgets the failed attempts.

        Returns whether a bucket existed. Resetting is what makes the limit count
        *consecutive* abuse rather than lifetime abuse: without it, a user who once
        mistyped their password eleven times would be throttled forever.
        """
        if not self._enabled:
            return False
        digest = _digest(identifier)
        key = self._redis.key("rl", limit.scope.replace(":", "-"), digest)
        try:
            removed = await self._reset(keys=[key], args=[])
        except Exception as exc:  # noqa: BLE001 - a failed reset must not fail a login
            # Failing open here is safe: the bucket expires on its own, and refusing
            # a *successful* login because a cache clear failed would be worse than
            # the tiny over-count it leaves behind.
            _logger.warning(
                "rate limit reset failed",
                extra={
                    "event": "rate_limit.reset_failed",
                    "scope": limit.scope,
                    "identifier": digest,
                    "error_type": type(exc).__name__,
                },
            )
            return False
        return bool(int(removed or 0))

    async def _on_redis_failure(
        self, limit: RateLimit, *, digest: str, cause: BaseException
    ) -> RateLimitDecision:
        """Decide what an unreachable Redis means for this scope."""
        if limit.fail_closed:
            # Logged at ERROR, with the driver's exception type: a fail-closed
            # refusal produces a 503 the client cannot explain, and without this
            # line an operator sees 503s on every login with no indication that the
            # cause is the limiter's dependency. The type also distinguishes an
            # outage (ConnectionError, TimeoutError) from a defect in the script
            # itself (ResponseError: "Error running script"), which look identical
            # from the outside and need very different responses (§139).
            _logger.error(
                "rate limiter unavailable; refusing request",
                extra={
                    "event": "rate_limit.fail_closed",
                    "scope": limit.scope,
                    "identifier": digest,
                    "error_type": type(cause).__name__,
                },
            )
            # 503 rather than 429: the client has not done anything wrong, and a
            # 429 would tell an attacker their volume attack is being noticed and
            # counted when in fact nothing is being counted at all.
            raise DependencyUnavailableError(
                "Rate limiting is temporarily unavailable.",
                context={"scope": limit.scope, "dependency": "redis"},
            ) from cause
        _logger.warning(
            "rate limiter unavailable; allowing request without enforcement",
            extra={
                "event": "rate_limit.fail_open",
                "scope": limit.scope,
                "identifier": digest,
                "error_type": type(cause).__name__,
            },
        )
        return RateLimitDecision(
            allowed=True,
            enforced=False,
            scope=limit.scope,
            limit=limit.limit,
            remaining=None,
            retry_after=None,
            reset_at=None,
        )


def _digest(identifier: str) -> str:
    """Hash an identifier so it can be used as a Redis key and a log label."""
    return hashlib.sha256(identifier.strip().encode("utf-8")).hexdigest()[:_DIGEST_CHARS]


def _from_ms(value: int) -> datetime:
    """Convert a millisecond timestamp from the script to an aware datetime."""
    return datetime.fromtimestamp(value / 1000, UTC)


# --- Presets -----------------------------------------------------------------
# Thresholds live in code for now so each one sits next to the reasoning for its
# value; promoting them to Settings is a mechanical change when an operator needs
# to tune one without a deploy.

#: Per source IP. Generous enough that a household NAT, a university or an office
#: behind one address is not punished, and low enough that a distributed guesser
#: gets very little from a single address.
LOGIN_BY_IP: Final[RateLimit] = RateLimit(
    scope="auth:login:ip", limit=30, window=timedelta(minutes=15)
)

#: Per account. Deliberately looser than the five-failure lockout in PostgreSQL
#: (§59): the lockout should be what a user hits, with its explanatory message, and
#: this limit only catches something far more aggressive than mistyping a password.
LOGIN_BY_ACCOUNT: Final[RateLimit] = RateLimit(
    scope="auth:login:account", limit=10, window=timedelta(minutes=15)
)

#: Per source IP. Account creation is the one endpoint an attacker wants to
#: automate for spam and for farming free-tier entitlements, and no legitimate
#: client creates five accounts an hour.
REGISTER_BY_IP: Final[RateLimit] = RateLimit(
    scope="auth:register:ip", limit=5, window=timedelta(hours=1)
)

#: Per source IP. Also an email-sending endpoint, so it is limited twice over:
#: here, and by the delivery provider's own throttling.
PASSWORD_RESET_BY_IP: Final[RateLimit] = RateLimit(
    scope="auth:password-reset:ip", limit=5, window=timedelta(hours=1)
)

#: Per account. TOTP codes are six digits, so without a limit an attacker holding
#: a valid MFA challenge could try them all; ten attempts per fifteen minutes keeps
#: the expected time to guess a code measured in years (§59).
MFA_VERIFY_BY_ACCOUNT: Final[RateLimit] = RateLimit(
    scope="auth:mfa:account", limit=10, window=timedelta(minutes=15)
)

#: Per source IP. Token refresh is chatty by design — one call per access-token
#: lifetime per session — so this is the loosest of the auth limits.
REFRESH_BY_IP: Final[RateLimit] = RateLimit(
    scope="auth:refresh:ip", limit=120, window=timedelta(minutes=15)
)

#: Per authenticated user across the whole API. Fails **open**: this protects
#: capacity, not credentials, and taking the entire API offline because Redis
#: restarted would be a worse outcome than a brief period of unpoliced traffic.
API_PER_USER: Final[RateLimit] = RateLimit(
    scope="api:user", limit=600, window=timedelta(minutes=1), fail_closed=False
)
