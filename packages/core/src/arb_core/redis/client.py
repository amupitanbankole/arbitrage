"""Async Redis access (§64).

Redis is used for caching, pub/sub, real-time event fan-out, distributed locks,
rate limiting and transient worker state. It is **never** the authoritative
store for anything financial: PostgreSQL is the source of truth, and any value
that would be a problem to lose must be persisted there in the same operation
that produced it (§64, §100).

Consequences of that rule, enforced by this module:

* Keys are namespaced with a configurable prefix so several environments can
  share one Redis server without cross-contamination.
* The connection URL is only ever exposed masked (:attr:`RedisClient.url_safe`),
  because Redis URLs may carry a password (§133).
* :meth:`RedisClient.probe` reports ``UNAVAILABLE`` instead of raising, so a
  Redis outage degrades the platform (no cache, no locks, no live fan-out)
  rather than taking down unrelated endpoints (§25, §139).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from redis.asyncio import Redis
from redis.asyncio.connection import ConnectionPool

from arb_core.clock import duration_ms, utc_now
from arb_core.health import ComponentCheck, HealthState
from arb_core.log import get_logger
from arb_core.security.redaction import mask_dsn

if TYPE_CHECKING:
    from arb_core.config import Settings

__all__ = ["RedisClient", "decode"]

_logger = get_logger(__name__)

_DEGRADED_AFTER_MS = 100


def decode(value: Any) -> Any:
    """Normalise a Redis reply to ``str``/``int``/``None``.

    With ``decode_responses=False`` the driver returns bytes. Callers should not
    have to care, and silently ``.decode()``-ing at each call site is how
    ``b'1'`` ends up compared against ``'1'`` in a trading decision.
    """
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes | bytearray):
        return value.decode()
    return value


class RedisClient:
    """Thin, prefix-aware wrapper around ``redis.asyncio.Redis``."""

    def __init__(
        self,
        client: Redis,
        *,
        key_prefix: str,
        url_safe: str,
    ) -> None:
        self._client = client
        self._key_prefix = key_prefix.strip(":")
        self._url_safe = url_safe

    # --- construction ----------------------------------------------------
    @classmethod
    def create(cls, url: str, *, key_prefix: str = "arb", **kwargs: Any) -> RedisClient:
        """Create a client with its own connection pool."""
        pool = ConnectionPool.from_url(url, **kwargs)
        client: Redis = Redis(connection_pool=pool)
        return cls(client, key_prefix=key_prefix, url_safe=mask_dsn(url))

    @classmethod
    def from_settings(cls, settings: Settings) -> RedisClient:
        """Create a client using configuration from :class:`Settings`."""
        return cls.create(
            settings.redis_url.get_secret_value(),
            key_prefix=settings.redis_key_prefix,
            **settings.redis_connection_kwargs,
        )

    # --- accessors -------------------------------------------------------
    @property
    def raw(self) -> Redis:
        """The underlying driver client, for operations the wrapper lacks."""
        return self._client

    @property
    def url_safe(self) -> str:
        """Connection URL with any password masked — safe to log (§127)."""
        return self._url_safe

    @property
    def key_prefix(self) -> str:
        """Namespace applied to every key produced by :meth:`key`."""
        return self._key_prefix

    def key(self, *parts: str) -> str:
        """Build a namespaced key: ``prefix:part1:part2``."""
        joined = ":".join(str(part).strip(":") for part in parts if str(part) != "")
        return f"{self._key_prefix}:{joined}" if joined else self._key_prefix

    # --- lifecycle -------------------------------------------------------
    async def ping(self) -> bool:
        """Return ``True`` when the server answers ``PING``, else ``False``.

        Never raises. The signature promises a boolean and callers — health
        checks, worker warm-up, feature-flag caching — rely on that to degrade
        gracefully instead of propagating an outage. It also keeps redis-py's
        exception message out of the call stack: that message embeds the
        connection URL, which may contain the password (§133).
        """
        try:
            return bool(await self._client.ping())
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a ping is a check, not a failure
            _logger.warning(
                "redis ping failed",
                extra={"error_type": type(exc).__name__, "redis": self._url_safe},
            )
            return False

    async def probe(self, *, degraded_after_ms: int = _DEGRADED_AFTER_MS) -> ComponentCheck:
        """Round-trip ``PING`` and report state plus latency (§111)."""
        started = utc_now()
        try:
            await self._client.ping()
        except Exception as exc:  # noqa: BLE001 - probe must never raise
            _logger.warning(
                "redis health probe failed",
                extra={"error_type": type(exc).__name__, "redis": self._url_safe},
            )
            return ComponentCheck(
                name="redis",
                state=HealthState.UNAVAILABLE,
                latency_ms=duration_ms(started),
                # Type only: redis-py error messages can embed the URL, which
                # may contain the password (§133).
                detail=f"probe failed: {type(exc).__name__}",
            )

        latency = duration_ms(started)
        if latency > degraded_after_ms:
            return ComponentCheck(
                name="redis",
                state=HealthState.DEGRADED,
                latency_ms=latency,
                detail=f"probe latency {latency}ms exceeds {degraded_after_ms}ms",
            )
        return ComponentCheck(name="redis", state=HealthState.HEALTHY, latency_ms=latency)

    async def aclose(self) -> None:
        """Close the client and release the connection pool."""
        await self._client.aclose()
        _logger.info("redis client closed")
