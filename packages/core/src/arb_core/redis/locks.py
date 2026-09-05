"""Distributed locking (§65).

Used to guarantee that a given unit of work happens at most once across the
whole fleet — the same opportunity is never executed twice, a bot is never run
by two workers, an order is never submitted twice, and two rebalancing passes
never race.

Correctness properties, all of which matter because the thing being protected is
a live order:

* **Ownership.** The lock value is a per-acquisition random token. Release and
  renewal are Lua compare-and-delete / compare-and-expire, so a process that
  overran its TTL can never release or extend a lock that another process now
  owns. A plain ``GET`` followed by ``DEL`` would allow exactly that.
* **Bounded lifetime.** Every lock has a TTL. A crashed holder cannot wedge the
  system forever.
* **Renewal.** Long operations pass ``auto_renew=True`` and the TTL is extended
  at one third of its lifetime. Without this, a slow exchange response can let
  the lock expire mid-trade — after which a second worker executes the *same*
  opportunity, which is a duplicate live order (§62).
* **Safe release.** Failing to acquire is reported as ``False`` (or as
  :class:`LockNotAcquiredError` from :meth:`RedisLock.hold`), never as a
  silently-held lock. Critically, the ``async with`` forms **raise** when the
  lock was not taken, so a protected block can never run unprotected.

These are *advisory* locks built on Redis. They are the right tool for
coordinating our own workers, but they are not a substitute for database-level
uniqueness: anything that must be unique even if Redis is unavailable or flushed
also needs a unique constraint in PostgreSQL (§64).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, ClassVar, Final, Self

from arb_core.errors import ConflictError, ErrorCode
from arb_core.identifiers import uuid7
from arb_core.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from arb_core.redis.client import RedisClient

__all__ = ["LockNotAcquiredError", "RedisLock"]

_logger = get_logger(__name__)

_RELEASE_SCRIPT: Final[str] = """
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
"""

_EXTEND_SCRIPT: Final[str] = """
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("pexpire", KEYS[1], ARGV[2])
else
  return 0
end
"""

#: Renew at one third of the TTL so two consecutive failed renewals still leave
#: the lock valid.
_RENEW_DIVISOR: Final[float] = 3.0
_DEFAULT_TTL_SECONDS: Final[float] = 30.0
_DEFAULT_ACQUIRE_TIMEOUT_SECONDS: Final[float] = 0.0
_RETRY_INTERVAL_SECONDS: Final[float] = 0.05


class LockNotAcquiredError(ConflictError):
    """Raised by :meth:`RedisLock.hold` when the lock is held elsewhere."""

    default_message: ClassVar[str] = "The operation is already in progress."

    def __init__(self, lock_name: str, *, message: str | None = None) -> None:
        super().__init__(
            message or f"could not acquire lock '{lock_name}'",
            code=ErrorCode.CONFLICT,
            details={"lock": lock_name},
        )


class RedisLock:
    """An owner-token Redis lock with TTL, optional renewal and safe release."""

    def __init__(
        self,
        redis: RedisClient,
        name: str,
        *,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
        owner: str | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            msg = "lock ttl_seconds must be positive; a lock with no expiry can wedge the system"
            raise ValueError(msg)
        self._redis = redis
        self._name = name
        self._key = redis.key("lock", name)
        self._ttl_ms = int(ttl_seconds * 1000)
        self._owner = owner or str(uuid7())
        self._held = False
        self._renew_task: asyncio.Task[None] | None = None
        # register_script() transparently uses EVALSHA with an EVAL fallback,
        # which avoids shipping the script body on every call.
        self._release = redis.raw.register_script(_RELEASE_SCRIPT)
        self._extend = redis.raw.register_script(_EXTEND_SCRIPT)

    # --- introspection ---------------------------------------------------
    @property
    def name(self) -> str:
        """Logical lock name (without the Redis key prefix)."""
        return self._name

    @property
    def key(self) -> str:
        """Fully-qualified Redis key."""
        return self._key

    @property
    def owner(self) -> str:
        """Token identifying this acquisition."""
        return self._owner

    @property
    def held(self) -> bool:
        """``True`` once :meth:`acquire` succeeded and before release."""
        return self._held

    # --- acquire / release -----------------------------------------------
    async def acquire(
        self,
        *,
        timeout_seconds: float = _DEFAULT_ACQUIRE_TIMEOUT_SECONDS,
        retry_interval_seconds: float = _RETRY_INTERVAL_SECONDS,
        auto_renew: bool = False,
    ) -> bool:
        """Try to take the lock.

        With ``timeout_seconds=0`` (the default) this is a single non-blocking
        attempt, which is what opportunity execution wants: if another worker
        already holds it, skip and move on. A positive timeout polls until the
        deadline.
        """
        if timeout_seconds < 0:
            msg = "timeout_seconds must be non-negative"
            raise ValueError(msg)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while True:
            acquired = await self._redis.raw.set(self._key, self._owner, nx=True, px=self._ttl_ms)
            if acquired:
                self._held = True
                _logger.debug(
                    "lock acquired",
                    extra={"lock": self._name, "lock_key": self._key, "ttl_ms": self._ttl_ms},
                )
                if auto_renew:
                    self._start_renewal()
                return True
            if loop.time() >= deadline:
                _logger.debug(
                    "lock not acquired", extra={"lock": self._name, "lock_key": self._key}
                )
                return False
            await asyncio.sleep(retry_interval_seconds)

    async def release(self) -> bool:
        """Release the lock **only if this instance still owns it**."""
        await self._stop_renewal()

        if not self._held:
            return False

        released = int(await self._release(keys=[self._key], args=[self._owner]) or 0)
        self._held = False
        if not released:
            # The TTL expired and somebody else now holds the lock. This is a
            # correctness signal, not benign cleanup: the work that was
            # protected may have been duplicated.
            _logger.warning(
                "lock was not owned at release time; it may have expired and been "
                "re-acquired by another worker",
                extra={"lock": self._name, "lock_key": self._key},
            )
            return False
        _logger.debug("lock released", extra={"lock": self._name, "lock_key": self._key})
        return True

    async def extend(self, ttl_seconds: float | None = None) -> bool:
        """Extend the TTL, but only if this instance still owns the lock."""
        if not self._held:
            return False
        ttl_ms = self._ttl_ms if ttl_seconds is None else int(ttl_seconds * 1000)
        extended = int(await self._extend(keys=[self._key], args=[self._owner, str(ttl_ms)]) or 0)
        if not extended:
            self._held = False
            _logger.warning(
                "lock renewal failed; ownership was lost",
                extra={"lock": self._name, "lock_key": self._key},
            )
        return bool(extended)

    @contextlib.asynccontextmanager
    async def hold(
        self,
        *,
        timeout_seconds: float = _DEFAULT_ACQUIRE_TIMEOUT_SECONDS,
        auto_renew: bool = True,
    ) -> AsyncIterator[None]:
        """Async context manager that raises if the lock cannot be taken.

        Renewal is on by default here because a caller using a context manager
        is typically wrapping a block whose duration it does not control.
        """
        if not await self.acquire(timeout_seconds=timeout_seconds, auto_renew=auto_renew):
            raise LockNotAcquiredError(self._name)
        try:
            yield
        finally:
            await self.release()

    # --- internals -------------------------------------------------------
    def _start_renewal(self) -> None:
        interval = (self._ttl_ms / 1000) / _RENEW_DIVISOR
        self._renew_task = asyncio.create_task(
            self._renew_loop(interval), name=f"lock-renew:{self._name}"
        )

    async def _stop_renewal(self) -> None:
        task = self._renew_task
        self._renew_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _renew_loop(self, interval: float) -> None:
        while self._held:
            await asyncio.sleep(interval)
            # No separate `_held` re-check here: extend() returns False when
            # ownership has been lost, and the branch below exits on that, so a
            # release during the sleep is already handled exactly once.
            try:
                if not await self.extend():
                    return
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - keep the loop alive through transient errors
                _logger.warning(
                    "lock renewal attempt errored; will retry",
                    extra={"lock": self._name, "lock_key": self._key},
                )

    async def __aenter__(self) -> Self:
        """Acquire with renewal, raising if the lock is held elsewhere."""
        if not await self.acquire(auto_renew=True):
            raise LockNotAcquiredError(self._name)
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Release the lock on exit."""
        await self.release()
