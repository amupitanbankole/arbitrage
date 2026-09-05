"""Worker runtime (§55, §140).

One process model for every background role — market data, arbitrage, execution,
rebalancing, notifications — rather than five near-identical apps. A role is a
registered coroutine; the runtime supplies it with configuration, database,
Redis, an event bus and metrics, then handles the parts that are easy to get
wrong and expensive to get wrong in a trading system:

* **Heartbeats.** Written to Redis on an interval so the admin worker page and
  the ``workers_online`` gauge reflect reality (§55). A worker that is alive but
  wedged stops heartbeating and is reported missing.
* **Graceful shutdown.** ``SIGTERM``/``SIGINT`` set a stop event, roles unwind,
  dependencies are closed. This is what makes §140 restart-recovery possible:
  the worker is not killed mid-write.
* **Fail loudly.** If a role task exits — normally or with an error — the whole
  process shuts down and returns a non-zero exit code. A partially-functioning
  trading worker that keeps running is more dangerous than one the orchestrator
  restarts.

The runtime deliberately holds **no trading logic**. Roles are registered from
their own packages (``packages/market-data``, ``packages/trading-engine``, …) in
later phases; adding a worker never requires changing this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Final

from arb_core.clock import isoformat, utc_now
from arb_core.config import Settings, get_settings
from arb_core.db.session import Database
from arb_core.events import Event, EventType, InProcessEventBus
from arb_core.log import get_logger
from arb_core.metrics import Metrics
from arb_core.redis.client import RedisClient

__all__ = [
    "FOUNDATION_ROLE",
    "WorkerContext",
    "WorkerFn",
    "WorkerRuntime",
    "available_roles",
    "register_role",
    "run_periodically",
]

_logger = get_logger(__name__)

_DEFAULT_SHUTDOWN_GRACE_SECONDS: Final[float] = 15.0

#: Role name for the always-present process that only reports liveness. Used by
#: the platform's own smoke tests and by compose services that have no
#: phase-specific work yet.
FOUNDATION_ROLE: Final[str] = "foundation"


class WorkerContext:
    """Everything a role needs, injected by :class:`WorkerRuntime`."""

    def __init__(
        self,
        *,
        role: str,
        settings: Settings,
        database: Database | None,
        redis: RedisClient | None,
        events: InProcessEventBus,
        metrics: Metrics,
        stop_event: asyncio.Event,
        identity: str,
    ) -> None:
        self.role = role
        self.settings = settings
        self.database = database
        self.redis = redis
        self.events = events
        self.metrics = metrics
        self.stop_event = stop_event
        self.identity = identity
        self.logger = get_logger(f"arb_worker.{role}")
        self.started_at = utc_now()
        self.jobs_processed = 0
        self.jobs_failed = 0

    @property
    def stopping(self) -> bool:
        """``True`` once shutdown has been requested."""
        return self.stop_event.is_set()


WorkerFn = Callable[[WorkerContext], Awaitable[None]]

_role_registry: dict[str, WorkerFn] = {}


def register_role(name: str) -> Callable[[WorkerFn], WorkerFn]:
    """Decorator registering a coroutine as a worker role.

    Registering the same name twice raises: a silent override would mean the
    process runs different code than the one operators believe is deployed.
    """

    def decorator(fn: WorkerFn) -> WorkerFn:
        if name in _role_registry and _role_registry[name] is not fn:
            msg = f"worker role {name!r} is already registered"
            raise ValueError(msg)
        _role_registry[name] = fn
        return fn

    return decorator


def available_roles() -> tuple[str, ...]:
    """Names of every registered role, sorted."""
    return tuple(sorted(_role_registry))


@register_role(FOUNDATION_ROLE)
async def foundation_role(context: WorkerContext) -> None:
    """Idle role that keeps a process alive so it reports liveness.

    The heartbeat is written by :meth:`WorkerRuntime._heartbeat_loop` on its own
    task, so this coroutine's only job is to *not return* until shutdown is
    requested. Returning early would exit the process, because
    :meth:`WorkerRuntime._run_role` treats a normal return as "nothing left to
    do".

    Compose services that have no phase-specific work yet run this role, and the
    platform smoke tests use it to verify that heartbeats, staleness detection
    and graceful shutdown all function before any real job exists (§55, §140).
    """
    context.logger.info(
        "foundation role started",
        extra={"role": context.role, "identity": context.identity},
    )
    await context.stop_event.wait()
    context.logger.info(
        "foundation role stopping",
        extra={"role": context.role, "identity": context.identity},
    )


async def run_periodically(
    context: WorkerContext,
    *,
    interval_seconds: float,
    fn: Callable[[WorkerContext], Awaitable[None]],
) -> None:
    """Call ``fn`` every ``interval_seconds`` until shutdown is requested.

    Exceptions are caught, counted and logged so one failed cycle cannot kill the
    role — but cancellation propagates, which is how graceful shutdown works.
    """
    if interval_seconds <= 0:
        msg = "interval_seconds must be positive"
        raise ValueError(msg)

    while not context.stopping:
        try:
            await fn(context)
            context.jobs_processed += 1
            context.metrics.worker_jobs_total.labels(role=context.role, result="success").inc()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # the loop must survive a bad cycle
            context.jobs_failed += 1
            context.metrics.worker_jobs_total.labels(role=context.role, result="failure").inc()
            context.metrics.worker_failures_total.labels(
                role=context.role, error_type=type(exc).__name__
            ).inc()
            context.logger.exception("periodic job failed", extra={"role": context.role})

        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(context.stop_event.wait(), timeout=interval_seconds)


class WorkerRuntime:
    """Owns dependency construction, role tasks, heartbeats and shutdown."""

    def __init__(
        self,
        roles: Sequence[str],
        *,
        settings: Settings | None = None,
        database: Database | None = None,
        redis: RedisClient | None = None,
        events: InProcessEventBus | None = None,
        metrics: Metrics | None = None,
        shutdown_grace_seconds: float = _DEFAULT_SHUTDOWN_GRACE_SECONDS,
    ) -> None:
        if not roles:
            msg = "at least one worker role must be specified"
            raise ValueError(msg)

        unknown = [role for role in roles if role not in _role_registry]
        if unknown:
            msg = (
                f"unknown worker role(s): {sorted(unknown)}; "
                f"registered roles: {list(available_roles())}"
            )
            raise ValueError(msg)

        self.roles = list(roles)
        self._settings = settings or get_settings()
        self._database = database
        self._redis = redis
        # Only dependencies this runtime constructed may be closed by stop().
        # Disposing an injected Database or RedisClient pulls the handle out from
        # under whoever owns it — an embedding host, or a test fixture shared
        # with the assertions that follow. The API lifespan applies the same rule
        # to its injected container, and the two must not disagree.
        self._owns_database = database is None
        self._owns_redis = redis is None
        self._events = events or InProcessEventBus()
        self._metrics = metrics or Metrics()
        self._grace_seconds = shutdown_grace_seconds
        self._stop_event = asyncio.Event()
        self._host = socket.gethostname()
        self._pid = str(os.getpid())
        self._identity = f"{self._host}:{self._pid}"
        self._contexts: list[WorkerContext] = []
        self._tasks: list[asyncio.Task[Any]] = []
        self._exit_code = 0

    # --- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        """Construct shared dependencies that were not injected."""
        if self._database is None:
            self._database = Database.from_settings(self._settings)
        if self._redis is None:
            self._redis = RedisClient.from_settings(self._settings)

    async def run(self) -> int:
        """Run every role until shutdown. Returns a process exit code."""
        await self.start()
        self._install_signal_handlers()

        _logger.info(
            "worker runtime starting",
            extra={
                "roles": self.roles,
                "identity": self._identity,
                "environment": self._settings.environment.value,
            },
        )

        for role in self.roles:
            context = WorkerContext(
                role=role,
                settings=self._settings,
                database=self._database,
                redis=self._redis,
                events=self._events,
                metrics=self._metrics,
                stop_event=self._stop_event,
                identity=self._identity,
            )
            self._contexts.append(context)
            self._tasks.append(
                asyncio.create_task(self._run_role(role, context), name=f"role:{role}")
            )

        self._tasks.append(asyncio.create_task(self._heartbeat_loop(), name="heartbeat"))

        # Wait for the first task to finish; any exit is a shutdown trigger.
        done, _pending = await asyncio.wait(self._tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.cancelled():
                continue
            exception = task.exception()
            if exception is not None:
                self._exit_code = 1
                _logger.error(
                    "worker task failed; shutting down",
                    extra={"task": task.get_name(), "error_type": type(exception).__name__},
                    exc_info=exception,
                )

        await self.stop()
        return self._exit_code

    async def stop(self) -> None:
        """Request shutdown, wait for roles to unwind, then close dependencies."""
        if self._stop_event.is_set() and not self._tasks:
            return
        self._stop_event.set()
        _logger.info("worker runtime stopping", extra={"identity": self._identity})

        for context in self._contexts:
            with contextlib.suppress(Exception):
                await self._publish_shutdown_heartbeat(context)

        pending = [task for task in self._tasks if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending, timeout=self._grace_seconds)
            still_running = [task for task in pending if not task.done()]
            if still_running:
                _logger.error(
                    "worker tasks did not stop within the grace period",
                    extra={"tasks": [task.get_name() for task in still_running]},
                )
                self._exit_code = self._exit_code or 1
        self._tasks = []

        if self._redis is not None and self._owns_redis:
            with contextlib.suppress(Exception):
                await self._redis.aclose()
        if self._database is not None and self._owns_database:
            with contextlib.suppress(Exception):
                await self._database.dispose()
        _logger.info("worker runtime stopped", extra={"exit_code": self._exit_code})

    # --- internals -------------------------------------------------------
    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                # NotImplementedError on platforms without loop signal support.
                loop.add_signal_handler(sig, self._request_stop, sig)

    def _request_stop(self, sig: signal.Signals) -> None:
        _logger.info("shutdown signal received", extra={"signal": sig.name})
        self._stop_event.set()

    async def _run_role(self, role: str, context: WorkerContext) -> None:
        fn = _role_registry[role]
        try:
            await fn(context)
        except asyncio.CancelledError:
            raise
        except Exception:
            _logger.exception("worker role crashed", extra={"role": role})
            self._exit_code = 1
            raise
        else:
            # A role returning normally means the process has nothing left to
            # do. Exiting is correct; silently idling would hide a bug.
            _logger.info("worker role completed", extra={"role": role})
            self._stop_event.set()

    def _heartbeat_key(self, role: str) -> str:
        """Redis key for one *instance* of ``role``.

        The key includes host and pid, not just the role. A role-keyed record
        makes replicas of the same role overwrite one another, so a crashed
        replica stays invisible for as long as any sibling keeps writing — the
        fleet view reports healthy while capacity is silently gone. Per-instance
        keys are what ``WorkerHeartbeatRepository.latest_per_worker`` already
        assumes on the persistence side (it groups by ``role`` *and*
        ``identity``), and what a multi-replica Docker deployment (§124) needs.

        The reader, ``SystemService.workers``, scans ``worker:heartbeat:*`` and
        reads fields from the hash rather than parsing the key, so the extra
        segments cost nothing there.
        """
        return self._redis_key("worker", "heartbeat", role)

    def _alive_key(self, role: str) -> str:
        """Short-lived liveness marker for one instance of ``role``."""
        return self._redis_key("worker", "alive", role)

    def _redis_key(self, *parts: str) -> str:
        if self._redis is None:
            msg = "redis client is not configured"
            raise RuntimeError(msg)
        return self._redis.key(*parts, self._host, self._pid)

    async def _heartbeat_loop(self) -> None:
        interval = float(self._settings.worker_heartbeat_interval_seconds)
        while not self._stop_event.is_set():
            for context in self._contexts:
                await self._write_heartbeat(context)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)

    async def _write_heartbeat(self, context: WorkerContext) -> None:
        """Record liveness in Redis so stale workers are detectable (§55)."""
        if self._redis is None:
            return
        now = utc_now()
        # redis-py's `hset` mapping is invariant in its key type, so a plain
        # `dict[str, str]` is not assignable to it even though every value written
        # here really is a str. The alias documents that without losing the shape.
        payload: Mapping[Any, Any] = {
            "role": context.role,
            "identity": self._identity,
            "pid": str(os.getpid()),
            "host": socket.gethostname(),
            "environment": self._settings.environment.value,
            "version": self._settings.app_version,
            "status": "stopping" if self._stop_event.is_set() else "running",
            "started_at": isoformat(context.started_at),
            "last_heartbeat_at": isoformat(now),
            "jobs_processed": str(context.jobs_processed),
            "jobs_failed": str(context.jobs_failed),
        }
        key = self._heartbeat_key(context.role)
        alive_key = self._alive_key(context.role)
        ttl = self._settings.worker_stale_after_seconds
        try:
            pipeline = self._redis.raw.pipeline()
            pipeline.hset(key, mapping=payload)
            # The heartbeat record persists for inspection after shutdown; the
            # "alive" key expires, which is what makes staleness observable.
            pipeline.expire(key, ttl * 4)
            pipeline.set(alive_key, self._identity, ex=ttl)
            await pipeline.execute()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - heartbeat failure must not kill the worker
            _logger.warning(
                "failed to write worker heartbeat",
                extra={"role": context.role, "error_type": "RedisError"},
            )

        await context.events.publish(
            Event(
                event_type=EventType.WORKER_HEARTBEAT,
                source=f"worker:{context.role}",
                payload={
                    "role": context.role,
                    "identity": self._identity,
                    "jobs_processed": context.jobs_processed,
                    "jobs_failed": context.jobs_failed,
                },
            )
        )

    async def _publish_shutdown_heartbeat(self, context: WorkerContext) -> None:
        """Write a final heartbeat marked ``stopping`` (§55, §140)."""
        if self._redis is None:
            return
        key = self._heartbeat_key(context.role)
        with contextlib.suppress(Exception):
            await self._redis.raw.hset(key, mapping={"status": "stopped"})
            await self._redis.raw.delete(self._alive_key(context.role))


def run_cli(roles: Sequence[str] | None = None) -> int:
    """Synchronous entry point used by the ``arb-worker`` console script."""
    settings = get_settings()
    resolved = list(roles) if roles else settings.worker_role_list
    runtime = WorkerRuntime(resolved, settings=settings)
    return asyncio.run(runtime.run())
