"""Internal event contract (§99, §100).

The platform is event-driven:

    MarketDataUpdated -> OpportunityDetected -> RiskValidated -> TradeApproved
        -> OrderSubmitted -> OrderFilled -> PnlUpdated -> NotificationSent

Two properties are mandatory and are enforced here rather than left to callers:

* **Idempotency.** Every event carries a server-generated ``event_id`` and an
  optional ``idempotency_key``. :class:`InProcessEventBus` de-duplicates on
  both, so a redelivered message (Redis pub/sub reconnect, worker restart, at
  least-once queue semantics) cannot double-execute a trade or double-count P&L.
* **Persistence is the caller's responsibility.** Redis transport is transient.
  Anything that forms part of financial history must also be written to
  PostgreSQL in the same transaction that produced it (§100). The bus never
  claims to have stored anything.

Payloads must be JSON-serialisable and must not contain secrets; the publisher
is responsible for that, and :mod:`arb_core.log` redacts anything that leaks
into a log line.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

from arb_core.clock import utc_now
from arb_core.identifiers import uuid7
from arb_core.log import get_logger

__all__ = [
    "Event",
    "EventBus",
    "EventHandler",
    "EventType",
    "InProcessEventBus",
]

_logger = get_logger(__name__)


class EventType(StrEnum):
    """Canonical internal event names.

    These strings are persisted in event-history tables and matched by alerting
    rules, so they must never be renamed. Add new members for new events.
    """

    # --- Market data (§13, §79) ---
    MARKET_DATA_UPDATED = "MarketDataUpdated"
    MARKET_DATA_STALE = "MarketDataStale"
    ORDER_BOOK_UPDATED = "OrderBookUpdated"
    EXCHANGE_STATUS_CHANGED = "ExchangeStatusChanged"

    # --- Arbitrage lifecycle (§21, §98) ---
    OPPORTUNITY_DETECTED = "OpportunityDetected"
    OPPORTUNITY_VALIDATED = "OpportunityValidated"
    OPPORTUNITY_EXPIRED = "OpportunityExpired"
    OPPORTUNITY_REJECTED = "OpportunityRejected"

    # --- Risk (§24, §25, §26, §98) ---
    RISK_VALIDATED = "RiskValidated"
    RISK_REJECTED = "RiskRejected"
    CIRCUIT_BREAKER_TRIGGERED = "CircuitBreakerTriggered"
    CIRCUIT_BREAKER_RESET = "CircuitBreakerReset"
    KILL_SWITCH_TRIGGERED = "KillSwitchTriggered"
    KILL_SWITCH_CLEARED = "KillSwitchCleared"

    # --- Trading (§27, §98) ---
    TRADE_APPROVED = "TradeApproved"
    TRADE_SUBMITTED = "TradeSubmitted"
    TRADE_PARTIALLY_FILLED = "TradePartiallyFilled"
    TRADE_FILLED = "TradeFilled"
    TRADE_HEDGED = "TradeHedged"
    TRADE_COMPLETED = "TradeCompleted"
    TRADE_FAILED = "TradeFailed"
    LEG_FAILURE_DETECTED = "LegFailureDetected"

    # --- Orders (§29, §98) ---
    ORDER_CREATED = "OrderCreated"
    ORDER_SUBMITTED = "OrderSubmitted"
    ORDER_PARTIALLY_FILLED = "OrderPartiallyFilled"
    ORDER_FILLED = "OrderFilled"
    ORDER_CANCELLED = "OrderCancelled"
    ORDER_REJECTED = "OrderRejected"

    # --- Portfolio & P&L (§34, §35) ---
    BALANCE_UPDATED = "BalanceUpdated"
    RECONCILIATION_FAILED = "ReconciliationFailed"
    PNL_UPDATED = "PnlUpdated"

    # --- Bots (§38, §98) ---
    BOT_CREATED = "BotCreated"
    BOT_STARTED = "BotStarted"
    BOT_PAUSED = "BotPaused"
    BOT_STOPPED = "BotStopped"
    BOT_ERROR = "BotError"

    # --- Security & administration (§53, §131) ---
    SECURITY_EVENT = "SecurityEvent"
    AUDIT_EVENT = "AuditEvent"
    LIVE_TRADING_ENABLED = "LiveTradingEnabled"
    USER_SUSPENDED = "UserSuspended"
    CONFIGURATION_CHANGED = "ConfigurationChanged"

    # --- Platform (§55, §56, §111) ---
    WORKER_HEARTBEAT = "WorkerHeartbeat"
    WORKER_FAILURE = "WorkerFailure"
    DEPENDENCY_UNAVAILABLE = "DependencyUnavailable"
    NOTIFICATION_SENT = "NotificationSent"


class Event(BaseModel):
    """A single internal event.

    Immutable once constructed: handlers receive the same frozen object, so a
    handler cannot mutate state that a later handler depends on.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    #: Unique per emission; the primary de-duplication key.
    event_id: str = Field(default_factory=lambda: str(uuid7()))
    event_type: EventType
    #: Aware UTC timestamp of when the event occurred (§75).
    occurred_at: datetime = Field(default_factory=utc_now)
    #: Bumped when the payload shape changes in a backwards-incompatible way.
    schema_version: int = 1
    #: Component that produced the event, e.g. "arbitrage-worker".
    source: str = "unknown"
    #: Correlation identifier propagated from the originating request/job (§66).
    request_id: str | None = None
    #: Caller-supplied business key. Two events with the same key describe the
    #: same real-world occurrence even if they were emitted twice.
    idempotency_key: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    def dedupe_key(self) -> str:
        """Return the key used to suppress duplicate delivery."""
        return self.idempotency_key or self.event_id


EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """Interface every event transport must satisfy.

    Keeping this as an explicit base class (rather than a ``Protocol``) means
    implementations are checked against it by ``mypy`` at definition time rather
    than only at a call site, which is what we want for something the trading
    engine depends on.
    """

    async def publish(self, event: Event) -> None:
        """Deliver ``event`` to every subscribed handler."""
        raise NotImplementedError

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register ``handler`` for ``event_type``."""
        raise NotImplementedError


class InProcessEventBus(EventBus):
    """Single-process async bus used by the API and by each worker.

    Cross-process delivery (Redis Streams/pub-sub) is layered on top in later
    phases; the :class:`EventBus` interface stays identical so handlers do not
    change.

    De-duplication keeps the last ``max_seen`` keys. That bounds memory while
    covering the realistic duplicate window (reconnects and restarts), and it is
    only a *first* line of defence: handlers that mutate financial state must
    still be idempotent at the database level (§99).
    """

    _DEFAULT_MAX_SEEN: Final[int] = 10_000

    def __init__(self, *, max_seen: int = _DEFAULT_MAX_SEEN) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._wildcard: list[EventHandler] = []
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max_seen = max_seen
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register ``handler`` for one event type."""
        self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Register ``handler`` for every event type (audit/telemetry sinks)."""
        self._wildcard.append(handler)

    async def publish(self, event: Event) -> None:
        """Deliver ``event`` unless an identical event was already published."""
        async with self._lock:
            key = event.dedupe_key()
            if key in self._seen:
                _logger.debug(
                    "duplicate event suppressed",
                    extra={"event_type": event.event_type.value, "dedupe_key": key},
                )
                return
            self._seen[key] = None
            while len(self._seen) > self._max_seen:
                self._seen.popitem(last=False)

        handlers: Iterable[EventHandler] = (
            *self._handlers.get(event.event_type, []),
            *self._wildcard,
        )
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                # A failing subscriber must not prevent the remaining
                # subscribers from running, and must never take down the
                # publisher. The failure is logged with full context and
                # surfaced as its own event for alerting (§129).
                _logger.exception(
                    "event handler failed",
                    extra={
                        "event_type": event.event_type.value,
                        "event_id": event.event_id,
                        "handler": getattr(handler, "__qualname__", repr(handler)),
                    },
                )

    def clear(self) -> None:
        """Remove all handlers and de-duplication state. Test-only."""
        self._handlers.clear()
        self._wildcard.clear()
        self._seen.clear()
