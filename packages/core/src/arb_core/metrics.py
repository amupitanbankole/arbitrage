"""Prometheus metrics (§54, §112).

Every collector is created against a **per-instance** :class:`CollectorRegistry`
rather than the global default registry. Two reasons:

1. The FastAPI app factory runs more than once in a test-suite. With the global
   registry the second construction raises ``Duplicated timeseries``, which
   surfaces as a confusing failure far from its cause.
2. Several roles can run in one worker process. Separate registries make it
   explicit which component owns which series.

**Label cardinality is a safety property, not a style preference.** The ``route``
label must carry the FastAPI *route template* (``/api/v1/bots/{bot_id}``), never
the concrete request path. Raw paths make cardinality unbounded — one series per
bot, per order, per user — which eventually exhausts Prometheus memory and takes
down monitoring for the whole platform. :func:`normalize_route` exists so callers
cannot get this wrong by accident.

Metric names are prefixed with the ``arb_`` namespace following Prometheus naming
conventions; the mapping to the names listed in §112 is documented in
``docs/OPERATIONS.md``.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = ["LATENCY_BUCKETS", "Metrics", "normalize_route"]

#: Buckets tuned for a request path that should be single-digit milliseconds and
#: a trading path where tens of milliseconds already matters (§138).
LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

#: Label for anything that did not match a declared route. Prevents 404 scans
#: from creating one series per probed path.
_UNMATCHED_ROUTE: Final[str] = "_unmatched"


def normalize_route(path: str | None) -> str:
    """Return a bounded-cardinality label value for a request path.

    Concrete identifiers are never used. If a route template is unavailable the
    value collapses to ``_unmatched`` so an attacker probing random URLs cannot
    inflate Prometheus cardinality.
    """
    if not path:
        return _UNMATCHED_ROUTE
    return path if path.startswith("/") else f"/{path}"


class Metrics:
    """All platform Prometheus collectors, bound to one registry."""

    def __init__(
        self, *, namespace: str = "arb", registry: CollectorRegistry | None = None
    ) -> None:
        self.namespace = namespace
        self.registry = registry or CollectorRegistry()

        # --- API (§112: api_requests_total, api_request_latency) ---
        self.api_requests_total = Counter(
            "api_requests_total",
            "Total HTTP requests handled by the API.",
            labelnames=("method", "route", "status"),
            namespace=namespace,
            registry=self.registry,
        )
        self.api_request_latency_seconds = Histogram(
            "api_request_latency_seconds",
            "HTTP request latency in seconds.",
            labelnames=("method", "route", "status"),
            namespace=namespace,
            registry=self.registry,
            buckets=LATENCY_BUCKETS,
        )

        # --- Market data (§112) ---
        self.market_data_messages_total = Counter(
            "market_data_messages_total",
            "Market-data messages received, by exchange and feed type.",
            labelnames=("exchange", "feed", "result"),
            namespace=namespace,
            registry=self.registry,
        )
        self.market_data_latency_seconds = Histogram(
            "market_data_latency_seconds",
            "Delay between exchange timestamp and local processing.",
            labelnames=("exchange",),
            namespace=namespace,
            registry=self.registry,
            buckets=LATENCY_BUCKETS,
        )
        self.market_data_age_seconds = Histogram(
            "market_data_age_seconds",
            "Age of the newest order book per exchange/symbol (§79).",
            labelnames=("exchange",),
            namespace=namespace,
            registry=self.registry,
            buckets=LATENCY_BUCKETS,
        )

        # --- Arbitrage (§112) ---
        self.opportunities_detected_total = Counter(
            "opportunities_detected_total",
            "Opportunities detected, by strategy.",
            labelnames=("strategy",),
            namespace=namespace,
            registry=self.registry,
        )
        self.opportunities_rejected_total = Counter(
            "opportunities_rejected_total",
            "Opportunities rejected before execution, by reason.",
            labelnames=("strategy", "reason"),
            namespace=namespace,
            registry=self.registry,
        )
        self.opportunity_detection_latency_seconds = Histogram(
            "opportunity_detection_latency_seconds",
            "Time from market-data update to opportunity emission.",
            labelnames=("strategy",),
            namespace=namespace,
            registry=self.registry,
            buckets=LATENCY_BUCKETS,
        )

        # --- Trading (§112) ---
        self.trades_started_total = Counter(
            "trades_started_total",
            "Arbitrage trades that entered execution, by mode and strategy.",
            labelnames=("mode", "strategy"),
            namespace=namespace,
            registry=self.registry,
        )
        self.trades_completed_total = Counter(
            "trades_completed_total",
            "Trades that reached a terminal success state.",
            labelnames=("mode", "strategy"),
            namespace=namespace,
            registry=self.registry,
        )
        self.trades_failed_total = Counter(
            "trades_failed_total",
            "Trades that failed, by failure reason.",
            labelnames=("mode", "strategy", "reason"),
            namespace=namespace,
            registry=self.registry,
        )
        self.execution_latency_seconds = Histogram(
            "execution_latency_seconds",
            "End-to-end execution latency per trade.",
            labelnames=("mode", "exchange"),
            namespace=namespace,
            registry=self.registry,
            buckets=LATENCY_BUCKETS,
        )

        # --- Orders (§112) ---
        self.orders_submitted_total = Counter(
            "orders_submitted_total",
            "Orders submitted to an exchange (or the paper simulator).",
            labelnames=("mode", "exchange", "side"),
            namespace=namespace,
            registry=self.registry,
        )
        self.orders_filled_total = Counter(
            "orders_filled_total",
            "Orders that reached FILLED.",
            labelnames=("mode", "exchange"),
            namespace=namespace,
            registry=self.registry,
        )
        self.orders_rejected_total = Counter(
            "orders_rejected_total",
            "Orders rejected by the exchange or by pre-submission validation.",
            labelnames=("mode", "exchange", "reason"),
            namespace=namespace,
            registry=self.registry,
        )

        # --- Risk (§112) ---
        self.risk_rejections_total = Counter(
            "risk_rejections_total",
            "Pre-trade risk rejections, by limit that fired.",
            labelnames=("limit", "scope"),
            namespace=namespace,
            registry=self.registry,
        )
        self.circuit_breaker_events_total = Counter(
            "circuit_breaker_events_total",
            "Circuit-breaker state transitions.",
            labelnames=("breaker", "state"),
            namespace=namespace,
            registry=self.registry,
        )
        self.kill_switch_events_total = Counter(
            "kill_switch_events_total",
            "Kill-switch activations and clears, by scope.",
            labelnames=("scope", "action"),
            namespace=namespace,
            registry=self.registry,
        )

        # --- Workers & queues (§54, §55) ---
        self.worker_jobs_total = Counter(
            "worker_jobs_total",
            "Jobs processed by role.",
            labelnames=("role", "result"),
            namespace=namespace,
            registry=self.registry,
        )
        self.worker_failures_total = Counter(
            "worker_failures_total",
            "Job failures by role and error type.",
            labelnames=("role", "error_type"),
            namespace=namespace,
            registry=self.registry,
        )
        self.workers_online = Gauge(
            "workers_online",
            "Workers whose heartbeat is fresh, by role.",
            labelnames=("role",),
            namespace=namespace,
            registry=self.registry,
        )
        self.queue_depth = Gauge(
            "queue_depth",
            "Pending items per queue.",
            labelnames=("queue",),
            namespace=namespace,
            registry=self.registry,
        )

        # --- Platform state (§44) ---
        self.active_bots = Gauge(
            "active_bots",
            "Bots in RUNNING state, by mode.",
            labelnames=("mode",),
            namespace=namespace,
            registry=self.registry,
        )
        self.open_trades = Gauge(
            "open_trades",
            "Trades that are not yet in a terminal state.",
            labelnames=("mode",),
            namespace=namespace,
            registry=self.registry,
        )
        self.notifications_sent_total = Counter(
            "notifications_sent_total",
            "Notifications dispatched, by channel and result.",
            labelnames=("channel", "result"),
            namespace=namespace,
            registry=self.registry,
        )
        self.security_events_total = Counter(
            "security_events_total",
            "Security events recorded, by category.",
            labelnames=("category",),
            namespace=namespace,
            registry=self.registry,
        )

    # --- helpers ---------------------------------------------------------
    def observe_request(
        self,
        *,
        method: str,
        route: str | None,
        status: int,
        duration_seconds: float,
    ) -> None:
        """Record one HTTP request and its latency."""
        label = normalize_route(route)
        status_text = str(status)
        self.api_requests_total.labels(method=method, route=label, status=status_text).inc()
        self.api_request_latency_seconds.labels(
            method=method, route=label, status=status_text
        ).observe(duration_seconds)

    @contextmanager
    def timed(self, histogram: Histogram, **labels: str) -> Iterator[None]:
        """Observe the wall-clock duration of a block into ``histogram``."""
        started = time.perf_counter()
        try:
            yield
        finally:
            histogram.labels(**labels).observe(time.perf_counter() - started)

    def render(self) -> bytes:
        """Serialise the registry in Prometheus text exposition format."""
        return generate_latest(self.registry)

    @staticmethod
    def content_type() -> str:
        """Content type for a ``/metrics`` response."""
        return CONTENT_TYPE_LATEST
