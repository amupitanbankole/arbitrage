"""System status and worker fleet reporting (§44, §48, §55).

The trading-mode label is computed **server-side** and returned verbatim. A
client that derived "is live trading on?" from several booleans could get it
wrong, and the difference between a wrong ``PAPER TRADING`` banner and a wrong
``LIVE TRADING ACTIVE`` banner is real money (§31).

Live trading requires *both* gates to be open: the ``LIVE_TRADING_ENABLED``
environment master switch and the ``live_trading`` database feature flag. Either
one alone is insufficient. Two independent gates means a mistaken flag change
cannot enable live order submission on a deployment that was configured off, and
a redeploy cannot re-enable something an administrator turned off (§48, §58).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from arb_api.schemas.system import SystemInfo, WorkersResponse, WorkerSummary
from arb_core.clock import duration_ms, parse_isoformat, utc_now
from arb_core.errors import DependencyUnavailableError, ErrorCode
from arb_core.log import get_logger
from arb_persistence.models.enums import WorkerStatus

if TYPE_CHECKING:
    from arb_api.services.feature_flag_service import FeatureFlagService
    from arb_api.state import AppState

__all__ = ["SystemService", "trading_mode_label"]

_logger = get_logger(__name__)

#: Cap on how many worker records one status call will read. A runaway fleet
#: must not be able to turn the status endpoint into an unbounded scan.
_MAX_WORKER_RECORDS: Final[int] = 200
_SCAN_BATCH: Final[int] = 100

#: Heartbeats in these states are reported stale regardless of their age.
_TERMINAL_STATES: Final[frozenset[WorkerStatus]] = frozenset(
    {WorkerStatus.STOPPED, WorkerStatus.FAILED}
)


def trading_mode_label(
    *,
    live_trading: bool,
    kill_switch: bool,
    paper_trading: bool,
) -> str:
    """Return the banner text the UI renders verbatim (§31, §48)."""
    if kill_switch:
        return "GLOBAL KILL SWITCH ACTIVE"
    if live_trading:
        return "LIVE TRADING ACTIVE"
    if paper_trading:
        return "PAPER TRADING"
    return "TRADING DISABLED"


class SystemService:
    """Reads platform status from configuration, flags and Redis."""

    def __init__(self, state: AppState, flags: FeatureFlagService) -> None:
        self._state = state
        self._flags = flags

    async def info(self) -> SystemInfo:
        """Public platform status, including the trading safety gates."""
        settings = self._state.settings

        kill_switch = settings.global_kill_switch_enabled
        # Both gates must be open for live trading (§31, §48).
        live_trading = settings.live_trading_enabled and await self._flags.is_enabled(
            "live_trading"
        )
        paper_trading = await self._flags.is_enabled("paper_trading")

        return SystemInfo(
            service=settings.service_name,
            version=settings.app_version,
            environment=settings.environment.value,
            server_time=utc_now().isoformat(),
            uptime_seconds=self._state.uptime_seconds,
            live_trading_enabled=live_trading,
            global_kill_switch_enabled=kill_switch,
            paper_trading_enabled=paper_trading,
            demo_mode=settings.next_public_demo_mode,
            trading_mode_label=trading_mode_label(
                live_trading=live_trading,
                kill_switch=kill_switch,
                paper_trading=paper_trading,
            ),
        )

    async def workers(self) -> WorkersResponse:
        """Summarise the worker fleet from live Redis heartbeats (§55).

        Raises :class:`DependencyUnavailableError` when Redis cannot be read.
        Returning an empty list instead would be indistinguishable from "no
        workers are running", which is exactly the ambiguity an operator must
        not face during an incident (§128).
        """
        redis = self._state.redis
        settings = self._state.settings
        stale_after = settings.worker_stale_after_seconds
        pattern = redis.key("worker", "heartbeat", "*")

        summaries: list[WorkerSummary] = []
        try:
            seen = 0
            async for raw_key in redis.raw.scan_iter(match=pattern, count=_SCAN_BATCH):
                seen += 1
                if seen > _MAX_WORKER_RECORDS:
                    _logger.warning(
                        "worker heartbeat scan truncated",
                        extra={"limit": _MAX_WORKER_RECORDS},
                    )
                    break
                key = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
                payload = await redis.raw.hgetall(key)
                summary = self._to_summary(payload, stale_after_seconds=stale_after)
                if summary is not None:
                    summaries.append(summary)
        except Exception as exc:  # re-raised below as a safe API error
            _logger.warning(
                "failed to read worker heartbeats", extra={"error_type": type(exc).__name__}
            )
            msg = "Worker status is temporarily unavailable."
            raise DependencyUnavailableError(msg, code=ErrorCode.REDIS_UNAVAILABLE) from exc

        summaries.sort(key=lambda item: (item.role, item.age_seconds or 0))
        return WorkersResponse(
            items=summaries, total=len(summaries), stale_after_seconds=stale_after
        )

    def _to_summary(
        self, payload: dict[bytes | str, bytes | str], *, stale_after_seconds: int
    ) -> WorkerSummary | None:
        """Convert one Redis heartbeat hash into a public summary.

        ``host``, ``pid`` and ``identity`` are present in the payload but are
        deliberately not exposed: they map the internal network and process
        topology (§124). The permission-gated admin API returns them to
        authorized operators in Phase 9.
        """
        fields = {
            (key.decode() if isinstance(key, bytes) else str(key)): (
                value.decode() if isinstance(value, bytes) else str(value)
            )
            for key, value in payload.items()
        }
        role = fields.get("role")
        if not role:
            return None

        status = _parse_status(fields.get("status"))
        last_heartbeat = fields.get("last_heartbeat_at")
        age_seconds: int | None = None
        if last_heartbeat:
            try:
                age_seconds = duration_ms(parse_isoformat(last_heartbeat)) // 1000
            except ValueError:
                _logger.warning(
                    "worker heartbeat has an unparseable timestamp", extra={"role": role}
                )

        stale = status in _TERMINAL_STATES or (
            age_seconds is not None and age_seconds > stale_after_seconds
        )

        return WorkerSummary(
            role=role,
            status=status,
            last_heartbeat_at=last_heartbeat,
            age_seconds=age_seconds,
            jobs_processed=_parse_int(fields.get("jobs_processed")),
            jobs_failed=_parse_int(fields.get("jobs_failed")),
            stale=stale,
        )


def _parse_status(value: str | None) -> WorkerStatus:
    """Map a stored status string, defaulting to a non-alarming unknown state."""
    if not value:
        return WorkerStatus.STARTING
    try:
        return WorkerStatus(value.upper())
    except ValueError:
        # An unrecognised value means a newer worker wrote a state this API
        # version does not know. DEGRADED is honest; guessing RUNNING is not.
        return WorkerStatus.DEGRADED


def _parse_int(value: str | None) -> int:
    if not value:
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0
