"""Time handling (§75).

Rules enforced across the platform:

* Everything is stored and compared in **UTC**.
* Every ``datetime`` produced by this module is timezone-aware.
* Naive datetimes are rejected rather than silently assumed to be UTC — a
  silently-misinterpreted timestamp in a trading system produces silently-wrong
  P&L, which is worse than an exception.
* Conversion to a user's timezone happens only at presentation time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

__all__ = [
    "EPOCH",
    "assume_utc",
    "duration_ms",
    "ensure_aware",
    "from_millis",
    "is_stale",
    "isoformat",
    "parse_isoformat",
    "to_millis",
    "utc_now",
    "utc_now_ms",
]

EPOCH: Final[datetime] = datetime(1970, 1, 1, tzinfo=UTC)


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC ``datetime``."""
    return datetime.now(UTC)


def utc_now_ms() -> int:
    """Return the current time as milliseconds since the Unix epoch.

    Exchange feeds publish millisecond timestamps; keeping a single source for
    this avoids mixing second and millisecond precision (§79).
    """
    return to_millis(utc_now())


def to_millis(moment: datetime) -> int:
    """Convert an aware ``datetime`` to Unix epoch milliseconds."""
    aware = ensure_aware(moment)
    return int((aware - EPOCH).total_seconds() * 1000)


def from_millis(millis: int) -> datetime:
    """Convert Unix epoch milliseconds to an aware UTC ``datetime``."""
    return datetime.fromtimestamp(millis / 1000, tz=UTC)


def ensure_aware(moment: datetime) -> datetime:
    """Return ``moment`` unchanged if aware, otherwise raise.

    Naive timestamps are ambiguous and must never enter trading, P&L or audit
    code paths. Use :func:`assume_utc` when the source is *known* to be UTC but
    did not carry the tzinfo (for example some exchange REST payloads).
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        msg = (
            "naive datetime rejected: all timestamps must be timezone-aware UTC "
            "(§75). Use arb_core.clock.assume_utc() when the source is known to be UTC."
        )
        raise ValueError(msg)
    return moment.astimezone(UTC)


def assume_utc(moment: datetime) -> datetime:
    """Attach UTC to a naive ``datetime``; normalise an aware one to UTC."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def isoformat(moment: datetime) -> str:
    """Serialise as ISO-8601 with an explicit ``+00:00`` UTC offset."""
    return ensure_aware(moment).isoformat()


def parse_isoformat(value: str) -> datetime:
    """Parse an ISO-8601 string into an aware UTC ``datetime``.

    Accepts the trailing ``Z`` that exchanges and browsers commonly emit.
    """
    normalised = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = datetime.fromisoformat(normalised)
    return ensure_aware(parsed)


def duration_ms(start: datetime, end: datetime | None = None) -> int:
    """Elapsed milliseconds between two aware timestamps.

    ``end`` defaults to now, which is the common case for latency and data-age
    measurements (§79, §112).
    """
    finished = utc_now() if end is None else ensure_aware(end)
    return max(0, to_millis(finished) - to_millis(ensure_aware(start)))


def is_stale(moment: datetime, max_age_ms: int, *, now_ms: int | None = None) -> bool:
    """Return ``True`` when ``moment`` is older than ``max_age_ms``.

    This is the single authority for market-data freshness decisions (§79).
    Callers must not re-implement staleness checks inline, otherwise different
    parts of the system disagree about what "fresh" means.
    """
    if max_age_ms < 0:
        msg = "max_age_ms must be non-negative"
        raise ValueError(msg)
    reference = utc_now_ms() if now_ms is None else now_ms
    return (reference - to_millis(moment)) > max_age_ms
