"""Time handling (§75, §79).

A naive datetime that is silently assumed to be local time produces silently
wrong data-age calculations, which in turn means executing on stale order books.
These tests pin the behaviour that prevents it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from arb_core.clock import (
    EPOCH,
    assume_utc,
    duration_ms,
    ensure_aware,
    from_millis,
    is_stale,
    isoformat,
    parse_isoformat,
    to_millis,
    utc_now,
    utc_now_ms,
)


class TestAwareness:
    def test_utc_now_is_aware(self) -> None:
        now = utc_now()
        assert now.tzinfo is not None
        assert now.utcoffset() == timedelta(0)

    def test_ensure_aware_rejects_naive(self) -> None:
        """Ambiguous timestamps must fail loudly, not be guessed at."""
        with pytest.raises(ValueError, match="naive datetime rejected"):
            # Naive on purpose: rejecting ambiguity is the behaviour under test.
            ensure_aware(datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001

    def test_ensure_aware_normalises_an_offset(self) -> None:
        lagos = timezone(timedelta(hours=1))
        moment = datetime(2026, 1, 1, 13, 0, 0, tzinfo=lagos)
        assert ensure_aware(moment) == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    def test_assume_utc_attaches_utc_to_naive(self) -> None:
        naive = datetime(2026, 1, 1, 12, 0, 0)  # noqa: DTZ001 - the input is the point
        assumed = assume_utc(naive)
        assert assumed.tzinfo == UTC
        assert assumed.hour == 12


class TestMilliseconds:
    def test_epoch_is_zero(self) -> None:
        assert to_millis(EPOCH) == 0

    def test_round_trip_at_millisecond_precision(self) -> None:
        moment = from_millis(1_750_000_000_123)
        assert to_millis(moment) == 1_750_000_000_123

    def test_sub_millisecond_precision_is_truncated(self) -> None:
        """Documented behaviour: millisecond resolution, matching exchange feeds."""
        moment = datetime(2026, 1, 1, 0, 0, 0, 123_999, tzinfo=UTC)
        assert to_millis(moment) == to_millis(datetime(2026, 1, 1, 0, 0, 0, 123_000, tzinfo=UTC))

    def test_utc_now_ms_matches_utc_now(self) -> None:
        before = to_millis(utc_now())
        value = utc_now_ms()
        after = to_millis(utc_now())
        assert before <= value <= after


class TestIsoFormat:
    def test_includes_an_explicit_offset(self) -> None:
        assert isoformat(datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)).endswith("+00:00")

    @pytest.mark.parametrize(
        "value",
        ["2026-09-05T12:00:00Z", "2026-09-05T12:00:00z", "2026-09-05T12:00:00+00:00"],
    )
    def test_parses_zulu_and_offset_forms(self, value: str) -> None:
        parsed = parse_isoformat(value)
        assert parsed == datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
        assert parsed.tzinfo is not None

    def test_rejects_naive_iso_string(self) -> None:
        with pytest.raises(ValueError, match="naive datetime rejected"):
            parse_isoformat("2026-09-05T12:00:00")

    def test_round_trip(self) -> None:
        moment = utc_now()
        assert parse_isoformat(isoformat(moment)) == moment


class TestDuration:
    def test_measures_elapsed_time(self) -> None:
        start = utc_now() - timedelta(milliseconds=250)
        assert 240 <= duration_ms(start) <= 400

    def test_defaults_to_now(self) -> None:
        assert duration_ms(utc_now()) <= 50

    def test_never_negative(self) -> None:
        """A future timestamp yields 0, not a negative latency."""
        assert duration_ms(utc_now() + timedelta(seconds=60)) == 0


class TestStaleness:
    """Market-data freshness is the gate that prevents trading on stale books (§79)."""

    def test_fresh_data_is_not_stale(self) -> None:
        assert is_stale(utc_now(), max_age_ms=2000) is False

    def test_old_data_is_stale(self) -> None:
        old = utc_now() - timedelta(seconds=5)
        assert is_stale(old, max_age_ms=2000) is True

    def test_boundary_is_inclusive(self) -> None:
        """Exactly at the limit is still fresh; one millisecond beyond is not."""
        reference = 1_750_000_000_000
        moment = from_millis(reference - 2000)
        assert is_stale(moment, max_age_ms=2000, now_ms=reference) is False
        assert is_stale(from_millis(reference - 2001), max_age_ms=2000, now_ms=reference) is True

    def test_future_timestamp_is_not_stale(self) -> None:
        future = utc_now() + timedelta(seconds=30)
        assert is_stale(future, max_age_ms=2000) is False

    def test_negative_max_age_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            is_stale(utc_now(), max_age_ms=-1)
