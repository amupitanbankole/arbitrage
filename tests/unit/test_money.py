"""Financial precision (§74).

These tests exist because a float rounding error in a profitability calculation
is not a cosmetic bug: it turns a losing trade into an apparently profitable
one. The suite asserts the exact behaviours that prevent it.
"""

from __future__ import annotations

from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal

import pytest

from arb_core.money import (
    AMOUNT_PLACES,
    MONEY_PLACES,
    PERCENT_PLACES,
    PRICE_PLACES,
    ZERO,
    amount_to_decimal,
    is_positive,
    quantize,
    quantize_amount,
    quantize_money,
    quantize_percent,
    quantize_price,
    serialize_decimal,
    to_decimal,
    truncate_amount,
)


class TestToDecimal:
    def test_adding_tenths_is_exact(self) -> None:
        """The canonical binary-float failure must not occur."""
        assert to_decimal("0.1") + to_decimal("0.2") == Decimal("0.3")
        # Contrast with the float behaviour this module exists to prevent.
        assert 0.1 + 0.2 != 0.3

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("1.5", Decimal("1.5")),
            ("105000", Decimal("105000")),
            ("-0.00000001", Decimal("-0.00000001")),
            (7, Decimal(7)),
            (Decimal("2.25"), Decimal("2.25")),
            ("  3.5  ", Decimal("3.5")),
        ],
    )
    def test_accepts_exact_inputs(self, value: object, expected: Decimal) -> None:
        assert to_decimal(value) == expected  # type: ignore[arg-type]

    def test_float_is_rejected_by_default(self) -> None:
        with pytest.raises(TypeError, match="float is not accepted"):
            to_decimal(0.1)

    def test_float_allowed_at_trust_boundary(self) -> None:
        assert to_decimal(0.1, strict=False) == Decimal("0.1")

    def test_bool_is_rejected(self) -> None:
        """``True`` is an ``int`` subclass; treating it as 1 would be a silent bug."""
        with pytest.raises(TypeError, match="bool is not a valid monetary value"):
            to_decimal(True)

    def test_empty_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty string"):
            to_decimal("   ")

    def test_garbage_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid decimal literal"):
            to_decimal("12.3.4")


class TestAmountToDecimal:
    def test_float_payload_from_exchange(self) -> None:
        assert amount_to_decimal(105000.25) == Decimal("105000.25")

    def test_string_payload_from_exchange(self) -> None:
        assert amount_to_decimal("0.00000001") == Decimal("0.00000001")

    def test_unconvertible_payload_raises(self) -> None:
        """A silently-zero balance is a trading-safety hazard (§33)."""
        with pytest.raises(TypeError, match="cannot interpret"):
            amount_to_decimal(None)
        with pytest.raises(TypeError, match="cannot interpret"):
            amount_to_decimal({"price": 1})


class TestQuantization:
    def test_money_rounds_half_up(self) -> None:
        """Accounting convention: 1.005 -> 1.01, not banker's rounding."""
        assert quantize_money(Decimal("1.005")) == Decimal("1.01")
        assert quantize_money(Decimal("1.004")) == Decimal("1.00")

    def test_price_keeps_eight_places(self) -> None:
        assert quantize_price(Decimal("105000.123456789")) == Decimal("105000.12345679")

    def test_amount_keeps_eight_places(self) -> None:
        assert quantize_amount(Decimal("0.123456789")) == Decimal("0.12345679")

    def test_percent_keeps_four_places(self) -> None:
        assert quantize_percent(Decimal("0.123456")) == Decimal("0.1235")

    def test_truncation_never_rounds_a_size_up(self) -> None:
        """Rounding a tradable size up would exceed the available balance."""
        assert truncate_amount(Decimal("0.123456789")) == Decimal("0.12345678")
        assert truncate_amount(Decimal("0.999999999")) == Decimal("0.99999999")

    def test_explicit_rounding_mode(self) -> None:
        assert quantize(Decimal("1.005"), MONEY_PLACES, rounding=ROUND_DOWN) == Decimal("1.00")
        assert quantize(Decimal("1.005"), MONEY_PLACES, rounding=ROUND_HALF_UP) == Decimal("1.01")

    def test_non_finite_values_are_rejected(self) -> None:
        for value in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
            with pytest.raises(ValueError, match="non-finite"):
                quantize(value, MONEY_PLACES)

    def test_requires_a_decimal(self) -> None:
        with pytest.raises(TypeError, match="requires a Decimal"):
            quantize(1.5, MONEY_PLACES)  # type: ignore[arg-type]


class TestSerialization:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (Decimal("1E+2"), "100"),
            (Decimal("1.50"), "1.50"),
            (Decimal("0.00000001"), "0.00000001"),
            (Decimal("-25.10"), "-25.10"),
        ],
    )
    def test_never_emits_scientific_notation(self, value: Decimal, expected: str) -> None:
        """Clients parse money as a string; ``1E+2`` would break them (§74)."""
        assert serialize_decimal(value) == expected

    def test_non_finite_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            serialize_decimal(Decimal("NaN"))

    def test_precision_survives_a_round_trip(self) -> None:
        original = Decimal("0.30000000000000004")
        assert to_decimal(serialize_decimal(original)) == original


class TestHelpers:
    def test_is_positive(self) -> None:
        assert is_positive(Decimal("0.00000001")) is True
        assert is_positive(ZERO) is False
        assert is_positive(Decimal("-1")) is False
        assert is_positive(Decimal("NaN")) is False

    def test_place_constants_are_ordered(self) -> None:
        """Sanity: money is coarser than price, which is coarser than nothing."""
        assert MONEY_PLACES > PERCENT_PLACES > PRICE_PLACES == AMOUNT_PLACES

    def test_division_by_zero_raises_instead_of_yielding_infinity(self) -> None:
        """A divide-by-zero in a profitability calc must not become ``Infinity``.

        ``quantize`` rejects non-finite values, so an uncaught Infinity would
        surface as a clear error rather than an absurd order size.
        """
        with pytest.raises(ZeroDivisionError):
            Decimal("1") / Decimal("0")
