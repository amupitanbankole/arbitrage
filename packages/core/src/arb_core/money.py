"""Financial arithmetic (§74).

**Binary floating point is forbidden for any money-adjacent value.** ``0.1 + 0.2
!= 0.3`` in IEEE-754, and in a system that computes net arbitrage profit as
``gross - fees - slippage`` a single float rounding error can turn a losing
trade into an apparently profitable one.

Every price, quantity, fee, balance and P&L figure in this platform is a
:class:`decimal.Decimal`. This module is the only place that decides:

* how external input is converted into ``Decimal`` (and what is rejected),
* how many decimal places each quantity carries,
* which rounding mode is applied,
* how values are serialised for JSON without losing precision.

Rounding mode is ``ROUND_HALF_UP`` for money because that is what exchange
settlement statements and accounting systems expect; ``ROUND_DOWN`` (truncation)
is used for *quantities* you are allowed to trade, because rounding a size up
would produce an order larger than the available balance.
"""

from __future__ import annotations

from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Final

__all__ = [
    "AMOUNT_PLACES",
    "MONEY_PLACES",
    "PERCENT_PLACES",
    "PRICE_PLACES",
    "RATE_PLACES",
    "ZERO",
    "amount_to_decimal",
    "is_positive",
    "quantize",
    "quantize_amount",
    "quantize_money",
    "quantize_percent",
    "quantize_price",
    "serialize_decimal",
    "to_decimal",
    "truncate_amount",
]

ZERO: Final[Decimal] = Decimal(0)

# Precision profiles. Crypto venues use widely differing tick/step sizes; these
# are the *internal accounting* precisions, and are always narrowed further by
# the exchange-specific rules attached to each market (§74).
PRICE_PLACES: Final[Decimal] = Decimal("0.00000001")  # 8 dp — BTC-scale prices
AMOUNT_PLACES: Final[Decimal] = Decimal("0.00000001")  # 8 dp — base-asset sizes
MONEY_PLACES: Final[Decimal] = Decimal("0.01")  # 2 dp — quote/fiat accounting
RATE_PLACES: Final[Decimal] = Decimal("0.000001")  # 6 dp — fee rates
PERCENT_PLACES: Final[Decimal] = Decimal("0.0001")  # 4 dp — ROI / spread %


def to_decimal(value: Decimal | str | float, *, strict: bool = True) -> Decimal:
    """Convert ``value`` to ``Decimal``.

    ``float`` input is **rejected by default**. A float that has already been
    through binary arithmetic has lost information that cannot be recovered, so
    accepting it silently would defeat the purpose of using ``Decimal``. Pass
    ``strict=False`` only at a trust boundary where the producer genuinely sent
    a JSON number (for example a third-party exchange payload), in which case
    the float is routed through ``repr`` to preserve the shortest exact decimal
    representation rather than the full binary expansion.
    """
    if isinstance(value, Decimal):
        return value
    # bool must be tested before int: bool is a subclass of int, and treating
    # True as Decimal(1) is never what a caller means in financial code.
    if isinstance(value, bool):
        msg = "bool is not a valid monetary value"
        raise TypeError(msg)
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            msg = "cannot convert an empty string to Decimal"
            raise ValueError(msg)
        try:
            return Decimal(text)
        except InvalidOperation as exc:
            msg = f"invalid decimal literal: {value!r}"
            raise ValueError(msg) from exc

    # Remaining accepted type: float.
    if strict:
        msg = (
            "float is not accepted for financial values (§74); pass a str or "
            "Decimal, or call to_decimal(..., strict=False) at a trusted boundary"
        )
        raise TypeError(msg)
    return Decimal(repr(value))


def amount_to_decimal(value: object) -> Decimal:
    """Best-effort conversion at an external trust boundary.

    Used for exchange payloads where a JSON number may legitimately arrive as a
    float. Anything unconvertible raises rather than defaulting to zero, because
    a silently-zero balance is a trading-safety hazard (§33).
    """
    if isinstance(value, float):
        return to_decimal(value, strict=False)
    if isinstance(value, Decimal | int | str):
        return to_decimal(value)
    msg = f"cannot interpret {type(value).__name__} as a decimal amount"
    raise TypeError(msg)


def quantize(
    value: Decimal,
    places: Decimal,
    *,
    rounding: str = ROUND_HALF_UP,
) -> Decimal:
    """Round ``value`` to ``places`` using ``rounding``.

    ``value`` must already be a ``Decimal``; :func:`to_decimal` is the module's
    single conversion boundary and the only place a ``float`` is accepted.
    """
    # The declared parameter type is ``Decimal``, so no *typed* caller can pass
    # anything else. The guard stays anyway: money reaches this function from
    # untyped boundaries (JSON payloads, Redis values, DB drivers, ad-hoc
    # scripts), and a float silently rounded here is precisely the class of
    # financial bug this module exists to prevent. It must fail with a clear
    # TypeError rather than an AttributeError from `is_finite`.
    #
    # Widening through ``object`` keeps the check reachable for the type checker
    # — a `# type: ignore[unreachable]` would suppress the very analysis that
    # should notice if this guard ever does become dead code.
    received: object = value
    if not isinstance(received, Decimal):
        msg = "quantize() requires a Decimal; convert with to_decimal() first"
        raise TypeError(msg)
    if not received.is_finite():
        msg = f"cannot quantize non-finite decimal: {received}"
        raise ValueError(msg)
    return received.quantize(places, rounding=rounding)


def quantize_price(value: Decimal) -> Decimal:
    """Round a price to internal price precision."""
    return quantize(value, PRICE_PLACES)


def quantize_money(value: Decimal) -> Decimal:
    """Round a fiat/quote accounting figure to 2 dp, half-up."""
    return quantize(value, MONEY_PLACES)


def quantize_amount(value: Decimal) -> Decimal:
    """Round a tradable quantity to 8 dp, half-up."""
    return quantize(value, AMOUNT_PLACES)


def truncate_amount(value: Decimal) -> Decimal:
    """Truncate a tradable quantity to 8 dp.

    Truncation (not rounding) is used when sizing an order: rounding up could
    request more than the available balance and produce a rejected order or, at
    worst, an unintended exposure.
    """
    return quantize(value, AMOUNT_PLACES, rounding=ROUND_DOWN)


def quantize_percent(value: Decimal) -> Decimal:
    """Round a percentage / ROI figure to 4 dp."""
    return quantize(value, PERCENT_PLACES)


def is_positive(value: Decimal) -> bool:
    """Return ``True`` when ``value`` is finite and strictly greater than zero."""
    return value.is_finite() and value > ZERO


def serialize_decimal(value: Decimal) -> str:
    """Serialise a ``Decimal`` as an exact, non-scientific JSON string.

    JSON numbers are doubles in virtually every parser, so emitting
    ``Decimal("0.30000000000000004")`` as a JSON *number* would reintroduce the
    exact precision loss this module exists to prevent. Money is therefore
    transported as a string and parsed back with :func:`to_decimal`.
    """
    if not value.is_finite():
        msg = f"cannot serialize non-finite decimal: {value}"
        raise ValueError(msg)
    # "f" format never produces an exponent, so downstream clients never have to
    # handle "1E+2" — a JSON number in scientific notation is a precision trap
    # for every consumer that parses it as a double.
    return format(value, "f")
