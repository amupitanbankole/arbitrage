"""Portable column types (§9, §74, §75).

Production runs PostgreSQL. The automated test-suite must be hermetic, so it
runs the *same* models and the *same* migrations against SQLite. That only works
if the types are honest about both dialects — otherwise tests pass while
production silently stores different values.

Two dialect differences matter for a trading system, and both are handled here
rather than in models:

**Decimal precision.** SQLite has no decimal type. SQLAlchemy's default
behaviour is to store ``Decimal`` as a float and convert back, which introduces
exactly the binary rounding error §74 forbids — a test asserting
``net_profit == Decimal("0.30")`` could pass against SQLite while production
accumulated rounding drift. :class:`PreciseDecimal` stores the value as text on
SQLite and as ``NUMERIC`` on PostgreSQL, so both are exact.

**Timezone awareness.** SQLite returns naive datetimes. Left alone, that means
test code paths see naive values and production sees aware ones, so a
timezone bug can hide in CI and surface on the VPS. :class:`UTCDateTime`
normalises in both directions: it stores UTC, and it attaches UTC on the way
out, keeping every value the application sees timezone-aware.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Numeric, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON, TypeDecorator, Uuid

from arb_core.clock import assume_utc, ensure_aware
from arb_core.money import to_decimal

if TYPE_CHECKING:
    from sqlalchemy.engine import Dialect

__all__ = [
    "GUID",
    "AmountDecimal",
    "JSONType",
    "MoneyDecimal",
    "PreciseDecimal",
    "PriceDecimal",
    "RateDecimal",
    "UTCDateTime",
]

#: Portable UUID. PostgreSQL uses native ``UUID``; other dialects fall back to
#: ``CHAR(32)``. Combined with UUIDv7 this keeps primary keys compact and
#: time-ordered (§82).
GUID = Uuid


class PreciseDecimal(TypeDecorator[Decimal]):
    """Exact fixed-point decimal on every dialect.

    PostgreSQL -> ``NUMERIC(precision, scale)``
    SQLite     -> ``VARCHAR`` holding the exact decimal literal
    """

    impl = Numeric
    cache_ok = True

    def __init__(self, precision: int = 38, scale: int = 18, **kwargs: Any) -> None:
        self.precision = precision
        self.scale = scale
        super().__init__(**kwargs)

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        """Choose the physical type for ``dialect``."""
        if dialect.name == "sqlite":
            # +2 for the sign and the decimal point; +8 headroom for values that
            # arrive with more integer digits than the nominal precision.
            return dialect.type_descriptor(String(self.precision + 10))
        return dialect.type_descriptor(Numeric(self.precision, self.scale))

    def process_bind_param(self, value: Decimal | None, dialect: Dialect) -> Any:
        """Normalise on the way in, rejecting non-finite values."""
        if value is None:
            return None
        decimal_value = value if isinstance(value, Decimal) else to_decimal(value, strict=False)
        if not decimal_value.is_finite():
            msg = f"cannot persist non-finite decimal: {decimal_value}"
            raise ValueError(msg)
        if dialect.name == "sqlite":
            return str(decimal_value)
        return decimal_value

    def process_result_value(
        self,
        value: Any,
        # TypeDecorator fixes this signature; not every implementation needs the
        # dialect, but it cannot be dropped.
        dialect: Dialect,  # noqa: ARG002
    ) -> Decimal | None:
        """Return an exact ``Decimal`` on the way out."""
        if value is None:
            return None
        if isinstance(value, Decimal):
            return value
        return to_decimal(value, strict=False)

    def __repr__(self) -> str:
        return f"PreciseDecimal(precision={self.precision}, scale={self.scale})"


#: Prices and quantities: 18 decimal places covers every venue's tick/step size,
#: including the 16-dp precision used by some quote conversions (§74).
PriceDecimal = PreciseDecimal(38, 18)
AmountDecimal = PreciseDecimal(38, 18)
#: Fiat/quote accounting and P&L.
MoneyDecimal = PreciseDecimal(30, 10)
#: Fee rates, ROI and spread percentages.
RateDecimal = PreciseDecimal(20, 12)


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC timestamp on every dialect (§75)."""

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        """Always request a timezone-aware ``DATETIME``."""
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: Dialect,  # noqa: ARG002 - signature fixed by TypeDecorator
    ) -> datetime | None:
        """Normalise to UTC and reject naive input."""
        if value is None:
            return None
        return ensure_aware(value)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: Dialect,  # noqa: ARG002 - signature fixed by TypeDecorator
    ) -> datetime | None:
        """Guarantee the application only ever sees aware UTC datetimes.

        SQLite returns naive values; they were stored as UTC by
        :meth:`process_bind_param`, so attaching UTC is a correctness
        restoration rather than an assumption.
        """
        if value is None:
            return None
        return assume_utc(value)


class JSONType(TypeDecorator[Any]):
    """JSON column that upgrades to ``JSONB`` on PostgreSQL.

    ``JSONB`` is required for indexed querying of payload fields (GIN indexes)
    and for atomic partial updates, neither of which plain ``JSON`` supports.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        """Use ``JSONB`` on PostgreSQL, plain ``JSON`` elsewhere."""
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())
