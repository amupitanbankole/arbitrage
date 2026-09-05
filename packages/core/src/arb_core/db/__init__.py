"""Database layer: declarative base, portable types, engine and sessions."""

from __future__ import annotations

from arb_core.db.base import (
    NAMING_CONVENTION,
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from arb_core.db.session import Database, build_engine_kwargs, describe_url, is_sqlite_url
from arb_core.db.sql_types import (
    GUID,
    AmountDecimal,
    JSONType,
    MoneyDecimal,
    PreciseDecimal,
    PriceDecimal,
    RateDecimal,
    UTCDateTime,
)

__all__ = [
    "GUID",
    "NAMING_CONVENTION",
    "AmountDecimal",
    "Base",
    "Database",
    "JSONType",
    "MoneyDecimal",
    "PreciseDecimal",
    "PriceDecimal",
    "RateDecimal",
    "SoftDeleteMixin",
    "TimestampMixin",
    "UTCDateTime",
    "UUIDPrimaryKeyMixin",
    "build_engine_kwargs",
    "describe_url",
    "is_sqlite_url",
]
