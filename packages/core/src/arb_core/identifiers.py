"""Identifier generation.

The platform uses **UUIDv7** (RFC 9562) for primary keys. Compared with random
UUIDv4 this matters for a trading system: the leading 48 bits are a millisecond
timestamp, so primary keys sort chronologically and B-tree indexes on
high-insert tables (``orders``, ``order_fills``, ``opportunities``,
``market_snapshots``) get append-mostly write patterns instead of random page
splits (§82).

IDs are exposed externally in their canonical string form, optionally with a
short type prefix (``ord_``, ``trd_``, ``bot_``) so that support staff and log
readers can tell at a glance what kind of object an identifier refers to.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Final
from uuid import UUID

__all__ = ["new_id", "new_id_str", "parse_id", "prefixed_id", "uuid7"]

# UUIDv7 field layout (RFC 9562 §5.7):
#   48 bits unix_ts_ms | 4 bits version | 12 bits rand_a | 2 bits variant | 62 bits rand_b
_VERSION_SHIFT: Final[int] = 76
_VERSION_BITS: Final[int] = 0x7
_RAND_A_SHIFT: Final[int] = 64
_RAND_A_MASK: Final[int] = 0x0FFF
_VARIANT_SHIFT: Final[int] = 62
_VARIANT_BITS: Final[int] = 0b10
_RAND_B_MASK: Final[int] = 0x3FFFFFFFFFFFFFFF
_TIMESTAMP_MASK: Final[int] = 0xFFFFFFFFFFFF
_TIMESTAMP_SHIFT: Final[int] = 80


@dataclass
class _MonotonicState:
    """Per-process guard keeping UUIDv7 ordering monotonic."""

    timestamp_ms: int = 0
    sequence: int = 0


_lock = threading.Lock()
_state = _MonotonicState()


def uuid7() -> UUID:
    """Generate a time-ordered UUIDv7.

    Ordering is correct to millisecond resolution across processes. Within a
    process it is *strictly* increasing, because the 12-bit ``rand_a`` field is
    used as a monotonic counter rather than pure randomness — which is what keeps
    batched inserts append-only in the B-tree (§82).

    With the lock held, four cases are handled:

    * **New millisecond** — reseed the sequence from the CSPRNG.
    * **Same millisecond** — advance the sequence, so IDs generated in a tight
      loop stay strictly increasing and therefore preserve insertion order.
    * **Sequence exhausted** — the 12-bit ``rand_a`` field can only hold 4096
      values, so a burst of more than 4096 IDs inside one millisecond would wrap
      and could collide. Rather than accept that, the timestamp is advanced by
      one millisecond. Uniqueness and ordering are both preserved, at the cost
      of the identifier running up to a millisecond ahead of the wall clock —
      which is harmless because nothing derives a deadline from an ID.
    * **Clock moved backwards** (NTP step, VM migration) — hold the previously
      issued timestamp instead of going backwards, which would sort a new row
      before one already written.
    """
    with _lock:
        timestamp_ms = int(time.time() * 1000)
        if timestamp_ms <= _state.timestamp_ms:
            timestamp_ms = _state.timestamp_ms
            sequence = _state.sequence + 1
            if sequence > _RAND_A_MASK:
                timestamp_ms += 1
                sequence = 0
        else:
            sequence = int.from_bytes(os.urandom(2), "big") & _RAND_A_MASK
        _state.timestamp_ms = timestamp_ms
        _state.sequence = sequence

    rand_b = int.from_bytes(os.urandom(8), "big") & _RAND_B_MASK

    value = (timestamp_ms & _TIMESTAMP_MASK) << _TIMESTAMP_SHIFT
    value |= _VERSION_BITS << _VERSION_SHIFT
    value |= sequence << _RAND_A_SHIFT
    value |= _VARIANT_BITS << _VARIANT_SHIFT
    value |= rand_b
    return UUID(int=value)


def new_id() -> UUID:
    """Return a new primary-key UUID."""
    return uuid7()


def new_id_str() -> str:
    """Return a new primary-key UUID as a canonical lowercase string."""
    return str(uuid7())


def parse_id(value: str | UUID) -> UUID:
    """Parse an identifier, accepting an optional ``prefix_`` decoration.

    Prefixed IDs such as ``ord_01890b1e-...`` are accepted so that clients can
    round-trip the decorated form without a separate normalisation step.
    """
    if isinstance(value, UUID):
        return value
    candidate = value.strip()
    if "_" in candidate:
        candidate = candidate.split("_", 1)[1]
    try:
        return UUID(candidate)
    except (ValueError, AttributeError, TypeError) as exc:
        msg = f"invalid identifier: {value!r}"
        raise ValueError(msg) from exc


def prefixed_id(prefix: str) -> str:
    """Return a new identifier decorated with a short object-type prefix."""
    if not prefix or not prefix.isascii() or not prefix.isalnum():
        msg = "prefix must be a short ASCII alphanumeric tag, e.g. 'ord', 'trd', 'bot'"
        raise ValueError(msg)
    return f"{prefix.lower()}_{uuid7()}"
