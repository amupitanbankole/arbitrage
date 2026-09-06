"""Identifier generation and normalisation.

The platform uses **UUIDv7** (RFC 9562) for primary keys. Compared with random
UUIDv4 this matters for a trading system: the leading 48 bits are a millisecond
timestamp, so primary keys sort chronologically and B-tree indexes on
high-insert tables (``orders``, ``order_fills``, ``opportunities``,
``market_snapshots``) get append-mostly write patterns instead of random page
splits (§82).

IDs are exposed externally in their canonical string form, optionally with a
short type prefix (``ord_``, ``trd_``, ``bot_``) so that support staff and log
readers can tell at a glance what kind of object an identifier refers to.

One identifier is not generated but typed: the login email address. It lives here
because the rule that matters is the same kind of rule — every part of the platform
must agree on the canonical form of an identifier, or lookups disagree. See
:func:`normalize_email`.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Final
from uuid import UUID

__all__ = [
    "EMAIL_MAX_LENGTH",
    "new_id",
    "new_id_str",
    "normalize_email",
    "parse_id",
    "prefixed_id",
    "uuid7",
]

#: Longest address accepted. RFC 5321 allows 254 characters in a reverse-path
#: (320 only for the quoted-local-part form nobody implements); 254 is what every
#: real mail server will actually deliver to, and it is the width of the
#: ``users.email`` column, so validation and storage cannot disagree.
EMAIL_MAX_LENGTH: Final[int] = 254

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


def normalize_email(value: str) -> str:
    """Return the canonical form of a login email address.

    The email address is the one identifier on this platform that a human types,
    so it is the one that can arrive in several spellings. Every path that stores
    or looks up an account must agree on the canonical form, or the same person
    becomes two accounts — and two accounts with one password-reset flow is a
    takeover, not a duplicate.

    Applied: surrounding whitespace is stripped and the address is lowercased.

    Deliberately **not** applied:

    * **No dot-stripping or provider-specific rules.** ``a.b@gmail.com`` and
      ``ab@gmail.com`` are the same mailbox at Google, but "remove dots" is wrong
      for most other providers, and guessing per-domain means two people can end
      up sharing one account. Merging distinct addresses is worse than storing a
      redundant one.
    * **No Unicode case-folding beyond ``str.lower()``.** ``casefold()`` would map
      ``ß`` to ``ss`` and ﬁ to fi, again merging addresses that are not the same.
      Internationalised addresses are lowercased by ``lower()`` and left alone
      otherwise.
    * **No internal-whitespace removal and no syntax validation.** A space inside
      an address is a malformed address, and silently repairing it would hide a
      client bug. Rejecting it is :mod:`arb_core.validation`'s job (Pydantic
      ``EmailStr``), not this function's.

    The ``users.email`` column carries a ``CHECK (email = lower(email))``
    constraint, so a row that bypassed this function cannot be written at all:
    the unique index cannot be defeated by casing.
    """
    return _require_text(value).strip().lower()


def _require_text(value: object) -> str:
    """Return ``value`` when it is text, and raise otherwise.

    The parameter is typed ``object`` so that the runtime guard is reachable:
    ``normalize_email`` is annotated ``str``, and mypy would (correctly) report an
    ``isinstance`` check on an already-``str`` value as dead code. Emails reach this
    function from request bodies and administrative tooling, where a ``None`` or a
    ``bytes`` is a real possibility and must be a clear ``TypeError`` rather than an
    ``AttributeError`` from ``.strip()``.
    """
    if not isinstance(value, str):
        msg = "email must be a str"
        raise TypeError(msg)
    return value
