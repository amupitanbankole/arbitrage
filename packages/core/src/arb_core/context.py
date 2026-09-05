"""Request- and operation-scoped context (§66).

Every log line, metric and audit entry produced while handling a request or a
worker job must be attributable to that unit of work. Values are stored in
:mod:`contextvars`, which are propagated correctly across ``await`` boundaries
and are isolated per task, so concurrent requests never bleed into each other.

The context is a single copy-on-write mapping rather than one ``ContextVar`` per
field: trading code needs to attach ``trade_id``, ``bot_id``, ``exchange``,
``symbol`` and ``order_id`` (§66) without this module knowing about them in
advance, and adding a field must not require touching every call site.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

__all__ = [
    "clear_context",
    "context_scope",
    "current_context",
    "get_value",
    "request_id",
    "reset",
    "set_value",
    "user_id",
]

_EMPTY: Mapping[str, Any] = MappingProxyType({})
_context: ContextVar[Mapping[str, Any]] = ContextVar("arb_context", default=_EMPTY)


def current_context() -> dict[str, Any]:
    """Return a mutable copy of the active context mapping."""
    return dict(_context.get())


@contextmanager
def context_scope(**values: Any) -> Iterator[None]:
    """Bind ``values`` into the context for the duration of the block.

    ``None`` values are ignored so callers can pass optional identifiers
    straight through without pre-filtering::

        with context_scope(request_id=rid, user_id=user.id if user else None):
            ...
    """
    updates = {key: value for key, value in values.items() if value is not None}
    merged = {**_context.get(), **updates}
    token = _context.set(MappingProxyType(merged))
    try:
        yield
    finally:
        _context.reset(token)


def set_value(key: str, value: Any) -> Token[Mapping[str, Any]]:
    """Set a single context value, returning the reset token.

    Prefer :func:`context_scope` where possible; use this only when the lifetime
    of the value is managed by something other than a lexical block (for
    example middleware that resets in a separate callback).
    """
    merged = {**_context.get(), key: value}
    return _context.set(MappingProxyType(merged))


def reset(token: Token[Mapping[str, Any]]) -> None:
    """Restore the context captured by a previous :func:`set_value` call.

    Middleware that cannot use :func:`context_scope` — because the bind and the
    reset happen on opposite sides of an ``await self.app(...)`` — must use this
    rather than reaching into the module's private ``ContextVar``.
    """
    _context.reset(token)


def get_value(key: str, default: Any = None) -> Any:
    """Read a single context value."""
    return _context.get().get(key, default)


def clear_context() -> Token[Mapping[str, Any]]:
    """Reset the context to empty. Used between worker jobs and in tests."""
    return _context.set(_EMPTY)


def request_id() -> str | None:
    """The correlation identifier for the current request/job, if bound."""
    value = _context.get().get("request_id")
    return str(value) if value is not None else None


def user_id() -> str | None:
    """The authenticated user's identifier for the current request, if bound."""
    value = _context.get().get("user_id")
    return str(value) if value is not None else None
