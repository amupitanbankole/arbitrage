"""Structured logging (§66, §127).

Production emits one JSON object per line::

    {
      "timestamp": "2026-09-05T12:00:00.000000+00:00",
      "level": "INFO",
      "service": "execution-worker",
      "logger": "arb_core.worker",
      "request_id": "01J...",
      "trade_id": "01J...",
      "exchange": "binance",
      "symbol": "BTC/USDT",
      "message": "Order submitted"
    }

Non-negotiable properties:

* **Secrets never appear.** :class:`RedactionFilter` plus the formatter's
  redaction pass run :mod:`arb_core.security.redaction` over the rendered
  message, the traceback and every structured field.
* **Context is automatic.** Anything bound with
  :func:`arb_core.context.context_scope` is merged into every record without the
  call site having to remember to pass it.
* **Timestamps are UTC and timezone-aware** (§75).

The ``console`` format exists for local development only; it renders the same
record content in a readable single line and is equally redacted.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, ClassVar, Final

from arb_core.context import current_context
from arb_core.security.redaction import REDACTED, is_sensitive_key, redact_object, redact_text

__all__ = [
    "ConsoleFormatter",
    "JsonFormatter",
    "RedactionFilter",
    "configure_logging",
    "get_logger",
]

#: Attributes ``logging.LogRecord`` always carries. Anything else in
#: ``record.__dict__`` was supplied via ``extra=`` and is a structured field.
_RESERVED_RECORD_ATTRS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

#: Loggers owned by dependencies. They are re-pointed at our handlers so their
#: output is structured and redacted too, instead of using their own formats.
_THIRD_PARTY_LOGGERS: Final[tuple[str, ...]] = (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "fastapi",
    "sqlalchemy.engine",
    "sqlalchemy.pool",
    "alembic",
    "asyncio",
    "httpx",
    "httpcore",
)

_LEVEL_MAP: Final[dict[str, int]] = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def _json_default(value: Any) -> Any:
    """Serialise types JSON cannot handle natively.

    ``Decimal`` is emitted as an exact string (§74) rather than a float, which
    would reintroduce the precision loss the platform forbids.
    """
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, set | frozenset | tuple):
        return list(value)
    if isinstance(value, BaseException):
        return f"{type(value).__name__}"
    return repr(value)


def _record_extras(record: logging.LogRecord) -> dict[str, Any]:
    """Extract caller-supplied structured fields from a record."""
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _RESERVED_RECORD_ATTRS and not key.startswith("_")
    }


class RedactionFilter(logging.Filter):
    """Neutralise credential-named ``extra`` fields before formatting (§133).

    The filter replaces the *value* of any sensitive-named attribute with
    :data:`REDACTED` regardless of what it contained, so a careless
    ``logger.info(..., extra={"api_key": key})`` cannot leak even when the value
    itself looks innocuous.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        super().__init__()
        self.enabled = enabled

    def filter(self, record: logging.LogRecord) -> bool:
        """Always returns ``True``; this filter transforms, never drops."""
        if not self.enabled:
            return True
        for attribute in list(record.__dict__):
            if attribute in _RESERVED_RECORD_ATTRS:
                continue
            if is_sensitive_key(attribute):
                setattr(record, attribute, REDACTED)
        return True


class JsonFormatter(logging.Formatter):
    """Render records as single-line redacted JSON."""

    def __init__(self, *, service: str, redaction_enabled: bool = True) -> None:
        super().__init__()
        self.service = service
        self.redaction_enabled = redaction_enabled
        self._filter = RedactionFilter(enabled=redaction_enabled)

    def format(self, record: logging.LogRecord) -> str:
        """Produce the JSON line for ``record``."""
        self._filter.filter(record)

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Automatic ambient context (request_id, user_id, trade_id, exchange...).
        payload.update(current_context())

        # Explicit structured fields passed via extra=; context wins on conflict
        # because it is the more specific, operation-scoped value.
        for key, value in _record_extras(record).items():
            payload.setdefault(key, value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        if self.redaction_enabled:
            payload = redact_object(payload)

        return json.dumps(payload, default=_json_default, ensure_ascii=False, separators=(",", ":"))


class ConsoleFormatter(logging.Formatter):
    """Human-readable single-line format for local development."""

    _COLOURS: ClassVar[dict[str, str]] = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;31m",
    }
    _RESET: ClassVar[str] = "\033[0m"

    def __init__(
        self,
        *,
        service: str,
        redaction_enabled: bool = True,
        colour: bool = False,
    ) -> None:
        super().__init__()
        self.service = service
        self.redaction_enabled = redaction_enabled
        self.colour = colour
        self._filter = RedactionFilter(enabled=redaction_enabled)

    def _render_level(self, level: str) -> str:
        if not self.colour:
            return f"{level:<8}"
        colour = self._COLOURS.get(level, "")
        return f"{colour}{level:<8}{self._RESET}"

    def _render_extras(self, record: logging.LogRecord) -> str:
        merged = _record_extras(record)
        for key, value in current_context().items():
            merged.setdefault(key, value)
        if not merged:
            return ""
        rendered = redact_object(merged) if self.redaction_enabled else merged
        return " " + json.dumps(
            rendered, default=_json_default, ensure_ascii=False, separators=(",", ":")
        )

    def format(self, record: logging.LogRecord) -> str:
        """Produce the console line for ``record``."""
        self._filter.filter(record)

        when = datetime.fromtimestamp(record.created, tz=UTC).strftime("%H:%M:%S.%f")[:-3]
        message = record.getMessage()
        if self.redaction_enabled:
            message = redact_text(message)

        output = (
            f"{when} {self._render_level(record.levelname)} "
            f"[{self.service}] {record.name}: {message}{self._render_extras(record)}"
        )
        if record.exc_info:
            exception_text = self.formatException(record.exc_info)
            if self.redaction_enabled:
                exception_text = redact_text(exception_text)
            output = f"{output}\n{exception_text}"
        return output


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger.

    Callers should pass their module ``__name__`` so the ``logger`` field in
    JSON output identifies the emitting component.
    """
    return logging.getLogger(name)


def _resolve_level(level: str) -> int:
    """Map a level name to a ``logging`` constant, defaulting to INFO."""
    return _LEVEL_MAP.get(level.upper(), logging.INFO)


def _detect_colour(stream: Any) -> bool:
    """Enable ANSI colour only when writing to an interactive terminal."""
    isatty = getattr(stream, "isatty", None)
    return bool(isatty()) if callable(isatty) else False


def configure_logging(
    *,
    level: str = "INFO",
    log_format: str = "json",
    service: str = "arbitrage-platform",
    redaction_enabled: bool = True,
    stream: Any = None,
) -> None:
    """Install the platform logging configuration on the root logger.

    Idempotent: calling it repeatedly (as happens when the FastAPI app factory
    runs several times under a test-suite) replaces the previous handlers
    instead of stacking duplicates, which would otherwise emit every line twice.

    Redaction cannot be disabled in production — :mod:`arb_core.config` forces
    ``redaction_enabled=True`` when ``ENVIRONMENT=production``.
    """
    resolved_level = _resolve_level(level)
    output_stream = stream if stream is not None else sys.stdout

    handler = logging.StreamHandler(output_stream)
    handler.setLevel(resolved_level)

    formatter: logging.Formatter
    if log_format == "console":
        formatter = ConsoleFormatter(
            service=service,
            redaction_enabled=redaction_enabled,
            colour=_detect_colour(output_stream),
        )
    else:
        formatter = JsonFormatter(service=service, redaction_enabled=redaction_enabled)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
        existing.close()
    root.addHandler(handler)
    root.setLevel(resolved_level)

    # Route dependency loggers through our handlers so nothing is emitted in an
    # unstructured, unredacted format.
    for logger_name in _THIRD_PARTY_LOGGERS:
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.propagate = True
        if logger.level == logging.NOTSET:
            logger.setLevel(resolved_level)

    # Uvicorn's access log duplicates data captured by our request middleware;
    # never let it be more verbose than the configured level.
    logging.getLogger("uvicorn.access").setLevel(max(resolved_level, logging.INFO))

    # Send warnings.warn() output through the same pipeline.
    logging.captureWarnings(True)
