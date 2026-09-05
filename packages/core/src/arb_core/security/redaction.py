"""Secret redaction (§12, §127, §133).

Nothing sensitive may reach a log line, an API error body, a metric label or a
telemetry payload. Redaction is implemented once, here, and applied by:

* :mod:`arb_core.log` — a ``logging`` filter on every handler,
* :mod:`arb_core.errors` — the client-safe error payload builder,
* the audit-log service — ``old_value_safe`` / ``new_value_safe`` (§53).

Design notes:

* **Key-based redaction is the primary control.** Any mapping key that looks
  credential-shaped is replaced wholesale, regardless of its value. This is
  deliberately aggressive: a false positive costs one log field, a false
  negative leaks a key that controls real money.
* **Pattern-based redaction is the secondary control**, catching secrets
  embedded in free text such as ``Authorization: Bearer ...`` headers or
  ``postgresql://user:password@host`` DSNs.
* **Length is never disclosed.** :func:`mask_api_key` emits a fixed number of
  asterisks, because revealing the exact length of a secret narrows a search
  space and lets an attacker confirm a guess.
"""

from __future__ import annotations

import re
from typing import Any, Final

__all__ = [
    "REDACTED",
    "is_sensitive_key",
    "mask_api_key",
    "mask_dsn",
    "redact_mapping",
    "redact_object",
    "redact_text",
]

REDACTED: Final[str] = "[REDACTED]"

#: Key fragments that mark a mapping entry as credential-shaped.
#:
#: Note the deliberate absence of the bare fragment ``auth``: it would match
#: innocuous keys such as ``author``. The specific forms below are listed
#: instead.
_SENSITIVE_KEY_FRAGMENTS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "api_secret",
        "apisecret",
        "access_key",
        "access_token",
        "auth_token",
        "authorization",
        "authenticate",
        "bearer",
        "client_secret",
        "cookie",
        "credential",
        "csrf",
        "encryption_key",
        "jwt",
        "key",
        "mnemonic",
        "otp",
        "passcode",
        "passwd",
        "password",
        "private_key",
        "pwd",
        "refresh_token",
        "secret",
        "seed",
        "session_token",
        "signature",
        "signing_key",
        "token",
        "totp",
    }
)

#: Keys that contain a sensitive-looking fragment but are safe to log.
_SAFE_KEY_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "cache_key",
        "client_id",
        "idempotency_key",
        "key_prefix",
        "partition_key",
        "primary_key",
        "public_key",
        "redis_key_prefix",
        "request_id",
        "routing_key",
        "sort_key",
        "trace_key",
    }
)

_KEY_NORMALISE_RE: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

# --- Free-text patterns -----------------------------------------------------
_BEARER_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_BASIC_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(basic\s+)[A-Za-z0-9+/=]{8,}")
_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(x-api-key|api[_-]?key|apikey|authorization|proxy-authorization)"
    r"(\s*[:=]\s*)(\S+)"
)
_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?secret|private[_-]?key|"
    r"encryption[_-]?key|client[_-]?secret|mnemonic|seed)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
)
# The userinfo component is optional (`redis://:password@host` is valid and is
# exactly how a Redis password is usually supplied), so it must be allowed to be
# empty — otherwise that common form leaks the password.
_DSN_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/@\s]*:)([^@\s]+)(@)")

_MASK_STARS: Final[str] = "*" * 12
_MIN_VISIBLE: Final[int] = 4
_MAX_REDACTION_DEPTH: Final[int] = 12


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` when ``key`` looks like it holds a credential.

    Comparison is case-insensitive and ignores separators, so ``APIKey``,
    ``api-key`` and ``api_key`` are all treated identically.
    """
    normalised = _KEY_NORMALISE_RE.sub("_", str(key).lower()).strip("_")
    if normalised in _SAFE_KEY_ALLOWLIST:
        return False
    if any(fragment in normalised for fragment in _SENSITIVE_KEY_FRAGMENTS):
        return True
    # Catch concatenated camelCase forms such as "userApiKey".
    compact = normalised.replace("_", "")
    return any(fragment.replace("_", "") in compact for fragment in _SENSITIVE_KEY_FRAGMENTS)


def mask_api_key(value: Any, *, visible_suffix: int = _MIN_VISIBLE) -> str:
    """Mask a secret for display, revealing only a short suffix.

    Produces the admin-UI form required by §12::

        API key: ************1234

    The number of asterisks is **fixed** so the output never discloses the
    length of the underlying secret.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if not text:
        return ""
    if visible_suffix <= 0 or len(text) <= visible_suffix:
        return _MASK_STARS
    return f"{_MASK_STARS}{text[-visible_suffix:]}"


def mask_dsn(url: str) -> str:
    """Strip the password component from a database/Redis/cache URL."""
    if not url:
        return url
    return _DSN_RE.sub(r"\1" + REDACTED + r"\3", url)


def redact_text(text: str) -> str:
    """Scrub credential-shaped values embedded in free text."""
    if not text:
        return text
    result = _BEARER_RE.sub(r"\1" + REDACTED, text)
    result = _BASIC_RE.sub(r"\1" + REDACTED, result)
    result = _DSN_RE.sub(r"\1" + REDACTED + r"\3", result)
    result = _HEADER_RE.sub(r"\1\2" + REDACTED, result)
    return _ASSIGNMENT_RE.sub(r"\1\2" + REDACTED, result)


def redact_mapping(data: dict[Any, Any]) -> dict[Any, Any]:
    """Return a redacted copy of ``data`` (see :func:`redact_object`)."""
    redacted = redact_object(data)
    return redacted if isinstance(redacted, dict) else {}


def redact_object(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact credential-shaped material from ``value``.

    Handles mappings, sequences and strings. Objects of other types are passed
    through unchanged; they are deliberately **not** coerced to text here,
    because ``repr`` of an arbitrary object could itself expose a secret held
    in one of its attributes.
    """
    # Guard against self-referential structures and pathological nesting.
    if _depth > _MAX_REDACTION_DEPTH:
        return REDACTED

    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for item_key, item_value in value.items():
            if is_sensitive_key(str(item_key)):
                out[item_key] = REDACTED
            else:
                out[item_key] = redact_object(item_value, _depth=_depth + 1)
        return out
    if isinstance(value, list):
        return [redact_object(item, _depth=_depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_object(item, _depth=_depth + 1) for item in value)
    if isinstance(value, frozenset):
        return frozenset(redact_object(item, _depth=_depth + 1) for item in value)
    if isinstance(value, set):
        return {redact_object(item, _depth=_depth + 1) for item in value}
    if isinstance(value, str):
        return redact_text(value)
    return value
