"""Security primitives shared by every service.

Phase 1 provides secret **redaction** — the control that keeps credentials out
of logs, error payloads and telemetry (§12, §127, §133). Password hashing,
envelope encryption of exchange credentials and RBAC land in later phases and
will be added to this package rather than duplicated in callers.
"""

from __future__ import annotations

from arb_core.security.redaction import (
    REDACTED,
    is_sensitive_key,
    mask_api_key,
    mask_dsn,
    redact_mapping,
    redact_object,
    redact_text,
)

__all__ = [
    "REDACTED",
    "is_sensitive_key",
    "mask_api_key",
    "mask_dsn",
    "redact_mapping",
    "redact_object",
    "redact_text",
]
