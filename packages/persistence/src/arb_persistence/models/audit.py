"""Append-only audit log (§53, §83, §131).

Every sensitive action — administrative configuration changes, role changes,
live-trading activation, kill-switch operation, credential events — produces one
row here. The table is append-only by design:

* there is no ``updated_at`` and no soft-delete column, so there is nothing to
  update;
* the repository exposes ``add`` and read methods only;
* on PostgreSQL the migration installs a trigger rejecting ``UPDATE`` and
  ``DELETE``, so the guarantee holds even for a superuser session or a bug in
  future code.

**Never store secrets here.** ``old_value_safe`` / ``new_value_safe`` are
scrubbed with :mod:`arb_core.security.redaction` before insertion by the audit
service; the column names carry the ``_safe`` suffix as a permanent reminder at
every call site (§53, §133).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Final

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from arb_core.clock import utc_now
from arb_core.db import GUID, Base, JSONType, UTCDateTime, UUIDPrimaryKeyMixin
from arb_persistence.models.enums import ActorType, AuditResult, enum_column

__all__ = ["AuditLog"]

_ACTION_MAX_LENGTH: Final[int] = 128


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """One immutable record of a sensitive action."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        # "what did this actor do, in order" — the dominant admin query (§45).
        Index("ix_audit_logs_actor_id_occurred_at", "actor_id", "occurred_at"),
        # "everything that ever happened to this object" (§50 execution timeline).
        Index("ix_audit_logs_resource_type_resource_id", "resource_type", "resource_id"),
        # "every kill-switch activation" / "every live-trading enablement" (§131).
        Index("ix_audit_logs_action_occurred_at", "action", "occurred_at"),
        # Retention sweeps are time-ordered (§83).
        Index("ix_audit_logs_occurred_at", "occurred_at"),
    )

    #: When the audited action happened. Timezone-aware UTC (§75).
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utc_now)

    #: ``None`` for system- and worker-originated entries.
    actor_id: Mapped[uuid.UUID | None] = mapped_column(GUID, nullable=True)
    actor_type: Mapped[ActorType] = mapped_column(
        enum_column(ActorType, name="actor_type"), nullable=False
    )
    #: The role the actor held *at the time*, so the record stays meaningful
    #: after the actor's roles change (§103).
    actor_role: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: Stable machine-readable verb, e.g. ``ADMIN_TRIGGERED_GLOBAL_KILL_SWITCH``.
    action: Mapped[str] = mapped_column(String(_ACTION_MAX_LENGTH), nullable=False)

    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: Redacted before/after state. Must never contain passwords, API secrets,
    #: tokens or private keys (§53).
    old_value_safe: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    new_value_safe: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    #: Operator-supplied justification. Required for high-risk actions (§92).
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    result: Mapped[AuditResult] = mapped_column(
        enum_column(AuditResult, name="audit_result"),
        nullable=False,
        default=AuditResult.SUCCESS,
    )

    #: Correlates the audit entry with structured logs for the same request (§66).
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:
        # Deliberately excludes value payloads: a repr that reaches a log line
        # must not be able to carry redacted-but-sensitive material.
        return f"<AuditLog {self.action} {self.resource_type}:{self.resource_id} {self.result}>"
