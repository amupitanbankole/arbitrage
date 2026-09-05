"""Audit-log writing (§53, §91, §131).

Two guarantees this service is responsible for:

1. **Redaction before persistence.** ``old_value`` / ``new_value`` / ``reason``
   pass through :mod:`arb_core.security.redaction`. A credential that reaches
   ``audit_logs`` is a credential in a backup, in a replica and in every admin
   query result — the worst possible place to leak one (§53, §133). The model's
   columns are named ``*_safe`` so the guarantee is visible at every call site.

2. **Denials are recorded, not only successes.** ``result=DENIED`` entries are
   what make privilege probing visible in the security centre (§52, §130). A
   permission check that fails silently leaves no evidence that it was attempted.

The service does not commit. The caller's transaction boundary decides when the
entry becomes durable, which is what allows an audit entry and the change it
describes to be atomic (§63) — an action that succeeds without its audit record,
or an audit record for an action that rolled back, are both worse than useless.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from arb_core.context import request_id as current_request_id
from arb_core.log import get_logger
from arb_core.security.redaction import redact_object, redact_text
from arb_persistence.models.audit import AuditLog
from arb_persistence.models.enums import ActorType, AuditResult
from arb_persistence.repositories.audit import AuditRepository

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["AuditActor", "AuditService"]

_logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class AuditActor:
    """Who performed an audited action.

    ``ANONYMOUS``/``SYSTEM`` actors carry no identifier, which is why
    ``actor_id`` is optional rather than defaulted to a sentinel UUID.
    """

    actor_type: ActorType = ActorType.SYSTEM
    actor_id: UUID | None = None
    role: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None

    @classmethod
    def system(cls, *, role: str = "system") -> AuditActor:
        """An action taken by the platform itself (workers, startup, schedulers)."""
        return cls(actor_type=ActorType.SYSTEM, role=role)


class AuditService:
    """Writes append-only audit entries."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._repository = AuditRepository(session)

    async def record(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | UUID | int | None = None,
        actor: AuditActor | None = None,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
        reason: str | None = None,
        result: AuditResult = AuditResult.SUCCESS,
        request_id: str | None = None,
    ) -> AuditLog:
        """Create one audit entry. Flushes but does not commit (§63).

        ``action`` should be an upper-case stable verb, e.g.
        ``ADMIN_TRIGGERED_GLOBAL_KILL_SWITCH``. Actions are queried by exact
        match in the admin UI, so they must be consistent across call sites.

        ``resource_id`` accepts the identifier shapes callers actually hold —
        UUID primary keys, integer ids and composite string keys — and is
        stringified into a text column so the admin timeline can match it
        exactly (§45, §50).
        """
        if not action or not action.strip():
            msg = "audit action must be a non-empty stable verb"
            raise ValueError(msg)
        if not resource_type or not resource_type.strip():
            msg = "audit resource_type must be non-empty"
            raise ValueError(msg)

        resolved_actor = actor or AuditActor.system()
        entry = AuditLog(
            action=action.strip(),
            resource_type=resource_type.strip(),
            resource_id=str(resource_id) if resource_id is not None else None,
            actor_id=resolved_actor.actor_id,
            actor_type=resolved_actor.actor_type,
            actor_role=resolved_actor.role,
            # Redaction happens here, unconditionally. Callers cannot opt out.
            old_value_safe=_redact_payload(old_value),
            new_value_safe=_redact_payload(new_value),
            reason=redact_text(reason) if reason else None,
            ip_address=resolved_actor.ip_address,
            user_agent=_truncate(resolved_actor.user_agent, 512),
            result=result,
            request_id=request_id or current_request_id(),
        )
        self._repository.add(entry)
        await self._repository.flush()

        _logger.info(
            "audit entry recorded",
            extra={
                "audit_action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "actor_type": entry.actor_type.value,
                "audit_result": entry.result.value,
            },
        )
        return entry

    async def record_denied(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | UUID | int | None = None,
        actor: AuditActor | None = None,
        reason: str | None = None,
    ) -> AuditLog:
        """Record an action that authorization blocked (§52, §130)."""
        return await self.record(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor=actor,
            reason=reason,
            result=AuditResult.DENIED,
        )


def _redact_payload(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """Redact a value payload, returning ``None`` when there is nothing to store."""
    if payload is None:
        return None
    redacted = redact_object(payload)
    return redacted if isinstance(redacted, dict) else {"value": redacted}


def _truncate(value: str | None, limit: int) -> str | None:
    """Truncate to a column's declared width.

    A user agent longer than the column would raise a database error during an
    unrelated administrative action, turning a bookkeeping failure into a lost
    audit entry.
    """
    if value is None:
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"
