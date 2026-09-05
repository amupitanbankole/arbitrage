"""Status vocabularies and the portable enum column helper (§9).

Enums are stored as ``VARCHAR`` with a ``CHECK`` constraint rather than as native
PostgreSQL enum types. Native enums are marginally more compact, but:

* adding a value requires ``ALTER TYPE ... ADD VALUE``, which cannot run inside a
  transaction block on PostgreSQL < 12 and cannot be reverted, so an Alembic
  ``downgrade()`` has no way to undo it (§141 requires reversible migrations);
* SQLite has no enum type at all, so the test-suite would exercise a different
  physical schema than production.

``VARCHAR`` + ``CHECK`` migrates cleanly in both directions, validates on write,
and behaves identically on every dialect. The rationale is documented in
``packages/persistence/README.md``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final

from sqlalchemy import Enum as SqlEnum

__all__ = [
    "ActorType",
    "AuditResult",
    "WorkerStatus",
    "enum_column",
]

_ENUM_COLUMN_LENGTH: Final[int] = 64


class ActorType(StrEnum):
    """Who performed an audited action (§53)."""

    USER = "USER"
    ADMIN = "ADMIN"
    SYSTEM = "SYSTEM"
    WORKER = "WORKER"
    ANONYMOUS = "ANONYMOUS"


class AuditResult(StrEnum):
    """Outcome of an audited action (§53).

    ``DENIED`` is recorded for attempts that authorization blocked. Recording
    denials — not just successes — is what makes privilege-escalation probing
    visible in the security centre (§52, §130).
    """

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class WorkerStatus(StrEnum):
    """Lifecycle state of a worker process (§55)."""

    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


def enum_column(enum_cls: type[StrEnum], *, name: str, length: int = _ENUM_COLUMN_LENGTH) -> Any:
    """Build a portable, validated enum column type.

    ``values_callable`` stores the enum *values* rather than member names, so the
    text in the database is exactly what the API and logs emit. Without it, a
    future member whose name and value differ would silently change what is
    persisted.
    """
    return SqlEnum(
        enum_cls,
        name=name,
        native_enum=False,
        validate_strings=True,
        length=length,
        values_callable=lambda cls: [member.value for member in cls],
    )
