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
    "AuthTokenPurpose",
    "SessionStatus",
    "UserStatus",
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


class UserStatus(StrEnum):
    """Lifecycle state of an account (§41, §59).

    A status rather than a handful of booleans, because the states are mutually
    exclusive and a boolean set can express nonsense (``disabled`` and ``active``
    at once) that every reader would then have to defend against.

    ``DISABLED`` and ``SUSPENDED`` are kept apart deliberately: a suspension is
    temporary and expected to end (abuse review, a chargeback), while a disabled
    account has been closed and needs an explicit act to reopen. Support staff read
    that difference off the status without opening a ticket history.
    """

    #: Registered, email not yet confirmed. Cannot sign in (§59).
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    #: Normal state.
    ACTIVE = "ACTIVE"
    #: Closed by an administrator or by the account holder. Reopening is explicit.
    DISABLED = "DISABLED"
    #: Temporarily blocked, normally pending review. Expected to end.
    SUSPENDED = "SUSPENDED"


class SessionStatus(StrEnum):
    """Lifecycle state of a refresh-token session (§60).

    ``ROTATED`` is the reason this is an enum and not a ``revoked_at`` timestamp.
    Refresh tokens rotate on use: the old one is consumed and a new one issued. A
    consumed token is not the same thing as a revoked one — if a *rotated* token is
    presented again, that is proof somebody is replaying a credential the legitimate
    client already exchanged, and the correct response is to revoke the whole token
    family. That detection is impossible unless consumed tokens are remembered and
    distinguishable from ones an administrator or the user ended on purpose.
    """

    #: Usable: presents a valid refresh token.
    ACTIVE = "ACTIVE"
    #: Consumed by rotation. Retained so replay can be detected.
    ROTATED = "ROTATED"
    #: Ended on purpose — sign-out, "sign out everywhere", password change, or an
    #: administrator. Terminal.
    REVOKED = "REVOKED"
    #: Past its absolute or idle lifetime. Terminal.
    EXPIRED = "EXPIRED"


class AuthTokenPurpose(StrEnum):
    """What a single-use emailed token is for (§59, §60).

    One table with a purpose column rather than a table per flow: the columns are
    identical (a digest, an expiry, a consumed marker), and a single table means one
    place that enforces "hash it, expire it, consume it once".

    A token issued for one purpose is never accepted for another — the purpose is
    checked on use, so a password-reset link cannot be used to verify an email
    address.
    """

    #: Confirm ownership of the address at registration.
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    #: Sign in and set a new password without the current one.
    # S105 fires because the member name contains "password" and its value is a
    # literal equal to the name. This is a purpose *label* stored in a VARCHAR
    # column, not a credential; suppressed on this line alone.
    PASSWORD_RESET = "PASSWORD_RESET"  # noqa: S105
    #: Confirm ownership of a *new* address before an account's email changes.
    #:
    #: Declared now, wired when profile management lands: adding a value means
    #: altering a ``CHECK`` constraint, and doing that in the same migration as the
    #: feature is more risk than carrying one unused value. Nothing accepts it yet.
    EMAIL_CHANGE = "EMAIL_CHANGE"


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
