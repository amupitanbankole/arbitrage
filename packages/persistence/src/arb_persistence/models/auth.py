"""Authentication and session state (§10, §41, §59-§62).

Four tables: ``users``, ``user_sessions``, ``auth_tokens`` and
``mfa_recovery_codes``.

What is *not* stored here matters as much as what is:

* **No plaintext or reversible credentials.** ``users.password_hash`` is an
  argon2id digest; ``users.totp_secret_encrypted`` is AES-256-GCM ciphertext that
  only the exchange of a second factor ever decrypts; ``user_sessions`` and
  ``auth_tokens`` store SHA-256 digests of bearer credentials, so a database read
  yields nothing presentable (§12, §60, §83).
* **No roles or permissions table.** The role vocabulary and its grants live in
  :mod:`arb_core.security.rbac`, so a privilege change is a reviewed diff rather
  than a row nobody saw (§41). ``users.role`` stores one of those values.
* **No separate security-events table.** Every authentication outcome — success,
  failure, denial, MFA challenge, session revocation, token replay — is written to
  the existing append-only ``audit_logs``, which already records ``FAILURE`` and
  ``DENIED`` results with actor, IP, user agent and request id (§53, §62). A second
  log would be a second place for the two to disagree.

No ORM relationships are declared, on purpose. Under async SQLAlchemy a lazy
relationship load raises ``MissingGreenlet`` at the point of attribute access, far
from the query that should have fetched it; the failure looks like a bug in the
caller. Repositories therefore state their joins and ``selectinload`` options
explicitly, which also keeps the query plan reviewable in one place (§114).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from arb_core.clock import utc_now
from arb_core.db import (
    GUID,
    Base,
    SoftDeleteMixin,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)
from arb_core.identifiers import EMAIL_MAX_LENGTH
from arb_core.security.rbac import Role, default_role
from arb_persistence.models.enums import (
    AuthTokenPurpose,
    SessionStatus,
    UserStatus,
    enum_column,
)

__all__ = ["AuthToken", "MfaRecoveryCode", "User", "UserSession"]

#: argon2id output is ~96 characters and bcrypt's is 60. 255 leaves room for a
#: future scheme without a column migration — the whole point of dispatching
#: verification on the stored hash's prefix.
_PASSWORD_HASH_LENGTH: Final[int] = 255
#: SHA-256 hex digest length, used by every stored credential digest.
_DIGEST_LENGTH: Final[int] = 64
#: Display name, also used by the password policy's containment check (§59).
_DISPLAY_NAME_LENGTH: Final[int] = 100
_IP_LENGTH: Final[int] = 64
_USER_AGENT_LENGTH: Final[int] = 512
_REVOKE_REASON_LENGTH: Final[int] = 64


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """One account: credentials, role, status and lockout state (§41, §59).

    Soft-deleted rather than deleted. ``audit_logs.actor_id`` points at these rows
    and the audit log is append-only (§53), so removing a row would leave entries
    referring to nothing. Right-to-erasure requests are satisfied by
    *anonymisation* — rewriting the email to a tombstone and clearing the
    credentials — which is an explicit operation, not a side effect of a delete.
    Until then the address stays reserved, so a deleted account's address cannot be
    re-registered and start receiving another person's password resets.
    """

    __tablename__ = "users"
    __table_args__ = (
        # The canonical-form guarantee, enforced by the database rather than by
        # every code path remembering to call normalize_email(). Without it the
        # unique index can be defeated by casing, and "John@x.com" and "john@x.com"
        # become two accounts sharing one password-reset flow.
        CheckConstraint("email = lower(email)", name="email_is_normalized"),
        CheckConstraint("failed_login_count >= 0", name="failed_login_count_non_negative"),
        CheckConstraint("totp_last_used_step >= 0", name="totp_last_used_step_non_negative"),
        # Administrator queries filter by status and sort by recency (§45).
        Index("ix_users_status_created_at", "status", "created_at"),
    )

    #: Login identifier, always stored in the canonical form produced by
    #: :func:`arb_core.identifiers.normalize_email`. `unique=True` implies the index.
    email: Mapped[str] = mapped_column(String(EMAIL_MAX_LENGTH), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(_DISPLAY_NAME_LENGTH), nullable=True)

    #: argon2id (or bcrypt) digest. Never logged, never returned by an API, and
    #: excluded from :meth:`safe_snapshot` (§127, §133).
    password_hash: Mapped[str] = mapped_column(String(_PASSWORD_HASH_LENGTH), nullable=False)

    #: One of the seven platform roles. The vocabulary comes from
    #: :class:`arb_core.security.rbac.Role` so there is a single definition; the
    #: grants behind it are in code, not in a table (§41).
    role: Mapped[Role] = mapped_column(
        enum_column(Role, name="user_role"), nullable=False, default=default_role
    )
    status: Mapped[UserStatus] = mapped_column(
        enum_column(UserStatus, name="user_status"),
        nullable=False,
        default=UserStatus.PENDING_VERIFICATION,
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # --- Lockout state (§59) ------------------------------------------------
    #: Consecutive failures since the last success or since the last lock took
    #: effect. Authoritative here rather than in Redis: a cache flush must not
    #: reset an attacker's progress.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_failed_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # --- Second factor (§59) ------------------------------------------------
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: AES-256-GCM ciphertext from :class:`arb_core.security.crypto.SecretBox`,
    #: bound to the purpose ``totp_secret``. The plaintext secret is needed to
    #: verify a code, so unlike a password it cannot be a one-way digest — which is
    #: exactly why it is encrypted at rest rather than merely hashed.
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    #: The TOTP time step whose code was most recently accepted, so the same code
    #: cannot be presented twice.
    #:
    #: RFC 6238 §5.2 requires this: "The verifier MUST NOT accept the second attempt
    #: of the OTP after the successful validation." Without it the drift window that
    #: tolerates a slightly-skewed phone clock becomes a window in which a code read
    #: off somebody's shoulder — or out of a phishing page — can be replayed, three
    #: times over at the default drift of one step either side.
    #:
    #: Stored in the database rather than in Redis because it is a security control
    #: that must not fail open: if the cache is unreachable the check would silently
    #: disappear, and a control that vanishes when infrastructure is degraded is a
    #: control that vanishes exactly when an attacker is most likely to be trying it.
    totp_last_used_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # --- Credential lifecycle ----------------------------------------------
    #: Sessions created before this instant are not trustworthy: changing a password
    #: must end sessions an attacker may already hold (§59).
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    #: Set when an administrator resets a password on somebody's behalf, so the
    #: account is forced to choose its own before it can do anything else.
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # --- Derived state ------------------------------------------------------
    @property
    def is_active(self) -> bool:
        """Whether the account may sign in, ignoring the lockout.

        Lockout is reported separately because the two have different responses: a
        locked account gets ``423`` with a ``Retry-After`` and will recover on its
        own, while a disabled or suspended account gets ``403`` and will not.
        """
        return self.status is UserStatus.ACTIVE and not self.is_deleted

    @property
    def email_verified(self) -> bool:
        """Whether the address has been confirmed."""
        return self.email_verified_at is not None

    @property
    def mfa_confirmed(self) -> bool:
        """Whether a second factor is enrolled *and* was proven once.

        Enrollment is not complete until a code has been accepted: a mistyped
        shared secret would otherwise lock the account holder out of their own
        account at the worst possible moment (§59).
        """
        return self.mfa_enabled and self.totp_confirmed_at is not None

    def is_locked_at(self, moment: datetime) -> bool:
        """Whether the account is locked at ``moment``."""
        return self.locked_until is not None and self.locked_until > moment

    def lock_remaining(self, moment: datetime) -> timedelta | None:
        """How long the lock still has to run, for a ``Retry-After`` header."""
        if self.locked_until is None:
            return None
        remaining = self.locked_until - moment
        return remaining if remaining > timedelta(0) else None

    def record_failed_login(
        self, *, moment: datetime, max_attempts: int, lockout: timedelta
    ) -> bool:
        """Count a failure and lock the account at the threshold.

        Returns whether this failure caused a lock, so the caller can audit the
        transition rather than inferring it.

        Attempts made *while already locked* are not counted: the service refuses
        them with ``423`` before reaching the password check. Extending the lock on
        every hit would let an attacker keep a victim locked out forever by
        hammering the endpoint, which turns a brute-force defence into a denial of
        service against the account owner. Instead the lock runs its course, and
        the first failure after it expires re-locks — so a continuing attacker gets
        one guess per lockout period, and the owner gets their account back.
        """
        if max_attempts < 1:
            msg = "max_attempts must be at least 1"
            raise ValueError(msg)
        self.failed_login_count += 1
        self.last_failed_login_at = moment
        if self.failed_login_count >= max_attempts:
            self.locked_until = moment + lockout
            return True
        return False

    def clear_failed_logins(self) -> None:
        """Forget the failure counters once the password has been proved.

        Deliberately narrower than :meth:`record_successful_login`. An account with a
        second factor has proved one of two things at this point, and the counters
        track *password guessing* — which has stopped — while ``last_login_at`` must
        not claim a sign-in that has not finished yet. Stamping it here would show a
        successful login for every account whose MFA step was then abandoned, and
        "logins per hour" would quietly become "passwords guessed correctly per hour".
        """
        self.failed_login_count = 0
        self.locked_until = None

    def record_successful_login(self, *, moment: datetime) -> None:
        """Clear the failure counters after a verified sign-in (§61)."""
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login_at = moment

    def confirm_email(self, *, moment: datetime) -> None:
        """Mark the address verified and activate the account."""
        self.email_verified_at = moment
        if self.status is UserStatus.PENDING_VERIFICATION:
            self.status = UserStatus.ACTIVE

    def set_password_hash(self, password_hash: str, *, moment: datetime) -> None:
        """Install a new digest and stamp the change.

        The stamp is what lets the session repository revoke everything older than
        the change; without it, an attacker who obtained a session before the
        password was reset keeps it afterwards.
        """
        self.password_hash = password_hash
        self.password_changed_at = moment
        self.must_change_password = False
        # A password change is a credential event: the failure counters that led up
        # to it are about the old credential and must not carry over.
        self.failed_login_count = 0
        self.locked_until = None

    def enroll_totp(self, *, encrypted_secret: str) -> None:
        """Store the encrypted secret, pending confirmation by a valid code."""
        self.totp_secret_encrypted = encrypted_secret
        self.totp_confirmed_at = None
        self.mfa_enabled = False

    def confirm_totp(self, *, moment: datetime) -> None:
        """Complete enrollment once a code has been accepted (§59)."""
        if self.totp_secret_encrypted is None:
            msg = "no TOTP secret has been enrolled"
            raise ValueError(msg)
        self.totp_confirmed_at = moment
        self.mfa_enabled = True
        # Enrollment clears any step recorded against a previous secret, so the
        # first code entered on a freshly confirmed secret cannot be mistaken for a
        # replay of one accepted under the old secret.
        self.totp_last_used_step = None

    def totp_step_is_replay(self, step: int) -> bool:
        """Whether ``step`` has already been accepted for this account.

        RFC 6238 §5.2: "The verifier MUST NOT accept the second attempt of the OTP
        after the successful validation." Without this check, the drift window that
        tolerates a phone with a skewed clock is also a window in which a code seen
        once — over a shoulder, or typed into a phishing page — can be presented
        again, three times over at the default drift of one step either side.

        ``<=`` rather than ``==``: a step *older* than the newest accepted one must
        also be refused, or an attacker who recorded two codes could spend the older
        one after the newer one had been used.
        """
        return self.totp_last_used_step is not None and step <= self.totp_last_used_step

    def record_totp_step(self, step: int) -> None:
        """Remember the most recently accepted step so it cannot be reused."""
        self.totp_last_used_step = step

    def disable_mfa(self) -> None:
        """Remove the second factor entirely."""
        self.totp_secret_encrypted = None
        self.totp_confirmed_at = None
        self.totp_last_used_step = None
        self.mfa_enabled = False

    def safe_snapshot(self) -> dict[str, Any]:
        """Administrative view of the account (§45).

        Contains no credential material by construction: neither the password hash
        nor the encrypted TOTP secret appears, so this can be logged, serialised
        into an audit entry or returned to an administrator without a redaction pass
        (§53, §127).
        """
        return {
            "id": str(self.id),
            "email": self.email,
            "display_name": self.display_name,
            "role": self.role.value,
            "status": self.status.value,
            "email_verified": self.email_verified,
            "mfa_enabled": self.mfa_enabled,
            "mfa_confirmed": self.mfa_confirmed,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "failed_login_count": self.failed_login_count,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "must_change_password": self.must_change_password,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

    def __repr__(self) -> str:
        # The email is identity, not a secret, and support staff need it to tell
        # rows apart in a log. Neither credential field is included.
        return f"<User {self.email} role={self.role.value} status={self.status.value}>"


class UserSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One refresh-token session: a device that is signed in (§60).

    A session is the revocation unit. Access tokens are short-lived JWTs carrying
    this row's id as ``sid``, so ending a session ends every access token minted
    for it without a denylist — the check "is this session still active?" is one
    indexed lookup that has to happen anyway to load the caller's current role.

    Rotation and replay detection
    -----------------------------

    Refresh tokens rotate on every use. The consumed row moves to
    :attr:`SessionStatus.ROTATED` and a new row is created with the same
    ``family_id`` and ``parent_session_id`` pointing back at it.

    Keeping rotated rows is what makes replay detectable: presenting a ``ROTATED``
    token proves the presenter is not the client that already exchanged it, so the
    whole family is revoked. Without the retained row, a replayed token is merely
    "unknown" and looks identical to a typo, so the attacker keeps the session they
    stole and the legitimate user is silently signed out instead.

    Two independent expiries
    ------------------------

    ``expires_at`` is absolute — no session outlives it however actively it is used
    — and ``last_seen_at`` drives an idle timeout computed from configuration. Both
    are needed: idle expiry catches an abandoned browser on a shared machine, and
    the absolute cap bounds the damage from a stolen token that *is* being used.
    The idle window is deliberately not stored as a timestamp, so changing
    ``SESSION_IDLE_TIMEOUT_MINUTES`` applies to existing sessions immediately
    rather than only to new ones.
    """

    __tablename__ = "user_sessions"
    __table_args__ = (
        # "This user's signed-in devices" — the account-security page (§68).
        Index("ix_user_sessions_user_id_status", "user_id", "status"),
        # "Revoke every session descended from this login."
        Index("ix_user_sessions_family_id", "family_id"),
        # Retention sweeps and expiry marking are time-ordered.
        Index("ix_user_sessions_expires_at", "expires_at"),
        # Self-referential lineage. No FK constraint on it: a session's parent may
        # be purged by retention while the child is still active, and a dangling
        # reference must not break a sign-in.
        CheckConstraint(
            "parent_session_id IS NULL OR parent_session_id <> id",
            name="parent_session_is_not_self",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    #: Shared by every session descended from one sign-in.
    family_id: Mapped[uuid.UUID] = mapped_column(GUID, nullable=False)
    #: The session whose refresh token was exchanged to create this one.
    parent_session_id: Mapped[uuid.UUID | None] = mapped_column(GUID, nullable=True)

    #: SHA-256 digest of the opaque refresh token. The token itself is shown to the
    #: client exactly once and never stored (§60, §83).
    refresh_token_hash: Mapped[str] = mapped_column(
        String(_DIGEST_LENGTH), nullable=False, unique=True
    )

    status: Mapped[SessionStatus] = mapped_column(
        enum_column(SessionStatus, name="session_status"),
        nullable=False,
        default=SessionStatus.ACTIVE,
    )

    #: Absolute lifetime; never extended by activity.
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    #: Last successful use. Drives the idle timeout together with configuration.
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    #: Set when the second factor was satisfied. ``None`` for an account with no
    #: MFA enrolled, and for a session that has not completed it.
    mfa_completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    #: Machine-readable cause: ``SIGN_OUT``, ``PASSWORD_CHANGED``, ``TOKEN_REUSE``,
    #: ``ADMIN_REVOKE``, ``SESSIONS_REVOKED_ALL``, ``EXPIRED``. Recorded because
    #: "why did my session end?" is the first question a user asks and the first an
    #: investigator needs answered (§62).
    revoke_reason: Mapped[str | None] = mapped_column(String(_REVOKE_REASON_LENGTH), nullable=True)

    #: Presented to the user as their list of signed-in devices, so it must be
    #: something a person recognises rather than an opaque id (§68).
    ip_address: Mapped[str | None] = mapped_column(String(_IP_LENGTH), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(_USER_AGENT_LENGTH), nullable=True)

    @property
    def is_active(self) -> bool:
        """Whether the session can still be used, ignoring expiry."""
        return self.status is SessionStatus.ACTIVE

    @property
    def is_rotated(self) -> bool:
        """Whether this session's token was already exchanged.

        A presentation of such a token is replay evidence, not a stale client: the
        legitimate holder exchanged it and moved on.
        """
        return self.status is SessionStatus.ROTATED

    def idle_expires_at(self, idle_ttl: timedelta) -> datetime:
        """When this session expires from inactivity."""
        return self.last_seen_at + idle_ttl

    def is_expired_at(self, moment: datetime, *, idle_ttl: timedelta) -> bool:
        """Whether either lifetime has run out at ``moment``."""
        return moment >= self.expires_at or moment >= self.idle_expires_at(idle_ttl)

    def touch(self, *, moment: datetime) -> None:
        """Record activity, extending the idle window but never the absolute one."""
        self.last_seen_at = moment

    def mark_rotated(self, *, moment: datetime) -> None:
        """Record that this session's refresh token has been exchanged."""
        self.status = SessionStatus.ROTATED
        self.revoked_at = moment
        self.revoke_reason = "ROTATED"

    def revoke(self, *, moment: datetime, reason: str) -> None:
        """End the session. Idempotent: an already-ended session keeps its first
        reason, because that is the one an investigator needs."""
        if self.status in {SessionStatus.REVOKED, SessionStatus.EXPIRED}:
            return
        self.status = SessionStatus.REVOKED
        self.revoked_at = moment
        self.revoke_reason = reason

    def mark_expired(self, *, moment: datetime) -> None:
        """Record that a lifetime ran out, so cleanup is visible in the data."""
        if self.status in {SessionStatus.REVOKED, SessionStatus.EXPIRED}:
            return
        self.status = SessionStatus.EXPIRED
        self.revoked_at = moment
        self.revoke_reason = "EXPIRED"

    def safe_snapshot(self) -> dict[str, Any]:
        """View for the signed-in-devices list. Carries no token digest (§127)."""
        return {
            "id": str(self.id),
            "family_id": str(self.family_id),
            "status": self.status.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "mfa_completed_at": (
                self.mfa_completed_at.isoformat() if self.mfa_completed_at else None
            ),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoke_reason": self.revoke_reason,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "current": False,
        }

    def __repr__(self) -> str:
        # No digest: this repr can reach a log line, and a session credential must
        # not be quotable from one (§127).
        return f"<UserSession {self.id} user={self.user_id} status={self.status.value}>"


class AuthToken(Base, UUIDPrimaryKeyMixin):
    """A single-use emailed token: verification or password reset (§59, §60).

    Only the SHA-256 digest is stored, so the row is useless to somebody reading
    the database: unlike a password, this token has no dictionary to defend
    against — it is 256 bits of randomness — which is why a fast digest is correct
    here and would be wrong for a password (§60, §83).

    There is no ``updated_at``: the only change a token ever undergoes is being
    consumed, and recording when that happened is ``consumed_at``.
    """

    __tablename__ = "auth_tokens"
    __table_args__ = (
        # "Invalidate this user's outstanding reset tokens before issuing a new
        # one." Enforced in the repository rather than by a unique constraint,
        # because "one unconsumed token per user and purpose" needs a partial
        # index, which PostgreSQL supports and SQLite does not — and the two must
        # run the same schema (§9, §141).
        Index("ix_auth_tokens_user_id_purpose", "user_id", "purpose"),
        Index("ix_auth_tokens_expires_at", "expires_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[AuthTokenPurpose] = mapped_column(
        enum_column(AuthTokenPurpose, name="auth_token_purpose"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(_DIGEST_LENGTH), nullable=False, unique=True)

    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    #: When the token was requested. Not ``TimestampMixin``: this row is written
    #: once and then consumed, so an ``updated_at`` would only ever duplicate
    #: ``consumed_at`` and invite a reader to trust the wrong one. The request time
    #: is kept because it is half of the takeover signal below.
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utc_now, index=True
    )

    #: Where the request came from. A reset requested from one country and consumed
    #: from another is the single most useful signal in a takeover investigation
    #: (§62).
    requested_ip: Mapped[str | None] = mapped_column(String(_IP_LENGTH), nullable=True)
    consumed_ip: Mapped[str | None] = mapped_column(String(_IP_LENGTH), nullable=True)

    @property
    def is_consumed(self) -> bool:
        """Whether the token has already been used."""
        return self.consumed_at is not None

    def is_usable_at(self, moment: datetime) -> bool:
        """Whether the token can still be redeemed.

        Both conditions are checked together because a caller that forgets one
        produces a working exploit: an unconsumed-but-expired token must not reset
        a password, and a consumed token must not reset it twice.
        """
        return not self.is_consumed and moment < self.expires_at

    def consume(self, *, moment: datetime, ip_address: str | None = None) -> None:
        """Mark the token used. Idempotent, so a double submission cannot race into
        two password changes."""
        if self.consumed_at is None:
            self.consumed_at = moment
            self.consumed_ip = ip_address

    def safe_snapshot(self) -> dict[str, Any]:
        """Administrative view. Carries no digest (§127)."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "purpose": self.purpose.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "consumed": self.is_consumed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AuthToken {self.purpose.value} user={self.user_id} consumed={self.is_consumed}>"


class MfaRecoveryCode(Base, UUIDPrimaryKeyMixin):
    """One hashed recovery code (§59).

    Recovery codes are the fallback when an authenticator device is lost, which
    makes them bearer credentials equivalent to a password — so they are stored as
    digests, never in plaintext, and are single-use.

    Ten are issued and the plaintext set is shown exactly once. Consuming one is
    recorded rather than the row being deleted, so the account holder can see how
    many remain and an investigator can see when each was used.
    """

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (
        # A code must not be usable twice, and must not collide within an account.
        UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_codes_user_code"),
        Index("ix_mfa_recovery_codes_user_id", "user_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    #: SHA-256 of the normalised code. Recovery codes are 10 characters of
    #: unambiguous alphabet — enough entropy to resist guessing when combined with
    #: the MFA rate limit, and a fast digest is right for a high-entropy secret.
    code_hash: Mapped[str] = mapped_column(String(_DIGEST_LENGTH), nullable=False)

    #: When the set was issued, so "how long has this account been running on
    #: recovery codes?" is answerable without reading a log.
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utc_now, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    consumed_ip: Mapped[str | None] = mapped_column(String(_IP_LENGTH), nullable=True)

    @property
    def is_consumed(self) -> bool:
        """Whether this code has been used."""
        return self.consumed_at is not None

    def consume(self, *, moment: datetime, ip_address: str | None = None) -> bool:
        """Use the code. Returns ``False`` if it was already consumed, so a caller
        cannot treat a replay as a success."""
        if self.consumed_at is not None:
            return False
        self.consumed_at = moment
        self.consumed_ip = ip_address
        return True

    def __repr__(self) -> str:
        # Never the digest: it is the credential (§127).
        return f"<MfaRecoveryCode user={self.user_id} consumed={self.is_consumed}>"
