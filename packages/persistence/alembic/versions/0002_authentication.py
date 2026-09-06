"""authentication: users, sessions, one-time tokens, recovery codes

Phase 2 (§10, §41, §59-§62, §141).

Scope
-----
Four tables, and only four. Everything an authentication decision needs to read:
who the account is, what proves it, which devices are signed in, and which
single-use tokens are outstanding.

Deliberately **not** in this migration:

* **No ``roles`` or ``permissions`` table.** The role vocabulary and its grants
  live in ``arb_core.security.rbac``, so a privilege change is a reviewed diff with
  an author rather than a row nobody saw (§41). ``users.role`` stores one of those
  seven values.
* **No security-events table.** Every authentication outcome — success, failure,
  denial, MFA challenge, revocation, token replay — is written to the existing
  append-only ``audit_logs``, which already carries ``FAILURE`` and ``DENIED``
  results together with actor, IP, user agent and request id (§53, §62). A second
  log is a second place for the two accounts of an incident to disagree.
* **No subscription or plan columns.** Those arrive with the SaaS tables (§57);
  adding them now would mean guessing the shape of a phase that has not been
  designed.

Credentials at rest
-------------------
Nothing reversible and nothing plaintext is stored. ``users.password_hash`` is an
argon2id digest; ``users.totp_secret_encrypted`` is AES-256-GCM ciphertext (a TOTP
secret must be readable to verify a code, which is why it is encrypted rather than
hashed); ``user_sessions.refresh_token_hash``, ``auth_tokens.token_hash`` and
``mfa_recovery_codes.code_hash`` are SHA-256 digests of high-entropy values, so a
database read yields nothing that can be presented (§12, §60, §83).

Email canonicalisation
----------------------
``ck_users_email_is_normalized`` enforces ``email = lower(email)`` in the database.
The application normalises on every write, but a constraint means the unique index
cannot be defeated by casing even from a script, a backfill or a future code path
that forgets. Without it, ``John@x.com`` and ``john@x.com`` become two accounts
sharing one password-reset flow.

Session rotation
----------------
``session_status`` includes ``ROTATED``, which is why refresh tokens can be rotated
*and* replayed-tokens detected. A consumed token is not the same thing as a revoked
one: presenting a rotated token proves the presenter is not the client that already
exchanged it, and the response is to revoke the whole family (§60). That is only
possible if consumed rows are kept and distinguishable.

Portability
-----------
As in ``0001``: every type is dialect-portable, enum members are inlined as a frozen
copy rather than imported from the application, and the identical migration applies
to production PostgreSQL and to the SQLite database the hermetic test-suite runs
against (§142). Importing a live enum class would silently rewrite the DDL of an
already-applied migration whenever a member is added.

Reversible
----------
``downgrade()`` drops the dependent tables first and ``users`` last, so the
foreign keys are never violated on the way out. ``upgrade → downgrade → upgrade`` is
verified in CI (§141).

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-05

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# ---------------------------------------------------------------------------
# Portable type factories, as in 0001. A fresh instance per column: SQLAlchemy
# type objects carry per-column state once bound, so sharing one instance is unsafe.
# ---------------------------------------------------------------------------
def _uuid() -> sa.Uuid:
    return sa.Uuid()


def _utc() -> sa.DateTime:
    return sa.DateTime(timezone=True)


def _enum(*values: str, name: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, validate_strings=True, length=64)


# ---------------------------------------------------------------------------
# Frozen copies of the vocabularies as they stood when this migration was written.
# arb_core.security.rbac.Role and arb_persistence.models.enums are the live
# definitions; these literals are what the applied schema must keep saying.
# ---------------------------------------------------------------------------
_USER_ROLES: tuple[str, ...] = (
    "OWNER",
    "ADMIN",
    "COMPLIANCE_OFFICER",
    "SUPPORT_AGENT",
    "RISK_MANAGER",
    "TRADER",
    "VIEWER",
)
_USER_STATUSES: tuple[str, ...] = (
    "PENDING_VERIFICATION",
    "ACTIVE",
    "DISABLED",
    "SUSPENDED",
)
_SESSION_STATUSES: tuple[str, ...] = ("ACTIVE", "ROTATED", "REVOKED", "EXPIRED")
_TOKEN_PURPOSES: tuple[str, ...] = ("EMAIL_VERIFICATION", "PASSWORD_RESET", "EMAIL_CHANGE")

# Widths, mirroring the constants in arb_persistence.models.auth.
_EMAIL_LENGTH = 254
_PASSWORD_HASH_LENGTH = 255
_DIGEST_LENGTH = 64
_DISPLAY_NAME_LENGTH = 100
_IP_LENGTH = 64
_USER_AGENT_LENGTH = 512
_REVOKE_REASON_LENGTH = 64


def upgrade() -> None:
    # --- users (§41, §59) ---------------------------------------------------
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=_EMAIL_LENGTH), nullable=False),
        sa.Column("display_name", sa.String(length=_DISPLAY_NAME_LENGTH), nullable=True),
        sa.Column("password_hash", sa.String(length=_PASSWORD_HASH_LENGTH), nullable=False),
        sa.Column("role", _enum(*_USER_ROLES, name="user_role"), nullable=False),
        sa.Column("status", _enum(*_USER_STATUSES, name="user_status"), nullable=False),
        sa.Column("email_verified_at", _utc(), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", _utc(), nullable=True),
        sa.Column("last_login_at", _utc(), nullable=True),
        sa.Column("last_failed_login_at", _utc(), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("totp_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("totp_confirmed_at", _utc(), nullable=True),
        sa.Column("password_changed_at", _utc(), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("created_at", _utc(), nullable=False),
        sa.Column("updated_at", _utc(), nullable=False),
        sa.Column("deleted_at", _utc(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.CheckConstraint("email = lower(email)", name="ck_users_email_is_normalized"),
        sa.CheckConstraint(
            "failed_login_count >= 0", name="ck_users_failed_login_count_non_negative"
        ),
    )
    op.create_index("ix_users_created_at", "users", ["created_at"], unique=False)
    op.create_index("ix_users_updated_at", "users", ["updated_at"], unique=False)
    op.create_index("ix_users_deleted_at", "users", ["deleted_at"], unique=False)
    op.create_index("ix_users_status_created_at", "users", ["status", "created_at"], unique=False)

    # --- user_sessions (§60) ------------------------------------------------
    op.create_table(
        "user_sessions",
        sa.Column("user_id", _uuid(), nullable=False),
        sa.Column("family_id", _uuid(), nullable=False),
        sa.Column("parent_session_id", _uuid(), nullable=True),
        sa.Column("refresh_token_hash", sa.String(length=_DIGEST_LENGTH), nullable=False),
        sa.Column("status", _enum(*_SESSION_STATUSES, name="session_status"), nullable=False),
        sa.Column("expires_at", _utc(), nullable=False),
        sa.Column("last_seen_at", _utc(), nullable=False),
        sa.Column("mfa_completed_at", _utc(), nullable=True),
        sa.Column("revoked_at", _utc(), nullable=True),
        sa.Column("revoke_reason", sa.String(length=_REVOKE_REASON_LENGTH), nullable=True),
        sa.Column("ip_address", sa.String(length=_IP_LENGTH), nullable=True),
        sa.Column("user_agent", sa.String(length=_USER_AGENT_LENGTH), nullable=True),
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("created_at", _utc(), nullable=False),
        sa.Column("updated_at", _utc(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_user_sessions"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_sessions_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("refresh_token_hash", name="uq_user_sessions_refresh_token_hash"),
        sa.CheckConstraint(
            "parent_session_id IS NULL OR parent_session_id <> id",
            name="ck_user_sessions_parent_session_is_not_self",
        ),
    )
    op.create_index("ix_user_sessions_created_at", "user_sessions", ["created_at"], unique=False)
    op.create_index("ix_user_sessions_updated_at", "user_sessions", ["updated_at"], unique=False)
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"], unique=False)
    op.create_index("ix_user_sessions_family_id", "user_sessions", ["family_id"], unique=False)
    op.create_index(
        "ix_user_sessions_user_id_status",
        "user_sessions",
        ["user_id", "status"],
        unique=False,
    )

    # --- auth_tokens (§59, §60) ---------------------------------------------
    op.create_table(
        "auth_tokens",
        sa.Column("user_id", _uuid(), nullable=False),
        sa.Column("purpose", _enum(*_TOKEN_PURPOSES, name="auth_token_purpose"), nullable=False),
        sa.Column("token_hash", sa.String(length=_DIGEST_LENGTH), nullable=False),
        sa.Column("expires_at", _utc(), nullable=False),
        sa.Column("consumed_at", _utc(), nullable=True),
        sa.Column("created_at", _utc(), nullable=False),
        sa.Column("requested_ip", sa.String(length=_IP_LENGTH), nullable=True),
        sa.Column("consumed_ip", sa.String(length=_IP_LENGTH), nullable=True),
        sa.Column("id", _uuid(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_auth_tokens"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_auth_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_hash", name="uq_auth_tokens_token_hash"),
    )
    op.create_index("ix_auth_tokens_created_at", "auth_tokens", ["created_at"], unique=False)
    op.create_index("ix_auth_tokens_expires_at", "auth_tokens", ["expires_at"], unique=False)
    op.create_index(
        "ix_auth_tokens_user_id_purpose",
        "auth_tokens",
        ["user_id", "purpose"],
        unique=False,
    )

    # --- mfa_recovery_codes (§59) -------------------------------------------
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("user_id", _uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=_DIGEST_LENGTH), nullable=False),
        sa.Column("created_at", _utc(), nullable=False),
        sa.Column("consumed_at", _utc(), nullable=True),
        sa.Column("consumed_ip", sa.String(length=_IP_LENGTH), nullable=True),
        sa.Column("id", _uuid(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_mfa_recovery_codes"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_mfa_recovery_codes_user_id_users",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_codes_user_code"),
    )
    op.create_index(
        "ix_mfa_recovery_codes_created_at",
        "mfa_recovery_codes",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"], unique=False
    )


def downgrade() -> None:
    # Dependents first: dropping ``users`` while a foreign key still points at it
    # fails on PostgreSQL even with ON DELETE CASCADE, because CASCADE governs row
    # deletes and not the removal of the referenced table itself.
    op.drop_index("ix_mfa_recovery_codes_user_id", table_name="mfa_recovery_codes")
    op.drop_index("ix_mfa_recovery_codes_created_at", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")

    op.drop_index("ix_auth_tokens_user_id_purpose", table_name="auth_tokens")
    op.drop_index("ix_auth_tokens_expires_at", table_name="auth_tokens")
    op.drop_index("ix_auth_tokens_created_at", table_name="auth_tokens")
    op.drop_table("auth_tokens")

    op.drop_index("ix_user_sessions_user_id_status", table_name="user_sessions")
    op.drop_index("ix_user_sessions_family_id", table_name="user_sessions")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_updated_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_created_at", table_name="user_sessions")
    op.drop_table("user_sessions")

    op.drop_index("ix_users_status_created_at", table_name="users")
    op.drop_index("ix_users_deleted_at", table_name="users")
    op.drop_index("ix_users_updated_at", table_name="users")
    op.drop_index("ix_users_created_at", table_name="users")
    op.drop_table("users")
