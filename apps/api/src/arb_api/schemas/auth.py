"""Authentication request and response contracts (§59, §67, §68, §71).

Three rules shape every schema here.

**Nothing submitted is echoed back.** No response contains a password, a recovery
code that was spent, or a token that was presented. The one exception is a credential
at the moment of issue, which cannot be recovered later — and those responses say so
in the description that a client renders next to them.

**Unknown fields are rejected, not ignored.** ``extra="forbid"`` matters more on an
authentication endpoint than anywhere else in the API: a request that silently accepts
extra fields is one where a client can send ``role`` or ``is_admin`` and hope. Refusing
the request removes the hope and tells an integrator their payload is wrong, which is
kinder than accepting it and doing nothing.

**The wire format matches the OpenAPI document.** These models are the contract
``/docs`` publishes, so a client coded against the documentation does not meet an
undocumented envelope at runtime (§67).
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

__all__ = [
    "ChangePasswordRequest",
    "LoginRequest",
    "LoginResponse",
    "MfaConfirmRequest",
    "MfaDisableRequest",
    "MfaEnrollmentResponse",
    "MfaLoginRequest",
    "MfaStatusResponse",
    "PasswordChangeResponse",
    "PasswordResetConfirmRequest",
    "PasswordResetRequest",
    "PasswordResetResponse",
    "RefreshRequest",
    "RegisterRequest",
    "RegisterResponse",
    "ResendVerificationRequest",
    "SessionListResponse",
    "SessionSummary",
    "TokenSet",
    "UserSummary",
    "VerifyEmailRequest",
]

#: Coarse gate only. The real policy — length, composition, and whether the
#: candidate contains the account's own email address — is
#: :class:`arb_core.security.passwords.PasswordPolicy`, enforced server-side on every
#: write. A schema cannot express it without duplicating configuration, and a
#: duplicated policy is one that drifts.
_PASSWORD_MIN_LENGTH: Final[int] = 8
_PASSWORD_MAX_LENGTH: Final[int] = 128

#: Wide enough for a TOTP code and for a recovery code, and no wider. The upper bound
#: is what stops a client posting an entire password into the code field and having it
#: hashed and compared.
_CODE_MIN_LENGTH: Final[int] = 6
_CODE_MAX_LENGTH: Final[int] = 32

#: Opaque tokens are 43+ characters; a challenge JWT is longer. This only rejects the
#: obviously-empty case before a database lookup that cannot succeed.
_TOKEN_MIN_LENGTH: Final[int] = 20

_DISPLAY_NAME_MAX_LENGTH: Final[int] = 100
#: ``User-Agent`` is truncated to the column width, so an enormous header cannot be
#: used to inflate the session table.
_USER_AGENT_MAX_LENGTH: Final[int] = 512


class AuthSchema(BaseModel):
    """Base for every authentication contract: immutable and closed to extra fields."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class RegisterRequest(AuthSchema):
    """Self-service sign-up."""

    email: EmailStr = Field(
        max_length=254,
        description="Login identifier. Stored in canonical lower-case form.",
        examples=["trader@example.com"],
    )
    password: str = Field(
        min_length=_PASSWORD_MIN_LENGTH,
        max_length=_PASSWORD_MAX_LENGTH,
        description=(
            "Checked against the server-side password policy, which also rejects a "
            "password containing your own email address or display name. Never "
            "echoed back in any response or error."
        ),
    )
    display_name: str | None = Field(
        default=None,
        max_length=_DISPLAY_NAME_MAX_LENGTH,
        description="Optional name shown in the interface instead of the address.",
    )


class LoginRequest(AuthSchema):
    """Password sign-in."""

    email: EmailStr = Field(max_length=254)
    password: str = Field(
        min_length=1,
        max_length=_PASSWORD_MAX_LENGTH,
        description=(
            "No minimum length here on purpose: enforcing the policy minimum on "
            "*input* would tell a caller that a six-character password belongs to an "
            "account created before the policy changed. The policy applies when a "
            "password is set, not when one is presented."
        ),
    )


class MfaLoginRequest(AuthSchema):
    """The second step of a sign-in whose password was already correct."""

    challenge: str = Field(
        min_length=_TOKEN_MIN_LENGTH,
        description="The `mfa_challenge` returned with the 401 from `/auth/login`.",
    )
    code: str = Field(
        min_length=_CODE_MIN_LENGTH,
        max_length=_CODE_MAX_LENGTH,
        description=(
            "A code from the authenticator app, or one of the single-use recovery "
            "codes. Recovery codes may be entered with or without separators."
        ),
    )


class RefreshRequest(AuthSchema):
    """Exchange a refresh token for a new credential set.

    The token may instead arrive in the ``arb_refresh`` cookie, which is the normal
    path for a browser client. A cookie-authenticated call must also carry the CSRF
    header; see :mod:`arb_api.api.dependencies`.
    """

    refresh_token: str | None = Field(
        default=None,
        min_length=_TOKEN_MIN_LENGTH,
        description="Omit when the refresh token is being sent as a cookie.",
    )


class ChangePasswordRequest(AuthSchema):
    """Replace the password from an authenticated session."""

    current_password: str = Field(
        min_length=1,
        max_length=_PASSWORD_MAX_LENGTH,
        description="Required even though the caller is authenticated.",
    )
    new_password: str = Field(min_length=_PASSWORD_MIN_LENGTH, max_length=_PASSWORD_MAX_LENGTH)


class PasswordResetRequest(AuthSchema):
    """Ask for a reset link."""

    email: EmailStr = Field(
        max_length=254,
        description=(
            "The response is the same whether or not an account exists for this "
            "address, so this endpoint cannot be used to enumerate accounts."
        ),
    )


class PasswordResetConfirmRequest(AuthSchema):
    """Redeem a reset token."""

    token: str = Field(min_length=_TOKEN_MIN_LENGTH)
    new_password: str = Field(min_length=_PASSWORD_MIN_LENGTH, max_length=_PASSWORD_MAX_LENGTH)


class VerifyEmailRequest(AuthSchema):
    """Redeem an email-verification token."""

    token: str = Field(min_length=_TOKEN_MIN_LENGTH)


class ResendVerificationRequest(AuthSchema):
    """Ask for the confirmation email again.

    Unauthenticated by necessity — an account whose address is unconfirmed cannot sign
    in — and enumeration-safe in the same way as the password-reset request: the
    response does not depend on whether the address exists.
    """

    email: EmailStr = Field(max_length=254)


class MfaConfirmRequest(AuthSchema):
    """Prove possession of the authenticator that scanned the enrollment QR code."""

    code: str = Field(min_length=_CODE_MIN_LENGTH, max_length=_CODE_MAX_LENGTH)


class MfaDisableRequest(AuthSchema):
    """Remove the second factor."""

    password: str = Field(
        min_length=1,
        max_length=_PASSWORD_MAX_LENGTH,
        description=(
            "Required: removing MFA with only a session cookie would let anybody at "
            "an unlocked machine take the second factor off the account permanently."
        ),
    )


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
class UserSummary(AuthSchema):
    """An account as the API is willing to describe it.

    Contains no credential material of any kind — no password hash, no encrypted
    TOTP secret, no recovery-code digest — so it can be returned to a client,
    written into a log line or embedded in another response without a redaction
    pass (§127).
    """

    id: UUID
    email: EmailStr = Field(max_length=254)
    display_name: str | None = Field(default=None, max_length=_DISPLAY_NAME_MAX_LENGTH)
    role: str = Field(description="One of the seven platform roles (§41).")
    status: str = Field(description="PENDING_VERIFICATION, ACTIVE, DISABLED or SUSPENDED.")
    email_verified: bool
    mfa_enabled: bool = Field(
        description="True only once a code from the enrolled secret has been accepted."
    )
    must_change_password: bool = Field(
        description=(
            "True when an administrator reset this password on the account holder's "
            "behalf. The client should route straight to the change-password form."
        )
    )
    created_at: datetime
    last_login_at: datetime | None = None


class TokenSet(AuthSchema):
    """A complete credential set for one session."""

    access_token: str = Field(
        description="Send as `Authorization: Bearer <token>`. Short-lived by design."
    )
    refresh_token: str = Field(
        description=(
            "Shown once. Only its SHA-256 digest is stored, so it cannot be "
            "recovered later — store it now or sign in again."
        )
    )
    csrf_token: str = Field(
        description=(
            "Echo in the `X-CSRF-Token` header on cookie-authenticated requests. "
            "Also delivered as a readable cookie, which is what makes the "
            "double-submit check possible."
        )
    )
    token_type: str = Field(default="Bearer")
    expires_in: int = Field(
        description="Whole seconds until the access token expires; refresh before then."
    )
    session_id: UUID = Field(description="Identifies this session in `/auth/sessions`.")


class LoginResponse(AuthSchema):
    """A completed sign-in.

    A sign-in that still owes a second factor is **not** this response: it is a 401
    carrying `MFA_REQUIRED` with the challenge in `error.details`. Reporting a
    half-finished login as a success is how MFA gets bypassed by a client that only
    checks the status code (§59).
    """

    user: UserSummary
    tokens: TokenSet


class RegisterResponse(AuthSchema):
    """An account that was created."""

    user: UserSummary
    requires_email_verification: bool = Field(
        description=(
            "When true the account cannot sign in until the address is confirmed. "
            "The confirmation token is sent to the mailbox and never appears here."
        )
    )
    message: str
    dev_verification_token: str | None = Field(
        default=None,
        description=(
            "**Local development only, and email delivery is NOT IMPLEMENTED.** "
            "Present only when `EMAIL_PROVIDER=none` on an environment that is "
            "neither staging nor production, so a developer can confirm the address "
            "without a mail server. Always null in a deployed environment: an "
            "endpoint that hands a verification token to whoever asked for one has "
            "verified nothing, which is the entire point of the flow."
        ),
    )


class PasswordChangeResponse(AuthSchema):
    """A password was changed, and this device was signed in again.

    Every session — including the one that made the request — is revoked, because the
    session that changed a password was created before the change and is therefore
    indistinguishable from an attacker's. A replacement credential set is issued in the
    same transaction, so the client swaps tokens and carries on; a client that ignores
    ``tokens`` will find itself signed out on the next call, which is the safe failure.
    """

    message: str
    sessions_revoked: int = Field(description="How many sessions the change ended.")
    tokens: TokenSet


class PasswordResetResponse(AuthSchema):
    """A reset was requested.

    The payload is identical whether or not an account exists for the address, so
    this endpoint is not an enumeration oracle (§71). The only field that varies is
    the development token below, which is null in every deployed environment.
    """

    message: str
    dev_reset_token: str | None = Field(
        default=None,
        description=(
            "**Local development only, and email delivery is NOT IMPLEMENTED.** "
            "Present only when `EMAIL_PROVIDER=none` on an environment that is "
            "neither staging nor production. Null otherwise, always."
        ),
    )


class SessionSummary(AuthSchema):
    """One signed-in device, as shown on the account-security page (§68).

    The user agent and address are included because recognising a session is the
    entire point of the list; no credential is.
    """

    id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=_USER_AGENT_MAX_LENGTH)
    mfa_completed_at: datetime | None = Field(
        default=None,
        description="When the second factor was passed. Null means password only.",
    )
    current: bool = Field(description="True for the session making this request.")


class SessionListResponse(AuthSchema):
    """Every session currently valid for the caller."""

    sessions: list[SessionSummary]
    count: int


class MfaEnrollmentResponse(AuthSchema):
    """Everything needed to finish enrolling, shown exactly once.

    The secret and the recovery codes are not retrievable afterwards: the secret is
    stored encrypted for verification only, and each recovery code is stored as a
    digest. A client that loses this response must start enrollment again.
    """

    secret: str = Field(description="Base32 shared secret for manual entry.")
    provisioning_uri: str = Field(description="`otpauth://` URI to render as a QR code.")
    recovery_codes: tuple[str, ...] = Field(
        description=(
            "Single-use fallback codes. Store them somewhere offline; each one works "
            "once and the platform can only tell you how many are left."
        )
    )
    message: str


class MfaStatusResponse(AuthSchema):
    """The state of the second factor, without any of its material."""

    enabled: bool
    confirmed_at: datetime | None = None
    recovery_codes_remaining: int = Field(
        description="How many unused recovery codes are left. Never which ones."
    )
