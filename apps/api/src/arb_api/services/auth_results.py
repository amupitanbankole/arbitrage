"""Result types returned by the authentication services (§115).

Services return these rather than response schemas, and routers map them onto the
API contract. Keeping the two apart means a change to what an endpoint *says* does
not require a change to what the service *does*, and no service has to know whether
its caller is HTTP, a worker or a test.

The plaintext credentials in :class:`IssuedTokens` and :class:`MfaEnrollment` exist
for exactly one reason: this is the only moment they are available. A refresh token
and a recovery-code set are shown once and never stored in a recoverable form, so
the object that carries them is deliberately short-lived and never logged. Every
``__repr__`` here is written to omit them, because a dataclass repr is the easiest
accidental leak in Python — one ``logger.debug("%s", result)`` in a handler that
formats arguments lazily is enough (§127, §133).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from arb_core.security.tokens import TokenClaims
    from arb_persistence.models.auth import User, UserSession

__all__ = [
    "AuthenticatedRequest",
    "IssuedTokens",
    "LoginOutcome",
    "LoginResult",
    "MfaEnrollment",
    "PasswordChangeResult",
    "RegistrationResult",
]

#: The HTTP authentication scheme, per RFC 6750. A literal rather than a module
#: constant whose name contains "token", which secret-scanning lint reads as a
#: hard-coded credential.
_SCHEME_BEARER = "Bearer"


class LoginOutcome(StrEnum):
    """How far a login got.

    ``MFA_REQUIRED`` is not a failure and not a success: the password was correct
    and the caller still has no session. It is reported as a 401 with a challenge
    token, because a client that treated it as a login would proceed with no
    authority — and a client that treated it as a wrong password would tell the
    user to retype a password that was right (§59).
    """

    AUTHENTICATED = "AUTHENTICATED"
    MFA_REQUIRED = "MFA_REQUIRED"


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    """A complete credential set for one session."""

    access_token: str
    #: Shown to the client once. Only its SHA-256 digest is stored.
    refresh_token: str
    #: Double-submit token bound to ``session_id``; read from a non-HttpOnly cookie.
    csrf_token: str
    session_id: UUID
    #: Access-token lifetime in seconds, for the client's own refresh scheduling.
    expires_in: int
    token_type: str = _SCHEME_BEARER

    def __repr__(self) -> str:
        return (
            f"IssuedTokens(session_id={self.session_id}, expires_in={self.expires_in}, "
            f"token_type={self.token_type!r}, access_token=<redacted>, "
            f"refresh_token=<redacted>, csrf_token=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class LoginResult:
    """What a login attempt produced."""

    outcome: LoginOutcome
    user: User
    #: Present when ``outcome`` is ``AUTHENTICATED``.
    tokens: IssuedTokens | None = None
    #: A short-lived JWT proving the password was correct, carrying no ``sid``
    #: because no session exists yet (§59).
    mfa_challenge: str | None = None

    @property
    def is_authenticated(self) -> bool:
        """Whether the caller may proceed."""
        return self.outcome is LoginOutcome.AUTHENTICATED and self.tokens is not None

    def __repr__(self) -> str:
        # The user's email is identity rather than a credential, and support staff
        # need it to tell results apart; no token is included.
        return f"LoginResult(outcome={self.outcome.value}, user_id={self.user.id})"


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    """What signing up produced.

    ``verification_token`` is the plaintext of an emailed token, and is ``None`` when
    the platform does not require address confirmation. Whether it is ever delivered
    is the HTTP layer's decision and depends on configuration: a production response
    body must not contain it, because an endpoint that returns a verification token to
    whoever asked for one has verified nothing (§59).
    """

    user: User
    verification_token: str | None = None

    def __repr__(self) -> str:
        return (
            f"RegistrationResult(user_id={self.user.id}, "
            f"verification_token={'<redacted>' if self.verification_token else None})"
        )


@dataclass(frozen=True, slots=True)
class PasswordChangeResult:
    """What changing a password did.

    Carries a fresh credential set, which is the part that is easy to get wrong. The
    session that changed the password was necessarily created *before* the change, and
    every pre-change session is refused from then on — so without a replacement the
    caller would be signed out by their own successful request, and "sign out
    everywhere else" would be unusable as a self-defence tool.

    Re-issuing rather than exempting is also the stronger choice: the device that made
    the change gets a new session family and a new refresh token, so a token copied
    from that device earlier is dead too. An exemption would have left the one session
    an attacker was most likely to be holding as the only surviving one.
    """

    revoked_sessions: int
    tokens: IssuedTokens


@dataclass(frozen=True, slots=True)
class MfaEnrollment:
    """Everything needed to complete a TOTP enrollment, shown once."""

    #: Base32 shared secret, in plaintext, because the authenticator app has to be
    #: given it. Stored encrypted, never hashed: verifying a code requires reading
    #: it back (§12, §59).
    secret: str
    provisioning_uri: str
    recovery_codes: tuple[str, ...] = field(default_factory=tuple)

    def __repr__(self) -> str:
        return (
            f"MfaEnrollment(provisioning_uri=<redacted>, secret=<redacted>, "
            f"recovery_codes=<{len(self.recovery_codes)} codes, redacted>)"
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedRequest:
    """A caller whose access token, session and account all checked out.

    Carrying the session alongside the user is what makes revocation immediate:
    authority is read from these two rows on every request rather than from token
    claims, so ending a session or changing a role takes effect on the next request
    with no denylist and no stale-authority window (§43, §60).
    """

    user: User
    session: UserSession
    claims: TokenClaims

    @property
    def user_id(self) -> UUID:
        """The authenticated account."""
        return self.user.id

    @property
    def role(self) -> str:
        """The caller's current role, read from the database."""
        return self.user.role.value

    def __repr__(self) -> str:
        return (
            f"AuthenticatedRequest(user_id={self.user.id}, session_id={self.session.id}, "
            f"role={self.user.role.value})"
        )
