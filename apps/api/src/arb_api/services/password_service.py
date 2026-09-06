"""Credential lifecycle: change, reset and verify (§59, §60).

The unifying rule is that a credential change is also a *session* event. Changing a
password stamps ``password_changed_at`` and ends every session established before that
instant, because the reason people change a password is usually that they suspect
somebody else knows it — and a scheme that leaves the suspect's session alive has
performed the ceremony of a password change without its effect.

Reset is stricter than change: it ends *every* session including the caller's own. A
reset arrives by email, so the person clicking the link may not be the person holding
the open session, and the client is sent to sign in again with the new password. A
change, by contrast, spares the session making the request, because that session just
proved it holds the current password and throwing it out mid-action would make "sign
out everywhere else" unusable as a self-defence tool.

The two emailed-token flows answer identically whether or not the address exists. A
reset endpoint that says "no account with that address" is an enumeration oracle with
a rate limit on it, and the rate limit only slows the oracle down. What the endpoint
returns is a bare acknowledgement; the token goes to the mailbox, and the mailbox is
the proof of ownership.

**Email delivery is NOT IMPLEMENTED in Phase 2.** ``request_password_reset`` and
``request_email_verification`` return the plaintext token to their caller and nothing
sends it. The HTTP layer deliberately does not put that token in a response body: it
is only surfaced when ``EMAIL_PROVIDER=none`` *and* the deployment is not a deployed
environment, so a developer can complete the flow locally and a production response
can never carry it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from arb_api.services.audit_service import AuditActor, AuditService
from arb_api.services.auth_results import IssuedTokens, PasswordChangeResult
from arb_core.clock import utc_now
from arb_core.errors import InvalidCredentialsError, InvalidTokenError, PasswordPolicyError
from arb_core.identifiers import normalize_email
from arb_core.log import get_logger
from arb_core.security.passwords import PasswordHasher, PasswordPolicy
from arb_core.security.ratelimit import PASSWORD_RESET_BY_IP
from arb_core.security.tokens import generate_opaque_token, hash_opaque_token
from arb_persistence.models.enums import ActorType, AuditResult, AuthTokenPurpose
from arb_persistence.repositories.auth import AuthTokenRepository, UserRepository

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_api.services.session_service import SessionService
    from arb_core.config import Settings
    from arb_core.db.session import Database
    from arb_core.security.ratelimit import RateLimiter
    from arb_persistence.models.auth import User

__all__ = ["PasswordService"]

_logger = get_logger(__name__)

#: Prefixes make an emailed credential recognisable in a support transcript without
#: making it usable. The prefix is not part of the digest's input length problem:
#: these are 256-bit random values, not passwords.
_RESET_PREFIX: Final[str] = "pr"
_VERIFY_PREFIX: Final[str] = "ev"


class PasswordService:
    """Changes passwords, and issues and redeems the emailed tokens."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        settings: Settings,
        sessions: SessionService,
        rate_limiter: RateLimiter | None = None,
        database: Database | None = None,
    ) -> None:
        self._settings = settings
        self._sessions_service = sessions
        self._users = UserRepository(session)
        self._tokens = AuthTokenRepository(session)
        self._audit = AuditService(session, database=database)
        self._hasher = PasswordHasher.from_settings(settings)
        self._policy = PasswordPolicy.from_settings(settings)
        self._rate_limiter = rate_limiter

    # --- changing a known password ----------------------------------------
    async def change_password(
        self,
        *,
        user: User,
        current_password: str,
        new_password: str,
        session_id: UUID | None = None,
        moment: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> PasswordChangeResult:
        """Replace the password, end every session, and issue this caller a new one.

        The current password is required even from an authenticated caller: a session
        left open on an unlocked machine is not proof of who is sitting at it, and
        changing a password is exactly what somebody would do to take an account over
        from that position.

        Every session ends, *including the caller's own*, and a replacement is issued
        in the same transaction. The caller's session was created before the change and
        is therefore indistinguishable from an attacker's; sparing it would mean
        keeping alive the one session most likely to be the attacker's. Re-issuing
        costs the client one token swap and buys the stronger guarantee.

        ``session_id`` is still accepted, and still recorded in the audit entry, so an
        investigation can see which session performed the change even though it no
        longer survives it.
        """
        now = moment if moment is not None else utc_now()

        if not self._hasher.verify(current_password, user.password_hash):
            await self._audit.record_failure(
                action="AUTH_PASSWORD_CHANGE_REJECTED",
                resource_type="user",
                resource_id=user.id,
                actor=self._actor(user, ip_address),
                reason="the current password did not verify",
                request_id=request_id,
            )
            # The same error a login produces. Which credential was wrong is not
            # information this endpoint should hand out either.
            raise InvalidCredentialsError

        self._policy.validate(new_password, email=user.email, display_name=user.display_name)
        if self._hasher.verify(new_password, user.password_hash):
            # The policy cannot know what the current password is, so reuse is
            # checked here rather than inside it.
            raise PasswordPolicyError(
                details={"policy": ["The new password must differ from the current one."]}
            )

        user.set_password_hash(self._hasher.hash(new_password), moment=now)
        await self._users.flush()

        revoked = await self._sessions_service.revoke_all(
            user_id=user.id,
            reason="PASSWORD_CHANGED",
            moment=now,
            actor=self._actor(user, ip_address),
            request_id=request_id,
        )
        # Issued after the revocation and after the new digest is stored, so the new
        # session's created_at is unambiguously later than password_changed_at and the
        # per-request check in SessionService.authenticate lets it through.
        tokens: IssuedTokens = await self._sessions_service.issue(
            user=user, moment=now, ip_address=ip_address, user_agent=user_agent
        )
        await self._audit.record(
            action="AUTH_PASSWORD_CHANGED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={
                "sessions_revoked": revoked,
                "hash_scheme": self._hasher.scheme,
                "acting_session": str(session_id) if session_id else None,
                "replacement_session": str(tokens.session_id),
            },
            reason="the account holder changed their password",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        _logger.info(
            "password changed",
            extra={"user_id": str(user.id), "sessions_revoked": revoked},
        )
        return PasswordChangeResult(revoked_sessions=revoked, tokens=tokens)

    def verify_current_password(self, *, user: User, password: str) -> bool:
        """Whether ``password`` is this account's current password.

        Exists for operations that must be re-authorised with the credential itself
        rather than with a live session. Disabling MFA is the one in this phase:
        removing a second factor from a session on an unlocked machine would let
        anybody at that machine do it permanently, and the session proves only that
        somebody signed in earlier.

        Returns rather than raises so the caller decides what a wrong password means
        in its own context — but every caller in this codebase treats it as a refusal
        and audits it, because a failed re-authorisation attempt is exactly the kind
        of event §62 exists to record.
        """
        return self._hasher.verify(password, user.password_hash)

    async def audit_reauthorisation_failure(
        self,
        *,
        user: User,
        action: str,
        reason: str,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Record a refused re-authorisation, in a transaction that survives.

        The refusal raises, this request rolls back, and an entry written into that
        transaction would disappear with the event it describes. A failed attempt to
        disable MFA or change a password is exactly the kind of thing §52 and §62
        exist to keep, so it is written independently.
        """
        await self._audit.record_failure(
            action=action,
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            reason=reason,
            request_id=request_id,
        )

    # --- password reset by email ------------------------------------------
    async def request_password_reset(
        self,
        *,
        email: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> str | None:
        """Issue a reset token, or ``None`` if there is no account to reset.

        ``None`` and a token produce the same HTTP response. The distinction exists
        only so the caller can decide how to deliver the token — and so a test can
        assert that the token was really issued.
        """
        now = moment if moment is not None else utc_now()
        if self._rate_limiter is not None:
            await self._rate_limiter.enforce(
                PASSWORD_RESET_BY_IP, identifier=ip_address or "unknown", now=now
            )

        user = await self._users.get_by_email(normalize_email(email))
        if user is None or not user.is_active:
            # Audited without the address: the entry records that a reset was
            # requested for something that does not exist, which is the pattern worth
            # seeing, without turning the audit log into a record of who probed whom.
            await self._audit.record_failure(
                action="AUTH_PASSWORD_RESET_REQUESTED",
                resource_type="auth",
                actor=AuditActor(actor_type=ActorType.ANONYMOUS, ip_address=ip_address),
                reason="no active account for the submitted address",
                request_id=request_id,
            )
            return None

        token = generate_opaque_token(prefix=_RESET_PREFIX)
        _, superseded = await self._tokens.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(token),
            expires_at=now + self._settings.password_reset_token_ttl,
            moment=now,
            requested_ip=ip_address,
        )
        await self._audit.record(
            action="AUTH_PASSWORD_RESET_REQUESTED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"superseded_tokens": superseded},
            reason="a reset token was issued; only the newest is usable",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return token

    async def complete_password_reset(
        self,
        *,
        token: str,
        new_password: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> User:
        """Redeem a reset token and install a new password.

        Every refusal raises :class:`InvalidTokenError` with one message. Whether the
        token was invented, already spent or merely expired is audited and not
        reported: those three cases are the difference between a typo, a replay and a
        slow user, and only the first two interest an attacker.
        """
        now = moment if moment is not None else utc_now()
        row = await self._tokens.get_by_token(token, purpose=AuthTokenPurpose.PASSWORD_RESET)
        if row is None:
            await self._audit_token_rejection(
                reason="no reset token matched", ip_address=ip_address, request_id=request_id
            )
            raise InvalidTokenError

        user = await self._users.get_by_id(row.user_id)
        if user is None or not user.is_active:
            await self._audit_token_rejection(
                reason="the account is gone or inactive",
                resource_id=row.id,
                user_id=row.user_id,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        if not row.is_usable_at(now):
            await self._audit_token_rejection(
                reason="the token had already been redeemed"
                if row.is_consumed
                else "the token had expired",
                resource_id=row.id,
                user_id=user.id,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        # Validate before spending: a rejected password must leave the token usable,
        # or one typo in the new password costs the user a whole reset cycle and a
        # trip back to their mailbox.
        self._policy.validate(new_password, email=user.email, display_name=user.display_name)

        if not await self._tokens.consume(row, moment=now, ip_address=ip_address):
            await self._audit_token_rejection(
                reason="the token was spent by a concurrent request",
                resource_id=row.id,
                user_id=user.id,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        user.set_password_hash(self._hasher.hash(new_password), moment=now)
        await self._users.flush()

        # Every session ends, including the caller's. A reset arrives by email, so
        # whoever clicked the link is not necessarily whoever holds the open session.
        revoked = await self._sessions_service.revoke_all(
            user_id=user.id,
            reason="PASSWORD_RESET",
            moment=now,
            actor=self._actor(user, ip_address),
            request_id=request_id,
        )
        await self._audit.record(
            action="AUTH_PASSWORD_RESET_COMPLETED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"sessions_revoked": revoked},
            reason="a reset token was redeemed and every session ended",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        _logger.info(
            "password reset completed",
            extra={"user_id": str(user.id), "sessions_revoked": revoked},
        )
        return user

    # --- email verification -----------------------------------------------
    async def request_email_verification(
        self,
        *,
        user: User,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> str | None:
        """Issue a verification token for an account whose address is unconfirmed."""
        now = moment if moment is not None else utc_now()
        if user.email_verified:
            return None
        token = generate_opaque_token(prefix=_VERIFY_PREFIX)
        _, superseded = await self._tokens.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(token),
            expires_at=now + self._settings.email_verification_token_ttl,
            moment=now,
            requested_ip=ip_address,
        )
        await self._audit.record(
            action="AUTH_EMAIL_VERIFICATION_REQUESTED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"superseded_tokens": superseded},
            reason="a verification token was issued",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return token

    async def resend_email_verification(
        self,
        *,
        email: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> str | None:
        """Issue a fresh verification token for an address, if there is an account.

        Returns ``None`` for an unknown address, an account that is already verified
        and an account that is no longer active. All three produce the same HTTP
        response, so this cannot be used to discover which addresses are registered.
        """
        now = moment if moment is not None else utc_now()
        user = await self._users.get_by_email(normalize_email(email))
        if user is None or not user.is_active or user.email_verified:
            return None
        return await self.request_email_verification(
            user=user, moment=now, ip_address=ip_address, request_id=request_id
        )

    async def confirm_email(
        self,
        *,
        token: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> User:
        """Redeem a verification token, activating the account if it was pending."""
        now = moment if moment is not None else utc_now()
        row = await self._tokens.get_by_token(token, purpose=AuthTokenPurpose.EMAIL_VERIFICATION)
        if row is None:
            await self._audit_token_rejection(
                reason="no verification token matched",
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        user = await self._users.get_by_id(row.user_id)
        if user is None:
            await self._audit_token_rejection(
                reason="the account no longer exists",
                resource_id=row.id,
                user_id=row.user_id,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        if not row.is_usable_at(now):
            await self._audit_token_rejection(
                reason="the token had already been redeemed"
                if row.is_consumed
                else "the token had expired",
                resource_id=row.id,
                user_id=user.id,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        if not await self._tokens.consume(row, moment=now, ip_address=ip_address):
            await self._audit_token_rejection(
                reason="the token was spent by a concurrent request",
                resource_id=row.id,
                user_id=user.id,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise InvalidTokenError

        user.confirm_email(moment=now)
        await self._users.flush()
        await self._audit.record(
            action="AUTH_EMAIL_VERIFIED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"status": user.status.value},
            reason="the address was confirmed",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return user

    # --- helpers ----------------------------------------------------------
    def _actor(self, user: User | None, ip_address: str | None) -> AuditActor:
        """An audit actor for a known account, or an anonymous one."""
        if user is None:
            return AuditActor(actor_type=ActorType.ANONYMOUS, ip_address=ip_address)
        return AuditActor(
            actor_type=ActorType.USER,
            actor_id=user.id,
            role=user.role.value,
            ip_address=ip_address,
        )

    async def _audit_token_rejection(
        self,
        *,
        reason: str,
        resource_id: UUID | None = None,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Record a refused token redemption. The token itself is never stored."""
        await self._audit.record_failure(
            action="AUTH_TOKEN_REJECTED",
            resource_type="auth_token" if resource_id is not None else "auth",
            resource_id=resource_id,
            actor=AuditActor(
                actor_type=ActorType.USER if user_id is not None else ActorType.ANONYMOUS,
                actor_id=user_id,
                ip_address=ip_address,
            ),
            reason=reason,
            request_id=request_id,
        )
