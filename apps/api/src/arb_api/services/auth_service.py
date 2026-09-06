"""Registration and sign-in (§59, §61).

This is the file where the security decisions are actually made, so they are stated
here rather than left to be inferred from the control flow.

**One response for "wrong password" and "no such account."** Both raise
:class:`InvalidCredentialsError` with one code and one message. A distinct response
for an unknown address turns the login endpoint into an enumeration oracle, and the
first step of a targeted credential attack is compiling a list of addresses that
exist. The unknown-account path also burns a full password verification
(:meth:`PasswordHasher.verify_unknown_account`), because a response that returns in
2 ms instead of 80 ms reveals the same thing without ever differing in content.

**Three responses do reveal that an account exists** — locked, disabled, and
email-not-verified — and that is a deliberate, bounded trade rather than an
oversight. Each of them is information the legitimate owner needs and cannot get
elsewhere: "your account is locked, retry in 9 minutes" is the difference between a
user waiting and a user concluding their password was changed by somebody else. Each
is reachable only after the rate limit has been spent, each is audited, and the
lockout check runs *before* password verification so a locked account cannot be used
to make the platform perform unbounded argon2 work (§61, §71).

**A successful password clears the account budget but not the IP budget.** Resetting
``LOGIN_BY_IP`` on success would let an attacker who holds one valid account clear
their own guessing budget at will, which is the whole point of that bucket. The
per-account bucket is reset because it counts *consecutive* failures against one
credential, and that credential has just been proved.

**A lock does not extend while it runs.** Attempts made during a lockout are refused
before they reach the counter, so an attacker cannot keep a victim locked out forever
by hammering the endpoint. That would turn a brute-force defence into a denial of
service against the account owner. The lock runs its course and the first failure
after it expires re-locks, giving a continuing attacker one guess per lockout period.

**MFA completes the login; it does not decorate it.** A correct password on an account
with a confirmed second factor produces a challenge token and *no session*. The
challenge carries no ``sid`` claim, so nothing downstream can mistake it for
authority, and it expires in minutes. The client is told 401 with the challenge in the
error details — reporting a half-finished login as success is how MFA gets bypassed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from arb_api.services.audit_service import AuditActor, AuditService
from arb_api.services.auth_results import LoginOutcome, LoginResult, RegistrationResult
from arb_core.clock import utc_now
from arb_core.errors import (
    AccountDisabledError,
    AccountLockedError,
    EmailAlreadyRegisteredError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidTokenError,
    RegistrationDisabledError,
)
from arb_core.identifiers import normalize_email
from arb_core.log import get_logger
from arb_core.security.passwords import PasswordHasher, PasswordPolicy
from arb_core.security.ratelimit import LOGIN_BY_ACCOUNT, LOGIN_BY_IP, REGISTER_BY_IP
from arb_core.security.tokens import TokenService, TokenType
from arb_persistence.models.enums import ActorType, AuditResult, UserStatus
from arb_persistence.repositories.auth import UserRepository

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_api.services.mfa_service import MfaService
    from arb_api.services.password_service import PasswordService
    from arb_api.services.session_service import SessionService
    from arb_core.config import Settings
    from arb_core.db.session import Database
    from arb_core.security.ratelimit import RateLimiter
    from arb_persistence.models.auth import User

__all__ = ["AuthService"]

_logger = get_logger(__name__)

#: Identifier used when no client address is available. A real limit still applies,
#: which means an unattributable caller shares one budget with every other
#: unattributable caller — deliberately worse for them than for a normal client.
_UNKNOWN_IP: Final[str] = "unknown"


class AuthService:
    """Registers accounts and signs them in."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        settings: Settings,
        sessions: SessionService,
        mfa: MfaService,
        passwords: PasswordService,
        rate_limiter: RateLimiter | None = None,
        database: Database | None = None,
    ) -> None:
        self._settings = settings
        self._users = UserRepository(session)
        self._sessions_service = sessions
        self._mfa = mfa
        self._passwords = passwords
        self._audit = AuditService(session, database=database)
        self._tokens = TokenService.from_settings(settings)
        self._hasher = PasswordHasher.from_settings(settings)
        self._policy = PasswordPolicy.from_settings(settings)
        self._rate_limiter = rate_limiter

    # --- registration -----------------------------------------------------
    async def register(
        self,
        *,
        email: str,
        password: str,
        display_name: str | None = None,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> RegistrationResult:
        """Create an account. Self-service sign-up never confers platform authority.

        The role is whatever :func:`arb_core.security.rbac.default_role` returns — a
        customer role. There is no parameter for it on this path, so no crafted
        request body can produce an administrator (§41).
        """
        now = moment if moment is not None else utc_now()
        if not self._settings.registration_enabled:
            raise RegistrationDisabledError

        if self._rate_limiter is not None:
            await self._rate_limiter.enforce(
                REGISTER_BY_IP, identifier=ip_address or _UNKNOWN_IP, now=now
            )

        canonical = normalize_email(email)
        # Validated before existence is checked, so the response to a malformed
        # submission does not depend on whether the address happens to be taken.
        self._policy.validate(password, email=canonical, display_name=display_name)

        if await self._users.email_is_taken(canonical):
            await self._audit.record(
                action="AUTH_REGISTERED",
                resource_type="auth",
                actor=AuditActor(actor_type=ActorType.ANONYMOUS, ip_address=ip_address),
                reason="the address is already registered",
                result=AuditResult.FAILURE,
                request_id=request_id,
            )
            # Registration is the one endpoint that must disclose this: without it a
            # user who mistypes an address they already own has no way to recover.
            # The enumeration risk is accepted and bounded by the rate limit above.
            raise EmailAlreadyRegisteredError

        requires_verification = self._settings.email_verification_required
        user = await self._users.create(
            email=canonical,
            password_hash=self._hasher.hash(password),
            status=(
                UserStatus.PENDING_VERIFICATION if requires_verification else UserStatus.ACTIVE
            ),
            display_name=display_name,
        )
        verification_token = (
            await self._passwords.request_email_verification(
                user=user, moment=now, ip_address=ip_address, request_id=request_id
            )
            if requires_verification
            else None
        )

        await self._audit.record(
            action="AUTH_REGISTERED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={
                "role": user.role.value,
                "status": user.status.value,
                "email_verification_required": requires_verification,
            },
            reason="an account was created by self-service registration",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        _logger.info(
            "account registered",
            extra={"user_id": str(user.id), "status": user.status.value},
        )
        return RegistrationResult(user=user, verification_token=verification_token)

    # --- sign-in ----------------------------------------------------------
    async def login(
        self,
        *,
        email: str,
        password: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> LoginResult:
        """Verify a password and produce either a session or an MFA challenge."""
        now = moment if moment is not None else utc_now()
        canonical = normalize_email(email)

        # Before any database work. The limit is what bounds the argon2 cost an
        # attacker can impose, and checking it afterwards would spend the work first.
        if self._rate_limiter is not None:
            await self._rate_limiter.enforce(
                LOGIN_BY_IP, identifier=ip_address or _UNKNOWN_IP, now=now
            )
            await self._rate_limiter.enforce(LOGIN_BY_ACCOUNT, identifier=canonical, now=now)

        user = await self._users.get_by_email(canonical)
        if user is None:
            # Same work, same latency, same response as a wrong password.
            self._hasher.verify_unknown_account(password)
            await self._audit_login(
                user=None,
                reason="no account for the submitted address",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise InvalidCredentialsError

        if user.is_locked_at(now):
            remaining = user.lock_remaining(now)
            retry_after = int(remaining.total_seconds()) + 1 if remaining is not None else None
            await self._audit_login(
                user=user,
                reason="the account is locked; attempts during a lock are not counted",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise AccountLockedError(retry_after_seconds=retry_after)

        # Checked before the generic status refusal, and by status rather than by the
        # absence of a verification timestamp: ``is_active`` is false for a pending
        # account too, so this order decides whether the user is told "confirm your
        # address" - which they can act on - or "this account is not able to sign in",
        # which sends them to support for a problem they could have fixed themselves.
        if user.status is UserStatus.PENDING_VERIFICATION:
            await self._audit_login(
                user=user,
                reason="the address has not been confirmed",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise EmailNotVerifiedError

        if not user.is_active:
            await self._audit_login(
                user=user,
                reason=f"the account is {user.status.value}",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise AccountDisabledError

        if not self._hasher.verify(password, user.password_hash):
            locked = user.record_failed_login(
                moment=now,
                max_attempts=self._settings.login_max_failed_attempts,
                lockout=self._settings.login_lockout_duration,
            )
            await self._users.flush()
            await self._audit_login(
                user=user,
                reason="the password did not verify",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                new_value={
                    "failed_attempts": user.failed_login_count,
                    "locked": locked,
                },
            )
            if locked:
                seconds = int(self._settings.login_lockout_duration.total_seconds())
                _logger.warning(
                    "account locked after repeated failed sign-ins",
                    extra={"user_id": str(user.id), "attempts": user.failed_login_count},
                )
                raise AccountLockedError(retry_after_seconds=seconds)
            raise InvalidCredentialsError

        # --- the password is correct from here on ---
        if self._hasher.needs_rehash(user.password_hash):
            # Transparent upgrade: raising ARGON2_TIME_COST or moving off bcrypt then
            # migrates the account population one sign-in at a time, with no forced
            # reset and no window where the old parameters are still accepted.
            user.set_password_hash(self._hasher.hash(password), moment=now)
        user.clear_failed_logins()
        await self._users.flush()

        if self._rate_limiter is not None:
            # The account budget counts consecutive failures against one credential,
            # and that credential has just been proved. The IP budget is deliberately
            # NOT reset: an attacker holding one valid account could otherwise clear
            # their own guessing budget at will.
            await self._rate_limiter.reset(LOGIN_BY_ACCOUNT, identifier=canonical)

        if user.mfa_confirmed:
            challenge = self._tokens.issue_mfa_challenge(
                user_id=user.id, ttl=self._settings.mfa_challenge_ttl
            )
            await self._audit_login(
                user=user,
                reason="the password verified; a second factor is still owed",
                result=AuditResult.SUCCESS,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                action="AUTH_MFA_CHALLENGE_ISSUED",
                new_value={
                    "challenge_ttl_seconds": int(self._settings.mfa_challenge_ttl.total_seconds())
                },
            )
            return LoginResult(
                outcome=LoginOutcome.MFA_REQUIRED, user=user, mfa_challenge=challenge
            )

        tokens = await self._sessions_service.issue(
            user=user, moment=now, ip_address=ip_address, user_agent=user_agent
        )
        user.record_successful_login(moment=now)
        await self._users.flush()
        await self._audit_login(
            user=user,
            reason="password verified and a session was issued",
            result=AuditResult.SUCCESS,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            new_value={"session_id": str(tokens.session_id), "method": "PASSWORD"},
        )
        return LoginResult(outcome=LoginOutcome.AUTHENTICATED, user=user, tokens=tokens)

    async def complete_mfa_login(
        self,
        *,
        challenge: str,
        code: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> LoginResult:
        """Finish a sign-in that a correct password left half-done.

        The challenge proves the password was right and carries no session id, so
        nothing that reads it can mistake it for authority. The session created here
        records ``mfa_completed_at``, which is what lets an administrator tell a
        session that passed two factors from one that passed one (§59).
        """
        now = moment if moment is not None else utc_now()
        claims = self._tokens.decode(challenge, expected_type=TokenType.MFA_CHALLENGE)

        user = await self._users.get_by_id(claims.subject)
        if user is None:
            await self._audit_login(
                user=None,
                reason="the challenge named an account that does not exist",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                action="AUTH_MFA_CHALLENGE_REJECTED",
            )
            raise InvalidTokenError
        if not user.is_active:
            await self._audit_login(
                user=user,
                reason=f"the account became {user.status.value} mid sign-in",
                result=AuditResult.FAILURE,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                action="AUTH_MFA_CHALLENGE_REJECTED",
            )
            raise AccountDisabledError

        method = await self._mfa.verify(
            user=user, code=code, moment=now, ip_address=ip_address, request_id=request_id
        )

        tokens = await self._sessions_service.issue(
            user=user,
            moment=now,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_completed_at=now,
        )
        user.record_successful_login(moment=now)
        await self._users.flush()

        await self._audit_login(
            user=user,
            reason="the second factor was accepted and a session was issued",
            result=AuditResult.SUCCESS,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            new_value={"session_id": str(tokens.session_id), "method": method.value},
        )
        _logger.info(
            "sign-in completed with a second factor",
            extra={"user_id": str(user.id), "mfa_method": method.value},
        )
        return LoginResult(outcome=LoginOutcome.AUTHENTICATED, user=user, tokens=tokens)

    # --- sign-out ---------------------------------------------------------
    async def logout(
        self,
        *,
        session_id: UUID,
        user: User,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> bool:
        """End the caller's own session."""
        return await self._sessions_service.revoke(
            session_id=session_id,
            reason="USER_LOGOUT",
            moment=moment,
            actor=self._actor(user, ip_address),
            request_id=request_id,
        )

    async def logout_everywhere(
        self,
        *,
        user: User,
        session_id: UUID | None = None,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> int:
        """End every session except the one making the request.

        Sparing the caller is what makes this usable as self-defence: without it, the
        button somebody reaches for during an incident also throws them out mid-action,
        and the natural response is to not press it.
        """
        return await self._sessions_service.revoke_all(
            user_id=user.id,
            reason="USER_LOGOUT_ALL",
            moment=moment,
            except_session_id=session_id,
            actor=self._actor(user, ip_address),
            request_id=request_id,
        )

    # --- helpers ----------------------------------------------------------
    def _actor(
        self, user: User | None, ip_address: str | None, user_agent: str | None = None
    ) -> AuditActor:
        """Who did this. An anonymous actor for a submission that named no account."""
        if user is None:
            return AuditActor(
                actor_type=ActorType.ANONYMOUS, ip_address=ip_address, user_agent=user_agent
            )
        return AuditActor(
            actor_type=ActorType.USER,
            actor_id=user.id,
            role=user.role.value,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def _audit_login(
        self,
        *,
        user: User | None,
        reason: str,
        result: AuditResult,
        ip_address: str | None,
        user_agent: str | None,
        request_id: str | None,
        action: str = "AUTH_LOGIN",
        new_value: dict[str, object] | None = None,
    ) -> None:
        """Record one sign-in outcome.

        The submitted password and the submitted code are never passed in, and never
        appear in ``reason``: an audit log is read by support staff and exported to
        incident reviews, so a credential that reaches it has reached more people than
        the account it belongs to (§127, §133).
        """
        writer = self._audit.record if result is AuditResult.SUCCESS else self._audit.record_failure
        await writer(
            action=action,
            resource_type="user" if user is not None else "auth",
            resource_id=user.id if user is not None else None,
            actor=self._actor(user, ip_address, user_agent),
            new_value=new_value,
            reason=reason,
            result=result,
            request_id=request_id,
        )
