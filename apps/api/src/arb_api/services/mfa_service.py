"""Second-factor enrollment and verification (§59).

Three properties are worth stating before the code, because each one is a place
where a plausible-looking implementation is quietly wrong.

**The secret is encrypted, not hashed.** A password can be a one-way digest because
verifying it never needs the original. A TOTP secret cannot: producing the expected
code requires the shared key, so it is stored as AES-256-GCM ciphertext bound to a
purpose. That makes ``ENCRYPTION_KEY`` a credential whose compromise yields every
user's second factor — which is why it is a 32-byte key from the environment, never
derived from anything in the database, and never logged (§12).

**A code is spent once, and the drift window does not weaken that.** ``verify_totp``
returns the *step* that matched rather than a boolean, and the step is recorded on the
account. Accepting the same step twice — or accepting an older step after a newer one
— is what RFC 6238 §5.2 forbids, and the drift that accommodates a skewed phone clock
would otherwise become a replay window three steps wide.

**Recovery codes are single-use and are replaced as a set.** Re-enrolling deletes the
previous set rather than adding to it: codes shown on an earlier screen may no longer
be on a screen the account holder controls, and a set nobody can enumerate is a set
nobody can trust. Each code is stored as a SHA-256 digest, so the database holds
proof that a code was issued without holding the code.

Dispatch between the two factors is by *shape*, not by trying both. A six-digit string
is a TOTP code and anything else is a recovery code; attempting one and then the other
would double the number of guesses an attacker gets per request and would let a
recovery code be spent by a request that meant to send a TOTP code.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Final

from arb_api.services.audit_service import AuditActor, AuditService
from arb_api.services.auth_results import MfaEnrollment
from arb_core.clock import utc_now
from arb_core.errors import MfaInvalidError
from arb_core.log import get_logger
from arb_core.security.crypto import SecretBox
from arb_core.security.ratelimit import MFA_VERIFY_BY_ACCOUNT
from arb_core.security.totp import (
    TotpConfig,
    generate_recovery_codes,
    hash_recovery_code,
    new_totp_secret,
    normalise_recovery_code,
    provisioning_uri,
    verify_totp,
)
from arb_persistence.models.enums import ActorType, AuditResult
from arb_persistence.repositories.auth import MfaRecoveryCodeRepository, UserRepository

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.config import Settings
    from arb_core.db.session import Database
    from arb_core.security.ratelimit import RateLimiter
    from arb_persistence.models.auth import User

__all__ = ["MfaMethod", "MfaService"]

_logger = get_logger(__name__)

#: The purpose bound into the AEAD additional data for a TOTP secret. Binding a
#: purpose means ciphertext written for one field cannot be presented as another,
#: even by somebody with write access to the database.
_TOTP_AAD_PURPOSE: Final[str] = "totp_secret"


class MfaMethod(StrEnum):
    """Which second factor was accepted. Recorded in the audit trail, never shown
    back to the caller as part of an error — knowing that a recovery code worked
    would tell an attacker which of two guesses to keep spending."""

    TOTP = "TOTP"
    RECOVERY_CODE = "RECOVERY_CODE"


class MfaService:
    """Enrolls, confirms, disables and verifies the second factor."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        settings: Settings,
        rate_limiter: RateLimiter | None = None,
        database: Database | None = None,
    ) -> None:
        self._settings = settings
        self._users = UserRepository(session)
        self._codes = MfaRecoveryCodeRepository(session)
        self._audit = AuditService(session, database=database)
        self._box = SecretBox.from_settings(settings)
        self._totp = TotpConfig.from_settings(settings)
        self._rate_limiter = rate_limiter

    # --- enrollment -------------------------------------------------------
    async def begin_enrollment(
        self,
        *,
        user: User,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> MfaEnrollment:
        """Generate a secret and a recovery set, and return them once.

        The account is *not* protected yet: ``mfa_enabled`` stays false until
        :meth:`confirm_enrollment` accepts a code. Enabling on generation would let
        a user who scanned the QR code incorrectly lock themselves out of an account
        that never had a working second factor.
        """
        now = moment if moment is not None else utc_now()
        secret = new_totp_secret()
        user.enroll_totp(encrypted_secret=self._box.encrypt(secret, purpose=_TOTP_AAD_PURPOSE))

        codes = generate_recovery_codes(self._settings.mfa_recovery_code_count)
        await self._codes.store_all(
            user_id=user.id,
            code_hashes=[hash_recovery_code(normalise_recovery_code(code)) for code in codes],
            moment=now,
        )
        await self._users.flush()

        await self._audit.record(
            action="AUTH_MFA_ENROLLMENT_STARTED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"recovery_codes_issued": len(codes)},
            reason="a TOTP secret was generated and awaits confirmation",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        # The plaintext secret and the plaintext codes exist only in this return
        # value. MfaEnrollment.__repr__ omits them for that reason.
        return MfaEnrollment(
            secret=secret,
            provisioning_uri=provisioning_uri(
                secret,
                account_name=user.email,
                issuer=self._settings.mfa_totp_issuer,
                config=self._totp,
            ),
            recovery_codes=codes,
        )

    async def confirm_enrollment(
        self,
        *,
        user: User,
        code: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Accept a code from the enrolled secret and switch the second factor on.

        The code that confirms enrollment is also spent: recording its step means the
        confirmation cannot be replayed as the first login with the new factor.
        """
        now = moment if moment is not None else utc_now()
        if user.totp_secret_encrypted is None:
            await self._audit_rejection(
                user=user,
                reason="confirmation attempted with no secret enrolled",
                method=None,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise MfaInvalidError

        step = self._match_totp(user=user, code=code, moment=now)
        if step is None:
            await self._audit_rejection(
                user=user,
                reason="the code presented at confirmation did not match the enrolled secret",
                method=MfaMethod.TOTP,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise MfaInvalidError

        user.record_totp_step(step)
        user.confirm_totp(moment=now)
        await self._users.flush()

        await self._audit.record(
            action="AUTH_MFA_ENABLED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"method": MfaMethod.TOTP.value},
            reason="a code from the enrolled secret was accepted",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )

    async def cancel_enrollment(
        self,
        *,
        user: User,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Abandon a pending enrollment.

        A secret that was generated and never confirmed is still ciphertext sitting on
        the account; leaving it there means a later confirmation attempt could bind to
        a secret whose QR code was displayed on a page nobody remembers closing.
        """
        user.disable_mfa()
        await self._codes.delete_for_user(user.id)
        await self._users.flush()
        await self._audit.record(
            action="AUTH_MFA_ENROLLMENT_CANCELLED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            reason="a pending enrollment was abandoned",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )

    async def disable(
        self,
        *,
        user: User,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> int:
        """Remove the second factor and destroy its recovery codes.

        The caller must have verified the password first — removing MFA with only a
        session cookie would let anybody who walks up to an unlocked machine take the
        second factor off the account permanently.
        """
        removed = await self._codes.delete_for_user(user.id)
        user.disable_mfa()
        await self._users.flush()

        _logger.warning(
            "multi-factor authentication disabled",
            extra={"user_id": str(user.id), "recovery_codes_destroyed": removed},
        )
        await self._audit.record(
            action="AUTH_MFA_DISABLED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"recovery_codes_destroyed": removed},
            reason="the account holder removed the second factor",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return removed

    # --- verification -----------------------------------------------------
    async def verify(
        self,
        *,
        user: User,
        code: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        request_id: str | None = None,
    ) -> MfaMethod:
        """Accept a TOTP code or a recovery code, and say which one it was.

        Raises :class:`MfaInvalidError` for every refusal with the same message. The
        reason is audited, because "the code did not match" and "that recovery code
        was already spent" mean very different things to an investigation and exactly
        the same thing to an attacker.
        """
        now = moment if moment is not None else utc_now()
        await self._charge_budget(user.id, now=now)

        if not user.mfa_enabled:
            # Nothing to verify against. Refuse rather than treat "no second factor
            # configured" as a pass, which is how a missing enrollment becomes a
            # bypass.
            await self._audit_rejection(
                user=user,
                reason="verification attempted on an account with no confirmed second factor",
                method=None,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise MfaInvalidError

        if self._has_totp_shape(code):
            step = self._match_totp(user=user, code=code, moment=now)
            if step is None:
                await self._audit_rejection(
                    user=user,
                    reason="the code did not match any step inside the drift window",
                    method=MfaMethod.TOTP,
                    ip_address=ip_address,
                    request_id=request_id,
                )
                raise MfaInvalidError
            if user.totp_step_is_replay(step):
                # RFC 6238 §5.2. A repeated code is either a client retrying after a
                # lost response or somebody replaying a code they observed; both are
                # refused, and the difference is recorded rather than guessed at.
                _logger.warning(
                    "totp code replayed within its drift window",
                    extra={"user_id": str(user.id), "step": step},
                )
                await self._audit_rejection(
                    user=user,
                    reason="the code's step had already been accepted",
                    method=MfaMethod.TOTP,
                    ip_address=ip_address,
                    request_id=request_id,
                )
                raise MfaInvalidError

            user.record_totp_step(step)
            await self._users.flush()
            await self._audit_acceptance(
                user=user, method=MfaMethod.TOTP, ip_address=ip_address, request_id=request_id
            )
            return MfaMethod.TOTP

        return await self._verify_recovery_code(
            user=user, code=code, moment=now, ip_address=ip_address, request_id=request_id
        )

    async def _verify_recovery_code(
        self,
        *,
        user: User,
        code: str,
        moment: datetime,
        ip_address: str | None,
        request_id: str | None,
    ) -> MfaMethod:
        """Spend one recovery code."""
        digest = hash_recovery_code(normalise_recovery_code(code))
        row = await self._codes.find_usable(user_id=user.id, code_hash=digest)
        if row is None:
            await self._audit_rejection(
                user=user,
                reason="no unused recovery code matched",
                method=MfaMethod.RECOVERY_CODE,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise MfaInvalidError

        if not await self._codes.consume(row, moment=moment, ip_address=ip_address):
            # The row was found unconsumed and then was not: another request spent it
            # first. Refuse rather than accept a code twice because two requests
            # raced.
            await self._audit_rejection(
                user=user,
                reason="the recovery code had already been spent by a concurrent request",
                method=MfaMethod.RECOVERY_CODE,
                ip_address=ip_address,
                request_id=request_id,
            )
            raise MfaInvalidError

        remaining = await self._codes.remaining_count(user.id)
        if remaining == 0:
            _logger.warning(
                "last recovery code spent; the account has no fallback factor left",
                extra={"user_id": str(user.id)},
            )
        await self._audit.record(
            action="AUTH_MFA_VERIFIED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={
                "method": MfaMethod.RECOVERY_CODE.value,
                "recovery_codes_remaining": remaining,
            },
            reason="a single-use recovery code was accepted",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return MfaMethod.RECOVERY_CODE

    async def remaining_recovery_codes(self, user: User) -> int:
        """How many unused recovery codes the account still holds."""
        return await self._codes.remaining_count(user.id)

    # --- internals --------------------------------------------------------
    def _actor(self, user: User, ip_address: str | None) -> AuditActor:
        """An audit actor for the account performing the action."""
        return AuditActor(
            actor_type=ActorType.USER,
            actor_id=user.id,
            role=user.role.value,
            ip_address=ip_address,
        )

    def _has_totp_shape(self, code: str) -> bool:
        """Whether ``code`` looks like a TOTP code rather than a recovery code.

        Dispatching on shape means one guess per request. Trying both factors would
        double an attacker's guesses and could spend a recovery code on a request
        that only meant to send a TOTP code.
        """
        digits = self._settings.mfa_totp_digits
        return len(code) == digits and code.isdigit()

    def _match_totp(self, *, user: User, code: str, moment: datetime) -> int | None:
        """The step ``code`` matched, or ``None``.

        Returns the step rather than a boolean because the caller has to record it:
        that is what makes the drift window tolerant of clock skew without becoming a
        window in which one code can be spent twice.
        """
        if user.totp_secret_encrypted is None:
            return None
        secret = self._box.decrypt(user.totp_secret_encrypted, purpose=_TOTP_AAD_PURPOSE)
        return verify_totp(secret, code, at=moment, config=self._totp)

    async def _charge_budget(self, user_id: object, *, now: datetime) -> None:
        """Charge one verification attempt against the per-account budget."""
        if self._rate_limiter is None:
            return
        await self._rate_limiter.enforce(MFA_VERIFY_BY_ACCOUNT, identifier=str(user_id), now=now)

    async def _audit_acceptance(
        self,
        *,
        user: User,
        method: MfaMethod,
        ip_address: str | None,
        request_id: str | None,
    ) -> None:
        await self._audit.record(
            action="AUTH_MFA_VERIFIED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"method": method.value},
            reason="the second factor was accepted",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )

    async def _audit_rejection(
        self,
        *,
        user: User,
        reason: str,
        method: MfaMethod | None,
        ip_address: str | None,
        request_id: str | None,
    ) -> None:
        """Record a refusal. The submitted code never appears, in any form."""
        await self._audit.record_failure(
            action="AUTH_MFA_REJECTED",
            resource_type="user",
            resource_id=user.id,
            actor=self._actor(user, ip_address),
            new_value={"method": method.value if method is not None else None},
            reason=reason,
            request_id=request_id,
        )
