"""Session lifecycle: issue, rotate, revoke and authenticate (§59, §60, §63).

Two decisions carry the weight of the whole authentication design.

**The database is the authority on every request.** An access token is validated,
then the session row and the account row it points at are read and checked again.
That costs one indexed query per request and buys three properties no token-only
scheme has: revoking a session ends it immediately rather than after up to fifteen
more minutes of validity; a role change takes effect on the next request, because
authority is read from the row rather than carried in the token; and a password
change invalidates every session established before it, which is what a user means
when they change a password because they suspect somebody else knows it (§43, §60).

**Rotation treats reuse as theft, not as a retry.** A refresh token is exchanged for
a new one and the old row moves to ROTATED rather than being deleted. If a rotated
token is presented again then two things are simultaneously true: somebody exchanged
it earlier, and somebody else is holding it now. One of them is the legitimate owner
and nothing on the server can say which, so the only safe action is to revoke the
whole family and make both parties sign in again. The innocent user loses a session;
the attacker loses the account (§60).

The family's absolute deadline is carried across every rotation rather than renewed.
Refreshing every fifteen minutes would otherwise produce a session that never ends,
and ``SESSION_TTL_HOURS`` would be decoration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from arb_api.services.audit_service import AuditActor, AuditService
from arb_api.services.auth_results import AuthenticatedRequest, IssuedTokens
from arb_core.clock import utc_now
from arb_core.errors import SessionRevokedError, TokenExpiredError
from arb_core.log import get_logger
from arb_core.security.csrf import CsrfProtector
from arb_core.security.ratelimit import REFRESH_BY_IP
from arb_core.security.rbac import Permission, permissions_for
from arb_core.security.tokens import (
    TokenService,
    TokenType,
    generate_opaque_token,
    hash_opaque_token,
)
from arb_persistence.models.enums import ActorType, AuditResult
from arb_persistence.repositories.auth import SessionRepository, UserRepository

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.config import Settings
    from arb_core.security.ratelimit import RateLimiter
    from arb_core.security.tokens import TokenClaims
    from arb_persistence.models.auth import User, UserSession

__all__ = ["SessionService"]

_logger = get_logger(__name__)

#: How stale ``last_seen_at`` may become before a request writes a new value.
#:
#: Without this, every authenticated request issues an UPDATE — on a busy deployment
#: more write traffic than the trading tables produce. Idle expiry is therefore
#: accurate to within a minute, which is immaterial against a 30-minute default idle
#: timeout and never extends a session past its absolute deadline.
_TOUCH_GRANULARITY_SECONDS: Final[int] = 60

#: Prefix on a refresh token. Opaque credentials are recognisable in a support
#: transcript without being usable, and the prefix never appears in a digest.
_REFRESH_PREFIX: Final[str] = "rt"


class SessionService:
    """Creates, rotates, revokes and validates sessions."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        settings: Settings,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._sessions = SessionRepository(session)
        self._users = UserRepository(session)
        self._audit = AuditService(session)
        self._tokens = TokenService.from_settings(settings)
        self._csrf = CsrfProtector.from_settings(settings)
        self._rate_limiter = rate_limiter

    # --- issuing ----------------------------------------------------------
    async def issue(
        self,
        *,
        user: User,
        moment: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
        mfa_completed_at: datetime | None = None,
    ) -> IssuedTokens:
        """Open a new session family and return its credential set.

        The refresh token's plaintext exists only in the return value; the row holds
        a SHA-256 digest, so a database leak does not hand an attacker anybody's
        session (§60).
        """
        refresh_token = generate_opaque_token(prefix=_REFRESH_PREFIX)
        row = await self._sessions.start(
            user_id=user.id,
            refresh_token_hash=hash_opaque_token(refresh_token),
            expires_at=moment + self._settings.session_absolute_ttl,
            moment=moment,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_completed_at=mfa_completed_at,
        )
        return self._credential_set(user=user, row=row, refresh_token=refresh_token)

    def _credential_set(self, *, user: User, row: UserSession, refresh_token: str) -> IssuedTokens:
        """Assemble the tokens for an already-created session row."""
        return IssuedTokens(
            access_token=self._tokens.issue_access_token(
                user_id=user.id,
                session_id=row.id,
                ttl=self._settings.access_token_ttl,
            ),
            refresh_token=refresh_token,
            csrf_token=self._csrf.issue(session_id=row.id),
            session_id=row.id,
            expires_in=int(self._settings.access_token_ttl.total_seconds()),
        )

    # --- rotating ---------------------------------------------------------
    async def refresh(
        self,
        *,
        refresh_token: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> IssuedTokens:
        """Exchange a refresh token for a new one, detecting reuse.

        Every refusal raises :class:`SessionRevokedError` with the same message
        whether the token was stolen, revoked or merely old. The difference between
        those cases is exactly what an attacker would probe for, so it stays in the
        audit log and out of the response.
        """
        now = moment if moment is not None else utc_now()
        await self._charge_refresh_budget(ip_address, now=now)

        row = await self._sessions.get_by_refresh_token(hash_opaque_token(refresh_token))
        if row is None:
            await self._audit_rejection(
                reason="unknown refresh token",
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        if row.is_rotated:
            # REPLAY. Somebody exchanged this token already, so two holders exist
            # and one of them is not the owner. End the family: the legitimate user
            # re-authenticates and the stolen chain dies with it.
            revoked = await self._sessions.revoke_family(
                row.family_id, moment=now, reason="TOKEN_REUSE"
            )
            _logger.critical(
                "refresh token replay detected; session family revoked",
                extra={
                    "user_id": str(row.user_id),
                    "family_id": str(row.family_id),
                    "sessions_revoked": revoked,
                    "ip_address": ip_address or "unknown",
                },
            )
            await self._audit.record(
                action="AUTH_SESSION_REFRESH_TOKEN_REPLAY",
                resource_type="user_session",
                resource_id=row.id,
                actor=AuditActor(
                    actor_type=ActorType.USER,
                    actor_id=row.user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
                new_value={"family_id": str(row.family_id), "sessions_revoked": revoked},
                reason="a rotated refresh token was presented again",
                result=AuditResult.FAILURE,
                request_id=request_id,
            )
            raise SessionRevokedError

        if not row.is_active:
            await self._audit_rejection(
                reason=f"session not active ({row.status.value})",
                resource_id=row.id,
                user_id=row.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        if row.is_expired_at(now, idle_ttl=self._settings.session_idle_ttl):
            await self._sessions.expire(row, moment=now)
            await self._audit_rejection(
                reason="session expired",
                resource_id=row.id,
                user_id=row.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise TokenExpiredError

        user = await self._users.get_by_id(row.user_id)
        if user is None or not user.is_active:
            await self._sessions.revoke(row, moment=now, reason="USER_INACTIVE")
            await self._audit_rejection(
                reason="account is not active",
                resource_id=row.id,
                user_id=row.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        if user.password_changed_at is not None and row.created_at < user.password_changed_at:
            # A session that predates a credential change was authenticated with
            # something that may have been the attacker's password.
            await self._sessions.revoke(row, moment=now, reason="PASSWORD_CHANGED")
            await self._audit_rejection(
                reason="session predates a password change",
                resource_id=row.id,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        new_refresh_token = generate_opaque_token(prefix=_REFRESH_PREFIX)
        rotated = await self._sessions.rotate(
            row,
            refresh_token_hash=hash_opaque_token(new_refresh_token),
            # The family deadline is inherited, never renewed: rotating a token must
            # not be a way to stay signed in forever.
            expires_at=row.expires_at,
            moment=now,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await self._audit.record(
            action="AUTH_SESSION_REFRESH",
            resource_type="user_session",
            resource_id=rotated.id,
            actor=AuditActor(
                actor_type=ActorType.USER,
                actor_id=user.id,
                role=user.role.value,
                ip_address=ip_address,
                user_agent=user_agent,
            ),
            old_value={"session_id": str(row.id)},
            new_value={"family_id": str(rotated.family_id)},
            reason="refresh token rotated",
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return self._credential_set(user=user, row=rotated, refresh_token=new_refresh_token)

    async def _charge_refresh_budget(self, ip_address: str | None, *, now: datetime) -> None:
        """Charge one refresh attempt against the per-IP budget.

        No account is known yet — identifying it is what the token is for — so the
        budget is per-IP, which is what stops a stolen token being sprayed from one
        host. Users behind a shared NAT spend each other's budget; that is the
        accepted trade, because the alternative is no limit at all.
        """
        if self._rate_limiter is None:
            return
        await self._rate_limiter.enforce(REFRESH_BY_IP, identifier=ip_address or "unknown", now=now)

    # --- revoking ---------------------------------------------------------
    async def revoke(
        self,
        *,
        session_id: UUID,
        reason: str,
        moment: datetime | None = None,
        actor: AuditActor | None = None,
        request_id: str | None = None,
    ) -> bool:
        """End one session. Returns whether there was a session to end."""
        now = moment if moment is not None else utc_now()
        row = await self._sessions.get_by_id(session_id)
        if row is None:
            return False
        await self._sessions.revoke(row, moment=now, reason=reason)
        await self._audit.record(
            action="AUTH_SESSION_REVOKED",
            resource_type="user_session",
            resource_id=session_id,
            actor=actor,
            new_value={"status": row.status.value, "reason": reason},
            reason=reason,
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return True

    async def revoke_all(
        self,
        *,
        user_id: UUID,
        reason: str,
        moment: datetime | None = None,
        except_session_id: UUID | None = None,
        actor: AuditActor | None = None,
        request_id: str | None = None,
    ) -> int:
        """End every live session for an account, optionally sparing one.

        Sparing the caller's own session is what makes "sign out everywhere else"
        usable: without it the button that protects an account also throws the
        person protecting it out of it, mid-incident.
        """
        now = moment if moment is not None else utc_now()
        revoked = await self._sessions.revoke_all_for_user(
            user_id, moment=now, reason=reason, except_session_id=except_session_id
        )
        await self._audit.record(
            action="AUTH_SESSIONS_REVOKED_ALL",
            resource_type="user",
            resource_id=user_id,
            actor=actor,
            new_value={"sessions_revoked": revoked, "spared": str(except_session_id or "") or None},
            reason=reason,
            result=AuditResult.SUCCESS,
            request_id=request_id,
        )
        return revoked

    async def list_active(
        self, *, user_id: UUID, moment: datetime | None = None
    ) -> Sequence[UserSession]:
        """The account's currently valid sessions, most recently used first."""
        now = moment if moment is not None else utc_now()
        return await self._sessions.list_for_user(
            user_id, moment=now, idle_ttl=self._settings.session_idle_ttl
        )

    async def expire_idle(self, *, moment: datetime | None = None) -> int:
        """Housekeeping sweep for the worker: end idle and absolute-expired sessions.

        Expiry is enforced on read as well, so this is tidiness rather than the only
        line of defence — a session that no request ever touches again still needs to
        stop showing up in the user's device list.
        """
        now = moment if moment is not None else utc_now()
        return await self._sessions.mark_expired(
            moment=now, idle_ttl=self._settings.session_idle_ttl
        )

    # --- authenticating ---------------------------------------------------
    async def authenticate(
        self,
        *,
        access_token: str,
        moment: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> AuthenticatedRequest:
        """Validate an access token against the session and account it refers to.

        A cryptographically valid token is necessary and not sufficient: the session
        must still be ACTIVE and inside both of its deadlines, and the account must
        still be ACTIVE. A token points at authority; it is not authority.
        """
        now = moment if moment is not None else utc_now()
        claims: TokenClaims = self._tokens.decode(access_token, expected_type=TokenType.ACCESS)
        session_id = claims.session_id
        if session_id is None:
            # An access token with no session is not something this platform issues.
            # Treat it as a forgery attempt rather than as an authenticated caller
            # with an unusual token.
            await self._audit_rejection(
                reason="access token carries no session id",
                user_id=claims.subject,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        row = await self._sessions.get_by_id(session_id)
        if row is None or not row.is_active:
            await self._audit_rejection(
                reason="access token refers to a session that is not active",
                resource_id=session_id,
                user_id=claims.subject,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        if row.is_expired_at(now, idle_ttl=self._settings.session_idle_ttl):
            await self._sessions.expire(row, moment=now)
            await self._audit_rejection(
                reason="session expired",
                resource_id=row.id,
                user_id=claims.subject,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise TokenExpiredError

        user = await self._users.get_by_id(claims.subject)
        if user is None or not user.is_active:
            await self._sessions.revoke(row, moment=now, reason="USER_INACTIVE")
            await self._audit_rejection(
                reason="account is not active",
                resource_id=row.id,
                user_id=claims.subject,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        if user.password_changed_at is not None and row.created_at < user.password_changed_at:
            await self._sessions.revoke(row, moment=now, reason="PASSWORD_CHANGED")
            await self._audit_rejection(
                reason="session predates a password change",
                resource_id=row.id,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            raise SessionRevokedError

        await self._touch_if_stale(row, moment=now)
        return AuthenticatedRequest(user=user, session=row, claims=claims)

    async def _touch_if_stale(self, row: UserSession, *, moment: datetime) -> None:
        """Record activity at most once a minute per session."""
        if (moment - row.last_seen_at).total_seconds() >= _TOUCH_GRANULARITY_SECONDS:
            await self._sessions.touch(row, moment=moment)

    def permissions_for(self, request: AuthenticatedRequest) -> frozenset[Permission]:
        """The caller's effective permissions, from their *current* role.

        Computed per request rather than cached on the session, so demoting a user
        takes effect on their next request instead of when their token next expires
        (§43).
        """
        return permissions_for(request.user.role)

    # --- audit helper -----------------------------------------------------
    async def _audit_rejection(
        self,
        *,
        reason: str,
        resource_id: UUID | None = None,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Record a rejection. No credential and no token ever reaches the entry."""
        await self._audit.record(
            action="AUTH_SESSION_REJECTED",
            resource_type="user_session" if resource_id is not None else "auth",
            resource_id=resource_id,
            actor=AuditActor(
                actor_type=ActorType.USER if user_id is not None else ActorType.ANONYMOUS,
                actor_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
            ),
            reason=reason,
            result=AuditResult.FAILURE,
            request_id=request_id,
        )
