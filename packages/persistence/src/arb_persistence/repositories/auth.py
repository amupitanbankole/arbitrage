"""Authentication persistence (§59-§62, §114).

Four repositories over the four tables from migration ``0002``. Three rules shape
every method here.

**Digests in, never plaintext.** Every credential parameter is named ``*_hash`` and
receives an already-computed SHA-256 digest. Hashing happens once, in the service
that generated the token, so there is no second place that could hash it
differently — and no path by which a plaintext refresh token reaches the
persistence layer and from there a query log, an error message or a slow-query
report (§12, §127).

**Lookups return terminated rows too.** :meth:`SessionRepository.get_by_refresh_token`
and :meth:`AuthTokenRepository.get_by_token` deliberately return ``ROTATED``,
``REVOKED``, expired and consumed rows rather than filtering them out. A caller
that only ever sees live rows cannot distinguish "this token was already exchanged"
— which is proof of replay and means revoking the whole family — from "I have never
seen this token", which means a typo or a scan. Collapsing those two into one
``None`` is how token reuse goes undetected (§60). Deciding what each case *means*,
and what to tell the client, is the service's job, not the query's.

**Bulk operations do not refresh loaded instances.** The ``revoke_*`` methods issue
one ``UPDATE`` with ``synchronize_session=False``: revoking every session for a user
must not load them all first. A caller holding entities from before such a call must
re-fetch them rather than trust the in-memory state (§63).

No method here commits, but **every mutator flushes before returning**. The session
factory runs with ``autoflush=False``, so a row that was merely staged is invisible
to the next query in the same unit of work: ``create()`` followed by
``email_is_taken()`` would report the address as free. Flushing inside the mutator
makes "the repository gave it back, therefore it is persisted and queryable" a
contract rather than a thing each caller has to remember.

Transaction boundaries still belong to the caller through
:func:`arb_core.db.Database.unit_of_work`, so that a login can write the session,
clear the failure counters and append the audit entry as one atomic operation — a
session that exists without its audit entry is an incident nobody can reconstruct.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import Result, and_, delete, func, or_, select, update

from arb_core.identifiers import new_id, normalize_email
from arb_core.security.rbac import Role, default_role
from arb_core.security.tokens import hash_opaque_token
from arb_persistence.models.auth import AuthToken, MfaRecoveryCode, User, UserSession
from arb_persistence.models.enums import (
    AuthTokenPurpose,
    SessionStatus,
    UserStatus,
)
from arb_persistence.repositories.base import PaginatedResult, Repository

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime, timedelta
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.pagination import PaginationParams

__all__ = [
    "AuthTokenRepository",
    "MfaRecoveryCodeRepository",
    "SessionRepository",
    "UserRepository",
]

#: Terminal session states. Rows in these are candidates for retention purge; rows
#: in ``ROTATED`` are kept only as long as replay detection needs them.
_TERMINAL_SESSION_STATUSES: tuple[SessionStatus, ...] = (
    SessionStatus.ROTATED,
    SessionStatus.REVOKED,
    SessionStatus.EXPIRED,
)


def _rowcount(result: Result[Any]) -> int:
    """How many rows a bulk ``UPDATE`` or ``DELETE`` touched.

    ``AsyncSession.execute`` is typed as returning ``Result``, while ``rowcount``
    lives on the ``CursorResult`` that DML statements actually produce at runtime.
    Narrowing once here is honest about that gap and beats repeating a cast at every
    call site — and each of these counts is returned to a caller that reports "N
    sessions were revoked", so a silently wrong zero would be a lie in an API
    response.
    """
    return int(getattr(result, "rowcount", 0) or 0)


class UserRepository(Repository[User]):
    """Account lookup and creation.

    Every email path goes through :func:`arb_core.identifiers.normalize_email`,
    including the lookup. Normalising on write and not on read is how an account
    becomes unreachable by the address its owner types.
    """

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, User)

    async def create(
        self,
        *,
        email: str,
        password_hash: str,
        role: Role | None = None,
        status: UserStatus = UserStatus.PENDING_VERIFICATION,
        display_name: str | None = None,
    ) -> User:
        """Create and persist an account row.

        ``role`` defaults to a customer role: nothing about the creation path may
        confer platform authority, so an administrator account has to be created by
        saying so explicitly (§41).
        """
        user = self.add(
            User(
                id=new_id(),
                email=normalize_email(email),
                password_hash=password_hash,
                role=role if role is not None else default_role(),
                status=status,
                display_name=display_name.strip() if display_name else None,
            )
        )
        await self.flush()
        return user

    async def get_by_email(self, email: str) -> User | None:
        """Find an account by address, in canonical form."""
        statement = select(User).where(User.email == normalize_email(email))
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def email_is_taken(self, email: str) -> bool:
        """Whether an address already has an account.

        Counts rather than fetches, because the caller needs a boolean and a count
        never materialises a row containing somebody's password hash.

        The answer is used to decide what to *do*, not what to *say*: registration
        may report the collision, while password reset must not (§59, §71).
        """
        return await self.count(User.email == normalize_email(email)) > 0

    async def search(
        self,
        params: PaginationParams,
        *,
        query: str | None = None,
        status: UserStatus | None = None,
    ) -> PaginatedResult[User]:
        """Administrator account listing (§45).

        Soft-deleted accounts are excluded: they are tombstones, and an operator
        searching for a live account should not have to filter them out by hand.
        """
        criteria: list[Any] = [User.deleted_at.is_(None)]
        if status is not None:
            criteria.append(User.status == status)
        if query and query.strip():
            # Both LIKE wildcards are escaped, so searching for "a_b" finds the
            # account whose address contains a literal underscore rather than every
            # address with any character there. Built outside the f-string: a
            # backslash inside an f-string expression is a SyntaxError before 3.12.
            escaped = (
                normalize_email(query).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            criteria.append(User.email.ilike(f"%{escaped}%", escape="\\"))
        return await self.paginate(
            params, criteria=tuple(criteria), order_by=(User.created_at.desc(),)
        )

    async def count_by_status(self, status: UserStatus) -> int:
        """How many accounts are in one state, for the admin overview (§45)."""
        return await self.count(and_(User.status == status, User.deleted_at.is_(None)))

    async def list_locked(self, *, moment: datetime) -> Sequence[User]:
        """Accounts currently locked out, for the security centre (§62)."""
        statement = (
            select(User)
            .where(and_(User.locked_until.is_not(None), User.locked_until > moment))
            .order_by(User.locked_until.desc())
        )
        result = await self._session.execute(statement)
        return list(result.scalars().all())


class SessionRepository(Repository[UserSession]):
    """Refresh-token sessions: creation, rotation, revocation and replay response."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, UserSession)

    async def start(
        self,
        *,
        user_id: UUID,
        refresh_token_hash: str,
        expires_at: datetime,
        moment: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
        mfa_completed_at: datetime | None = None,
    ) -> UserSession:
        """Open a new session and a new token family.

        The session id is generated here rather than left to the column default,
        because a root session's ``family_id`` is its own id — and that has to be
        known before the row is flushed.
        """
        session_id = new_id()
        created = self.add(
            UserSession(
                id=session_id,
                user_id=user_id,
                family_id=session_id,
                parent_session_id=None,
                refresh_token_hash=refresh_token_hash,
                status=SessionStatus.ACTIVE,
                expires_at=expires_at,
                last_seen_at=moment,
                mfa_completed_at=mfa_completed_at,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        await self.flush()
        return created

    async def rotate(
        self,
        previous: UserSession,
        *,
        refresh_token_hash: str,
        expires_at: datetime,
        moment: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> UserSession:
        """Exchange ``previous`` for a child session in the same family (§60).

        The parent moves to ``ROTATED`` and is *kept*, which is what makes a later
        presentation of its token recognisable as replay. The absolute expiry is
        inherited rather than extended: rotation must not become a way to keep a
        session alive forever, so ``expires_at`` is the caller's choice and a
        correct implementation passes the family's original deadline.
        """
        previous.mark_rotated(moment=moment)
        child = self.add(
            UserSession(
                id=new_id(),
                user_id=previous.user_id,
                family_id=previous.family_id,
                parent_session_id=previous.id,
                refresh_token_hash=refresh_token_hash,
                status=SessionStatus.ACTIVE,
                expires_at=expires_at,
                last_seen_at=moment,
                mfa_completed_at=previous.mfa_completed_at,
                ip_address=ip_address or previous.ip_address,
                user_agent=user_agent or previous.user_agent,
            )
        )
        await self.flush()
        return child

    async def get_by_refresh_token(self, token: str) -> UserSession | None:
        """Find the session a presented refresh token belongs to.

        Returns terminated rows as well as live ones — see the module docstring. The
        caller must check :attr:`UserSession.is_active` and treat a ``ROTATED`` row
        as replay evidence.
        """
        statement = select(UserSession).where(
            UserSession.refresh_token_hash == hash_opaque_token(token)
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def get_active_by_refresh_token(
        self, token: str, *, moment: datetime, idle_ttl: timedelta
    ) -> UserSession | None:
        """The session for a token that is live *right now*, or ``None``.

        Convenience for the refresh path when replay handling is done separately.
        Both lifetimes are checked, because a session that is idle-expired is not
        usable and must not be treated as one.
        """
        statement = select(UserSession).where(
            and_(
                UserSession.refresh_token_hash == hash_opaque_token(token),
                UserSession.status == SessionStatus.ACTIVE,
                UserSession.expires_at > moment,
                UserSession.last_seen_at > moment - idle_ttl,
            )
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def list_for_user(
        self, user_id: UUID, *, moment: datetime, idle_ttl: timedelta
    ) -> Sequence[UserSession]:
        """The account holder's currently signed-in devices (§68).

        Only live sessions: showing somebody a list of long-dead sessions makes the
        page useless for the one question it exists to answer, which is "is anything
        signed in that should not be?".
        """
        statement = (
            select(UserSession)
            .where(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.status == SessionStatus.ACTIVE,
                    UserSession.expires_at > moment,
                    UserSession.last_seen_at > moment - idle_ttl,
                )
            )
            .order_by(UserSession.last_seen_at.desc())
        )
        result = await self._session.execute(statement)
        return list(result.scalars().all())

    async def count_active_for_user(
        self, user_id: UUID, *, moment: datetime, idle_ttl: timedelta
    ) -> int:
        """How many devices are signed in, for a device-limit check (§61)."""
        statement = (
            select(func.count())
            .select_from(UserSession)
            .where(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.status == SessionStatus.ACTIVE,
                    UserSession.expires_at > moment,
                    UserSession.last_seen_at > moment - idle_ttl,
                )
            )
        )
        result = await self._session.execute(statement)
        return int(result.scalar_one())

    async def revoke(self, session: UserSession, *, moment: datetime, reason: str) -> UserSession:
        """End one session. Idempotent, and keeps the first reason recorded."""
        session.revoke(moment=moment, reason=reason)
        await self.flush()
        return session

    async def expire(self, session: UserSession, *, moment: datetime) -> UserSession:
        """Mark one session expired, having found it already past a deadline.

        Separate from :meth:`revoke` because the two mean different things to an
        investigation: EXPIRED is a clock that ran out, REVOKED is an actor ending
        access, and a security report that cannot tell them apart cannot tell a
        lapsed session from a stolen one.
        """
        session.mark_expired(moment=moment)
        await self.flush()
        return session

    async def touch(self, session: UserSession, *, moment: datetime) -> UserSession:
        """Record activity, which is what keeps a session inside its idle window."""
        session.touch(moment=moment)
        await self.flush()
        return session

    async def revoke_family(self, family_id: UUID, *, moment: datetime, reason: str) -> int:
        """End every session descended from one sign-in.

        This is the response to token replay: the attacker may hold the newest token
        and the legitimate user the oldest, and there is no way to tell which from
        the database, so the only safe answer is to end the lot and make both
        parties sign in again (§60).

        Only ``ACTIVE`` rows are touched. A ``ROTATED`` row is already unusable —
        every lookup that admits a session requires ``ACTIVE`` — and rewriting it to
        ``REVOKED`` would erase the distinction that says "this token was consumed by
        a legitimate rotation at this moment". That record is the evidence an
        investigation reads to tell which link in the chain was stolen, so revoking
        the family must preserve it rather than flatten it.
        """
        return await self._bulk_revoke(
            and_(
                UserSession.family_id == family_id,
                UserSession.status == SessionStatus.ACTIVE,
            ),
            moment=moment,
            reason=reason,
        )

    async def revoke_all_for_user(
        self,
        user_id: UUID,
        *,
        moment: datetime,
        reason: str,
        except_session_id: UUID | None = None,
    ) -> int:
        """Sign a user out everywhere.

        ``except_session_id`` keeps the caller's own session alive, which is what
        makes "sign out all *other* devices" possible from inside a session — the
        common case after a password change, where the person making the change
        should not be logged out mid-request.
        """
        criteria: list[Any] = [
            UserSession.user_id == user_id,
            UserSession.status == SessionStatus.ACTIVE,
        ]
        if except_session_id is not None:
            criteria.append(UserSession.id != except_session_id)
        return await self._bulk_revoke(and_(*criteria), moment=moment, reason=reason)

    async def revoke_created_before(
        self, user_id: UUID, *, before: datetime, moment: datetime, reason: str
    ) -> int:
        """End sessions that predate a credential change (§59).

        A session established before the password changed was authenticated with a
        credential that may have been the attacker's, so it cannot be trusted
        afterwards. Timestamps are compared against ``created_at`` and not
        ``last_seen_at``: an attacker's session stays recent by being used.
        """
        return await self._bulk_revoke(
            and_(
                UserSession.user_id == user_id,
                UserSession.status == SessionStatus.ACTIVE,
                UserSession.created_at < before,
            ),
            moment=moment,
            reason=reason,
        )

    async def _bulk_revoke(self, criteria: Any, *, moment: datetime, reason: str) -> int:
        """One ``UPDATE`` for many rows; returns how many changed."""
        statement = (
            update(UserSession)
            .where(criteria)
            .values(status=SessionStatus.REVOKED, revoked_at=moment, revoke_reason=reason)
            .execution_options(synchronize_session=False)
        )
        result = await self._session.execute(statement)
        return _rowcount(result)

    async def mark_expired(self, *, moment: datetime, idle_ttl: timedelta) -> int:
        """Move sessions past either lifetime to ``EXPIRED``.

        Expiry is enforced on read as well — every lookup above checks both
        deadlines — so this is not what makes an expired session unusable. It exists
        so the stored state tells the truth: an operator counting active sessions, or
        a retention sweep deciding what to purge, must not have to recompute
        lifetimes to find out what is really live.
        """
        statement = (
            update(UserSession)
            .where(
                and_(
                    UserSession.status == SessionStatus.ACTIVE,
                    or_(
                        UserSession.expires_at <= moment,
                        UserSession.last_seen_at <= moment - idle_ttl,
                    ),
                )
            )
            .values(status=SessionStatus.EXPIRED, revoked_at=moment, revoke_reason="EXPIRED")
            .execution_options(synchronize_session=False)
        )
        result = await self._session.execute(statement)
        return _rowcount(result)

    async def purge_terminated_before(self, cutoff: datetime) -> int:
        """Delete terminal sessions whose retention window has passed.

        ``ROTATED`` rows are evidence and are kept until ``cutoff``; after that they
        are of no use to an investigation and the table would otherwise grow without
        bound. Live sessions are never touched, whatever their age (§83).
        """
        statement = delete(UserSession).where(
            and_(
                UserSession.status.in_(list(_TERMINAL_SESSION_STATUSES)),
                UserSession.updated_at < cutoff,
            )
        )
        result = await self._session.execute(statement)
        return _rowcount(result)


class AuthTokenRepository(Repository[AuthToken]):
    """Single-use emailed tokens: verification and password reset (§59, §60)."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, AuthToken)

    async def issue(
        self,
        *,
        user_id: UUID,
        purpose: AuthTokenPurpose,
        token_hash: str,
        expires_at: datetime,
        moment: datetime,
        requested_ip: str | None = None,
    ) -> tuple[AuthToken, int]:
        """Store a new token and invalidate the outstanding ones for that purpose.

        Returns the row and how many previous tokens were removed.

        Superseding matters: if two reset tokens for one account are both valid, the
        older one is a credential nobody is watching, and "I clicked the link from
        the earlier email" becomes a way to reset a password with a token the
        account holder has forgotten they requested. Only the newest is usable.

        The previous rows are deleted rather than marked, because ``consumed_at``
        means "redeemed" and overloading it would make an unused token
        indistinguishable from a used one. The issuance itself is recorded in
        ``audit_logs``, which is the system of record for who asked and when (§53).
        """
        superseded = await self._session.execute(
            delete(AuthToken).where(
                and_(
                    AuthToken.user_id == user_id,
                    AuthToken.purpose == purpose,
                    AuthToken.consumed_at.is_(None),
                )
            )
        )
        token = self.add(
            AuthToken(
                id=new_id(),
                user_id=user_id,
                purpose=purpose,
                token_hash=token_hash,
                expires_at=expires_at,
                created_at=moment,
                requested_ip=requested_ip,
            )
        )
        await self.flush()
        return token, _rowcount(superseded)

    async def get_by_token(self, token: str, *, purpose: AuthTokenPurpose) -> AuthToken | None:
        """Find a token by its plaintext value, scoped to one purpose.

        The purpose is part of the query and not a check afterwards: a
        password-reset token must be unfindable by the email-verification path, and
        scoping the lookup makes that structurally true rather than dependent on a
        caller remembering to compare two fields (§59).

        Consumed and expired rows are returned, so the caller can tell a replayed
        token from an invented one and audit the difference.
        """
        statement = select(AuthToken).where(
            and_(
                AuthToken.token_hash == hash_opaque_token(token),
                AuthToken.purpose == purpose,
            )
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def consume(
        self, token: AuthToken, *, moment: datetime, ip_address: str | None = None
    ) -> bool:
        """Mark a token used. Returns ``False`` if it was already consumed.

        The return value is the point: a caller that ignores it will happily reset a
        password twice on a double submission, and the second reset may be somebody
        else's request arriving first.
        """
        if token.is_consumed:
            return False
        token.consume(moment=moment, ip_address=ip_address)
        await self.flush()
        return True

    async def list_for_user(self, user_id: UUID) -> Sequence[AuthToken]:
        """Outstanding and recent tokens for one account, for the security view."""
        statement = (
            select(AuthToken)
            .where(AuthToken.user_id == user_id)
            .order_by(AuthToken.created_at.desc())
        )
        result = await self._session.execute(statement)
        return list(result.scalars().all())

    async def purge_expired(self, *, moment: datetime) -> int:
        """Delete tokens whose expiry has passed.

        They can never be redeemed again, so keeping them only grows the table. What
        happened with them is already in ``audit_logs`` (§83).
        """
        result = await self._session.execute(
            delete(AuthToken).where(AuthToken.expires_at <= moment)
        )
        return _rowcount(result)


class MfaRecoveryCodeRepository(Repository[MfaRecoveryCode]):
    """Hashed single-use recovery codes (§59)."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, MfaRecoveryCode)

    async def store_all(
        self, *, user_id: UUID, code_hashes: Sequence[str], moment: datetime
    ) -> list[MfaRecoveryCode]:
        """Insert a fresh set of codes, replacing any previous set.

        Replacement rather than appending: codes from an earlier enrollment were
        shown on a screen that may no longer be under the account holder's control,
        and a set nobody can enumerate is a set nobody can trust. The previous rows
        are deleted first so the unique ``(user_id, code_hash)`` constraint cannot be
        tripped by a re-enrollment that happens to repeat a code.

        The delete must be awaited. An un-awaited ``AsyncSession.execute`` returns a
        coroutine that never runs, which here would mean re-enrolling MFA silently
        left every previous recovery code valid — the old set keeps working and
        nothing in the response says so.
        """
        await self._session.execute(
            delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id)
        )
        rows = [
            MfaRecoveryCode(id=new_id(), user_id=user_id, code_hash=code_hash, created_at=moment)
            for code_hash in code_hashes
        ]
        self.add_all(rows)
        await self.flush()
        return rows

    async def find_usable(self, *, user_id: UUID, code_hash: str) -> MfaRecoveryCode | None:
        """An unconsumed code matching this digest, for one account.

        Scoped to the user: a recovery code is only meaningful against the account it
        was issued for, and a global lookup would let a code stolen from one account
        be tried against another.
        """
        statement = select(MfaRecoveryCode).where(
            and_(
                MfaRecoveryCode.user_id == user_id,
                MfaRecoveryCode.code_hash == code_hash,
                MfaRecoveryCode.consumed_at.is_(None),
            )
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def consume(
        self, code: MfaRecoveryCode, *, moment: datetime, ip_address: str | None = None
    ) -> bool:
        """Use a code once. ``False`` means it had already been used."""
        if not code.consume(moment=moment, ip_address=ip_address):
            return False
        await self.flush()
        return True

    async def remaining_count(self, user_id: UUID) -> int:
        """How many unused codes are left, to warn before the last one (§68)."""
        statement = (
            select(func.count())
            .select_from(MfaRecoveryCode)
            .where(
                and_(
                    MfaRecoveryCode.user_id == user_id,
                    MfaRecoveryCode.consumed_at.is_(None),
                )
            )
        )
        result = await self._session.execute(statement)
        return int(result.scalar_one())

    async def delete_for_user(self, user_id: UUID) -> int:
        """Remove every code, when MFA is disabled or reset (§59)."""
        result = await self._session.execute(
            delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id)
        )
        return _rowcount(result)
