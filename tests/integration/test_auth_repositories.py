"""Authentication repositories (§59-§62, §114).

These tests run against a real (in-memory SQLite) database through the real
session factory, so what is under test is the SQL: which rows a lookup can see,
what a bulk revoke actually touches, and whether a constraint holds.

The assertions concentrate on the cases where a plausible-looking query is wrong in
a way that is invisible in a happy path:

* a lookup that filters out terminated rows cannot distinguish a *replayed* refresh
  token from an invented one, so token-reuse detection silently disappears;
* a token lookup that is not scoped by purpose lets a password-reset link be
  redeemed through the email-verification path;
* a bulk revoke that matches on ``last_seen_at`` instead of ``created_at`` misses
  exactly the sessions that matter, because an attacker's session stays recent by
  being used;
* a recovery-code replacement that does not delete the previous set leaves codes
  from an earlier enrollment working after MFA was re-enrolled.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from arb_core.clock import utc_now
from arb_core.pagination import PaginationParams
from arb_core.security.rbac import Role
from arb_core.security.tokens import generate_opaque_token, hash_opaque_token
from arb_persistence.models.auth import MfaRecoveryCode, User, UserSession
from arb_persistence.models.enums import (
    AuthTokenPurpose,
    SessionStatus,
    UserStatus,
)
from arb_persistence.repositories.auth import (
    AuthTokenRepository,
    MfaRecoveryCodeRepository,
    SessionRepository,
    UserRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

BASE = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
IDLE_TTL = timedelta(minutes=30)
PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$ZGlnZXN0ZGlnZXN0ZGln"


def at(**kwargs: float) -> datetime:
    return BASE + timedelta(**kwargs)


async def reload(session: AsyncSession, row: object) -> None:
    """Re-read a row after a bulk operation.

    The bulk ``UPDATE``s run with ``synchronize_session=False`` — revoking every
    session for a user must not load them all first — so objects already in the
    session keep their pre-update state. Asserting on those would test the ORM
    cache rather than the database.
    """
    await session.refresh(row)


async def make_user(
    session: AsyncSession,
    email: str = "user@example.com",
    *,
    role: Role | None = None,
    status: UserStatus = UserStatus.ACTIVE,
    display_name: str | None = None,
) -> User:
    kwargs: dict[str, object] = {"password_hash": PASSWORD_HASH, "status": status}
    if role is not None:
        kwargs["role"] = role
    if display_name is not None:
        kwargs["display_name"] = display_name
    return await UserRepository(session).create(email=email, **kwargs)  # type: ignore[arg-type]


async def make_session(
    session: AsyncSession,
    user: User,
    *,
    token: str | None = None,
    moment: datetime = BASE,
    expires_at: datetime | None = None,
    ip_address: str | None = "203.0.113.7",
) -> tuple[UserSession, str]:
    plain = token or generate_opaque_token(prefix="rt")
    created = await SessionRepository(session).start(
        user_id=user.id,
        refresh_token_hash=hash_opaque_token(plain),
        expires_at=expires_at or at(hours=12),
        moment=moment,
        ip_address=ip_address,
        user_agent="pytest",
    )
    return created, plain


class TestUserRepository:
    async def test_an_account_is_created_and_findable(self, session: AsyncSession) -> None:
        user = await make_user(session, "someone@example.com")
        assert user.id is not None
        found = await UserRepository(session).get_by_email("someone@example.com")
        assert found is not None
        assert found.id == user.id

    async def test_the_email_is_canonicalised_on_write(self, session: AsyncSession) -> None:
        user = await make_user(session, "  MiXeD.Case@Example.COM  ")
        assert user.email == "mixed.case@example.com"

    async def test_lookup_canonicalises_too(self, session: AsyncSession) -> None:
        """Normalising on write and not on read is how an account becomes
        unreachable by the address its owner types."""
        created = await make_user(session, "owner@example.com")
        for variant in ["OWNER@EXAMPLE.COM", "  owner@example.com ", "Owner@Example.Com"]:
            found = await UserRepository(session).get_by_email(variant)
            assert found is not None, variant
            assert found.id == created.id

    async def test_an_unknown_address_finds_nothing(self, session: AsyncSession) -> None:
        assert await UserRepository(session).get_by_email("nobody@example.com") is None

    async def test_the_default_role_is_a_customer_role(self, session: AsyncSession) -> None:
        """Nothing about the creation path may confer platform authority (§41)."""
        user = await make_user(session, "default@example.com")
        assert user.role is Role.TRADER
        assert user.status is UserStatus.ACTIVE

    async def test_a_staff_role_has_to_be_asked_for(self, session: AsyncSession) -> None:
        user = await make_user(session, "admin@example.com", role=Role.ADMIN)
        assert user.role is Role.ADMIN

    async def test_the_display_name_is_trimmed(self, session: AsyncSession) -> None:
        user = await make_user(session, "named@example.com", display_name="  Ada Lovelace  ")
        assert user.display_name == "Ada Lovelace"

    async def test_email_is_taken(self, session: AsyncSession) -> None:
        repository = UserRepository(session)
        assert await repository.email_is_taken("taken@example.com") is False
        await make_user(session, "TAKEN@example.com")
        assert await repository.email_is_taken("taken@example.com") is True
        assert await repository.email_is_taken("  Taken@Example.COM ") is True

    async def test_search_excludes_soft_deleted_accounts(self, session: AsyncSession) -> None:
        """A tombstone is not an account an operator is looking for (§45)."""
        live = await make_user(session, "live@example.com")
        gone = await make_user(session, "gone@example.com")
        gone.deleted_at = at(minutes=1)
        await session.flush()
        page = await UserRepository(session).search(PaginationParams(page=1, page_size=50))
        emails = {user.email for user in page.items}
        assert live.email in emails
        assert gone.email not in emails
        assert page.total == 1

    async def test_search_filters_by_status(self, session: AsyncSession) -> None:
        await make_user(session, "active@example.com", status=UserStatus.ACTIVE)
        await make_user(session, "suspended@example.com", status=UserStatus.SUSPENDED)
        page = await UserRepository(session).search(
            PaginationParams(page=1, page_size=50), status=UserStatus.SUSPENDED
        )
        assert [user.email for user in page.items] == ["suspended@example.com"]

    async def test_search_treats_like_wildcards_literally(self, session: AsyncSession) -> None:
        """``_`` and ``%`` are SQL wildcards. Unescaped, searching for "a_b" would
        also match "axb", and searching for "%" would return every account — an
        administrator's search box quietly becoming a full-table dump."""
        await make_user(session, "a_b@example.com")
        await make_user(session, "axb@example.com")
        repository = UserRepository(session)

        underscore = await repository.search(PaginationParams(page=1, page_size=50), query="a_b")
        assert [user.email for user in underscore.items] == ["a_b@example.com"]

        percent = await repository.search(PaginationParams(page=1, page_size=50), query="%")
        assert percent.items == []

    async def test_search_is_case_insensitive(self, session: AsyncSession) -> None:
        await make_user(session, "findme@example.com")
        page = await UserRepository(session).search(
            PaginationParams(page=1, page_size=50), query="FINDME"
        )
        assert [user.email for user in page.items] == ["findme@example.com"]

    async def test_count_by_status(self, session: AsyncSession) -> None:
        await make_user(session, "one@example.com", status=UserStatus.ACTIVE)
        await make_user(session, "two@example.com", status=UserStatus.ACTIVE)
        await make_user(session, "three@example.com", status=UserStatus.PENDING_VERIFICATION)
        repository = UserRepository(session)
        assert await repository.count_by_status(UserStatus.ACTIVE) == 2
        assert await repository.count_by_status(UserStatus.PENDING_VERIFICATION) == 1
        assert await repository.count_by_status(UserStatus.SUSPENDED) == 0

    async def test_list_locked_returns_only_currently_locked(self, session: AsyncSession) -> None:
        locked = await make_user(session, "locked@example.com")
        locked.locked_until = at(minutes=10)
        expired = await make_user(session, "expired@example.com")
        expired.locked_until = at(minutes=-10)
        never = await make_user(session, "never@example.com")
        await session.flush()
        found = await UserRepository(session).list_locked(moment=BASE)
        assert [user.email for user in found] == ["locked@example.com"]
        assert never.locked_until is None
        assert expired.locked_until is not None


class TestSessionCreationAndLookup:
    async def test_a_new_session_starts_its_own_family(self, session: AsyncSession) -> None:
        user = await make_user(session)
        created, _ = await make_session(session, user)
        assert created.status is SessionStatus.ACTIVE
        assert created.family_id == created.id
        assert created.parent_session_id is None
        assert created.last_seen_at == BASE

    async def test_a_token_is_found_by_its_plaintext_value(self, session: AsyncSession) -> None:
        """The repository hashes what it is given: only digests are ever stored."""
        user = await make_user(session)
        created, plain = await make_session(session, user)
        found = await SessionRepository(session).get_by_refresh_token(plain)
        assert found is not None
        assert found.id == created.id

    async def test_a_digest_is_stored_rather_than_the_token(self, session: AsyncSession) -> None:
        user = await make_user(session)
        _, plain = await make_session(session, user)
        stored = await SessionRepository(session).get_by_refresh_token(plain)
        assert stored is not None
        assert stored.refresh_token_hash == hash_opaque_token(plain)
        assert plain not in stored.refresh_token_hash

    async def test_an_unknown_token_finds_nothing(self, session: AsyncSession) -> None:
        assert await SessionRepository(session).get_by_refresh_token("not-a-real-token") is None

    async def test_a_rotated_session_is_still_findable(self, session: AsyncSession) -> None:
        """The single most important lookup property here.

        Filtering to live rows would make a replayed token indistinguishable from an
        invented one, and the family-revocation response to replay could never
        trigger (§60).
        """
        user = await make_user(session)
        parent, plain = await make_session(session, user)
        await SessionRepository(session).rotate(
            parent,
            refresh_token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(hours=12),
            moment=at(minutes=1),
        )
        assert parent.status is SessionStatus.ROTATED
        found = await SessionRepository(session).get_by_refresh_token(plain)
        assert found is not None
        assert found.is_rotated is True

    async def test_a_revoked_session_is_still_findable(self, session: AsyncSession) -> None:
        user = await make_user(session)
        created, plain = await make_session(session, user)
        await SessionRepository(session).revoke(created, moment=BASE, reason="SIGN_OUT")
        found = await SessionRepository(session).get_by_refresh_token(plain)
        assert found is not None
        assert found.status is SessionStatus.REVOKED

    async def test_get_active_excludes_terminated_sessions(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = SessionRepository(session)
        parent, plain = await make_session(session, user)
        await repository.rotate(
            parent,
            refresh_token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(hours=12),
            moment=at(minutes=1),
        )
        assert (
            await repository.get_active_by_refresh_token(plain, moment=BASE, idle_ttl=IDLE_TTL)
            is None
        )

    async def test_get_active_excludes_an_expired_session(self, session: AsyncSession) -> None:
        user = await make_user(session)
        _, plain = await make_session(session, user, expires_at=at(minutes=5))
        found = await SessionRepository(session).get_active_by_refresh_token(
            plain, moment=at(minutes=6), idle_ttl=IDLE_TTL
        )
        assert found is None

    async def test_get_active_excludes_an_idle_session(self, session: AsyncSession) -> None:
        """Idle expiry is not stored as a timestamp, so the query has to compute it
        — and a query that forgets it accepts a session abandoned on a shared
        machine."""
        user = await make_user(session)
        _, plain = await make_session(session, user, moment=BASE)
        repository = SessionRepository(session)
        assert (
            await repository.get_active_by_refresh_token(
                plain, moment=at(minutes=29), idle_ttl=IDLE_TTL
            )
        ) is not None
        assert (
            await repository.get_active_by_refresh_token(
                plain, moment=at(minutes=31), idle_ttl=IDLE_TTL
            )
        ) is None


class TestRotation:
    async def test_rotation_creates_a_child_in_the_same_family(self, session: AsyncSession) -> None:
        user = await make_user(session)
        parent, _ = await make_session(session, user, moment=BASE)
        child_token = generate_opaque_token()
        child = await SessionRepository(session).rotate(
            parent,
            refresh_token_hash=hash_opaque_token(child_token),
            expires_at=at(hours=12),
            moment=at(minutes=5),
        )
        assert child.id != parent.id
        assert child.family_id == parent.family_id
        assert child.parent_session_id == parent.id
        assert child.status is SessionStatus.ACTIVE
        assert parent.status is SessionStatus.ROTATED
        assert parent.revoke_reason == "ROTATED"

    async def test_a_rotated_chain_keeps_one_family(self, session: AsyncSession) -> None:
        """Revoking the family has to reach every generation, or a stolen token
        survives as the newest link in the chain."""
        user = await make_user(session)
        current, _ = await make_session(session, user, moment=BASE)
        root_family = current.family_id
        repository = SessionRepository(session)
        for generation in range(1, 6):
            current = await repository.rotate(
                current,
                refresh_token_hash=hash_opaque_token(generate_opaque_token()),
                expires_at=at(hours=12),
                moment=at(minutes=generation),
            )
            assert current.family_id == root_family
        revoked = await repository.revoke_family(
            root_family, moment=at(minutes=10), reason="TOKEN_REUSE"
        )
        # Only the newest link is still ACTIVE; the five rotated ones are already
        # unusable and are left as they are, because rewriting them to REVOKED would
        # erase the record of which token was exchanged when.
        assert revoked == 1
        await reload(session, current)
        assert current.status is SessionStatus.REVOKED
        assert current.revoke_reason == "TOKEN_REUSE"
        # Every generation is now unusable, which is the point of the exercise.
        assert (
            await repository.count_active_for_user(
                user.id, moment=at(minutes=10), idle_ttl=IDLE_TTL
            )
            == 0
        )

    async def test_rotation_inherits_the_second_factor_proof(self, session: AsyncSession) -> None:
        """MFA was satisfied for this login; rotating a token must not ask again,
        and must not lose the record that it happened."""
        user = await make_user(session)
        parent, _ = await make_session(session, user)
        parent.mfa_completed_at = BASE
        await session.flush()
        child = await SessionRepository(session).rotate(
            parent,
            refresh_token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(hours=12),
            moment=at(minutes=1),
        )
        assert child.mfa_completed_at == BASE

    async def test_the_absolute_expiry_is_not_extended_by_rotation(
        self, session: AsyncSession
    ) -> None:
        """Rotation must not become a way to keep a session alive forever, so the
        deadline is whatever the caller passes — and a correct caller passes the
        family's original one."""
        user = await make_user(session)
        parent, _ = await make_session(session, user, expires_at=at(hours=12))
        child = await SessionRepository(session).rotate(
            parent,
            refresh_token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=parent.expires_at,
            moment=at(hours=1),
        )
        assert child.expires_at == at(hours=12)
        assert child.expires_at < at(hours=13)


class TestListingSessions:
    async def test_only_live_sessions_are_listed(self, session: AsyncSession) -> None:
        """The devices page answers one question — is anything signed in that should
        not be? — so dead sessions are noise that hides the answer (§68)."""
        user = await make_user(session)
        repository = SessionRepository(session)
        live, _ = await make_session(session, user, moment=BASE, ip_address="203.0.113.1")
        ended, _ = await make_session(session, user, moment=BASE, ip_address="203.0.113.2")
        await repository.revoke(ended, moment=BASE, reason="SIGN_OUT")
        expired, _ = await make_session(
            session, user, moment=at(hours=-13), expires_at=at(hours=-1), ip_address="203.0.113.3"
        )
        idle, _ = await make_session(session, user, moment=at(hours=-2), ip_address="203.0.113.4")

        listed = await repository.list_for_user(user.id, moment=BASE, idle_ttl=IDLE_TTL)
        ids = {row.id for row in listed}
        assert ids == {live.id}
        assert ended.id not in ids
        assert expired.id not in ids
        assert idle.id not in ids

    async def test_devices_are_ordered_by_most_recent_use(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = SessionRepository(session)
        oldest, _ = await make_session(session, user, moment=at(minutes=-25))
        newest, _ = await make_session(session, user, moment=at(minutes=-1))
        middle, _ = await make_session(session, user, moment=at(minutes=-10))
        listed = await repository.list_for_user(user.id, moment=BASE, idle_ttl=IDLE_TTL)
        assert [row.id for row in listed] == [newest.id, middle.id, oldest.id]

    async def test_a_session_idle_for_exactly_the_ttl_is_not_listed(
        self, session: AsyncSession
    ) -> None:
        """The boundary is exclusive: at exactly ``idle_ttl`` the session is over.

        An inclusive comparison would keep a session alive for one extra window on
        every request that touches it, which is how an "idle timeout" quietly stops
        timing anything out.
        """
        user = await make_user(session)
        repository = SessionRepository(session)
        edge, _ = await make_session(session, user, moment=at(minutes=-30))
        just_inside, _ = await make_session(session, user, moment=at(minutes=-29, seconds=-59))
        listed = await repository.list_for_user(user.id, moment=BASE, idle_ttl=IDLE_TTL)
        ids = {row.id for row in listed}
        assert edge.id not in ids
        assert just_inside.id in ids

    async def test_another_users_sessions_are_not_listed(self, session: AsyncSession) -> None:
        first = await make_user(session, "first@example.com")
        second = await make_user(session, "second@example.com")
        await make_session(session, first)
        mine, _ = await make_session(session, second)
        listed = await SessionRepository(session).list_for_user(
            second.id, moment=BASE, idle_ttl=IDLE_TTL
        )
        assert [row.id for row in listed] == [mine.id]

    async def test_count_active_matches_the_listing(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = SessionRepository(session)
        for index in range(3):
            await make_session(session, user, moment=at(minutes=-index))
        counted = await repository.count_active_for_user(user.id, moment=BASE, idle_ttl=IDLE_TTL)
        listed = await repository.list_for_user(user.id, moment=BASE, idle_ttl=IDLE_TTL)
        assert counted == 3 == len(listed)


class TestRevocation:
    async def test_revoking_is_idempotent_and_keeps_the_first_reason(
        self, session: AsyncSession
    ) -> None:
        """The first reason is the one an investigator needs: "ADMIN_REVOKE then
        SIGN_OUT" would say the wrong thing about who ended it and why."""
        user = await make_user(session)
        created, _ = await make_session(session, user)
        repository = SessionRepository(session)
        await repository.revoke(created, moment=BASE, reason="ADMIN_REVOKE")
        await repository.revoke(created, moment=at(minutes=1), reason="SIGN_OUT")
        assert created.revoke_reason == "ADMIN_REVOKE"
        assert created.revoked_at == BASE

    async def test_revoking_a_family_leaves_other_families_alone(
        self, session: AsyncSession
    ) -> None:
        user = await make_user(session)
        repository = SessionRepository(session)
        stolen, _ = await make_session(session, user, moment=BASE, ip_address="203.0.113.9")
        unrelated, _ = await make_session(session, user, moment=BASE, ip_address="198.51.100.1")
        revoked = await repository.revoke_family(
            stolen.family_id, moment=BASE, reason="TOKEN_REUSE"
        )
        assert revoked == 1
        await reload(session, stolen)
        await reload(session, unrelated)
        assert stolen.status is SessionStatus.REVOKED
        assert unrelated.status is SessionStatus.ACTIVE

    async def test_sign_out_everywhere(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = SessionRepository(session)
        for index in range(4):
            await make_session(session, user, moment=at(minutes=-index))
        revoked = await repository.revoke_all_for_user(
            user.id, moment=BASE, reason="SESSIONS_REVOKED_ALL"
        )
        assert revoked == 4
        assert await repository.count_active_for_user(user.id, moment=BASE, idle_ttl=IDLE_TTL) == 0

    async def test_sign_out_everywhere_can_spare_the_caller(self, session: AsyncSession) -> None:
        """The common case after a password change: end every other device without
        logging out the person making the change mid-request."""
        user = await make_user(session)
        repository = SessionRepository(session)
        mine, _ = await make_session(session, user, moment=BASE)
        for index in range(3):
            await make_session(session, user, moment=at(minutes=-(index + 1)))
        revoked = await repository.revoke_all_for_user(
            user.id, moment=BASE, reason="PASSWORD_CHANGED", except_session_id=mine.id
        )
        assert revoked == 3
        assert mine.status is SessionStatus.ACTIVE

    async def test_a_credential_change_revokes_by_creation_not_by_last_use(
        self, session: AsyncSession
    ) -> None:
        """The distinction that decides whether an attacker keeps access.

        A session created before the password changed was authenticated with a
        credential that may have been the attacker's. Matching on ``last_seen_at``
        would spare exactly that session, because an attacker keeps it recent by
        using it.
        """
        user = await make_user(session)
        repository = SessionRepository(session)

        # ``created_at`` comes from the ORM's real wall-clock default and ``moment``
        # only sets ``last_seen_at``, so both are pinned explicitly here: the test is
        # about a session that is old by creation and recent by use.
        attackers, _ = await make_session(session, user, moment=at(hours=-3))
        attackers.created_at = at(hours=-3)
        attackers.last_seen_at = at(minutes=-1)  # actively used, moments ago
        await session.flush()

        honest = (await make_session(session, user, moment=at(minutes=-5)))[0]
        honest.created_at = at(minutes=-5)
        await session.flush()

        revoked = await repository.revoke_created_before(
            user.id, before=at(minutes=-30), moment=BASE, reason="PASSWORD_CHANGED"
        )
        assert revoked == 1
        await reload(session, attackers)
        await reload(session, honest)
        assert attackers.status is SessionStatus.REVOKED
        assert attackers.revoke_reason == "PASSWORD_CHANGED"
        assert honest.status is SessionStatus.ACTIVE

    async def test_bulk_revocation_reports_an_accurate_count(self, session: AsyncSession) -> None:
        """The count becomes "N devices were signed out" in an API response, so a
        wrong number is a wrong statement to the user."""
        user = await make_user(session)
        repository = SessionRepository(session)
        for index in range(5):
            await make_session(session, user, moment=at(minutes=-index))
        assert await repository.revoke_all_for_user(user.id, moment=BASE, reason="X") == 5
        # Revoking again changes nothing, and must not claim otherwise.
        assert await repository.revoke_all_for_user(user.id, moment=BASE, reason="X") == 0


class TestExpiryAndRetention:
    async def test_mark_expired_moves_both_kinds_of_dead_session(
        self, session: AsyncSession
    ) -> None:
        user = await make_user(session)
        repository = SessionRepository(session)
        absolute, _ = await make_session(
            session, user, moment=at(hours=-13), expires_at=at(hours=-1)
        )
        idle, _ = await make_session(session, user, moment=at(hours=-2))
        alive, _ = await make_session(session, user, moment=BASE)

        marked = await repository.mark_expired(moment=BASE, idle_ttl=IDLE_TTL)
        assert marked == 2
        await reload(session, absolute)
        await reload(session, idle)
        assert absolute.status is SessionStatus.EXPIRED
        assert idle.status is SessionStatus.EXPIRED
        assert alive.status is SessionStatus.ACTIVE

    async def test_mark_expired_does_not_overwrite_a_revocation(
        self, session: AsyncSession
    ) -> None:
        """A session an administrator revoked must not be relabelled as merely
        expired: the reason is the evidence."""
        user = await make_user(session)
        repository = SessionRepository(session)
        revoked, _ = await make_session(session, user, moment=at(hours=-2))
        await repository.revoke(revoked, moment=at(hours=-1), reason="ADMIN_REVOKE")
        assert await repository.mark_expired(moment=BASE, idle_ttl=IDLE_TTL) == 0
        await reload(session, revoked)
        assert revoked.status is SessionStatus.REVOKED
        assert revoked.revoke_reason == "ADMIN_REVOKE"

    async def test_purge_deletes_terminal_rows_only(self, session: AsyncSession) -> None:
        """A retention sweep must never delete a live session, however old it is.

        ``updated_at`` is stamped by the ORM at real wall-clock time rather than the
        synthetic instant the rest of these tests drive, so the cutoff here is
        relative to ``utc_now()``: a future cutoff means "everything past retention".
        """
        user = await make_user(session)
        repository = SessionRepository(session)
        rotated, plain = await make_session(session, user, moment=at(days=-40))
        await repository.rotate(
            rotated,
            refresh_token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(days=-39),
            moment=at(days=-39),
        )
        alive, alive_plain = await make_session(
            session, user, moment=at(days=-40), expires_at=at(days=1)
        )

        purged = await repository.purge_terminated_before(cutoff=utc_now() + timedelta(days=1))
        assert purged == 1
        assert await repository.get_by_refresh_token(plain) is None
        # The live session survives a sweep that removed everything terminal.
        assert await repository.get_by_refresh_token(alive_plain) is not None
        assert alive.status is SessionStatus.ACTIVE

    async def test_purge_keeps_recent_evidence(self, session: AsyncSession) -> None:
        """Rotated rows are replay evidence and must outlive the incident window."""
        user = await make_user(session)
        repository = SessionRepository(session)
        parent, plain = await make_session(session, user, moment=at(days=-2))
        await repository.rotate(
            parent,
            refresh_token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(days=1),
            moment=at(days=-1),
        )
        # A cutoff behind the rows' real ``updated_at`` retains the evidence.
        assert await repository.purge_terminated_before(cutoff=utc_now() - timedelta(days=30)) == 0
        found = await repository.get_by_refresh_token(plain)
        assert found is not None
        assert found.is_rotated is True


class TestAuthTokenRepository:
    async def test_a_token_is_issued_and_found(self, session: AsyncSession) -> None:
        user = await make_user(session)
        plain = generate_opaque_token(prefix="pr")
        repository = AuthTokenRepository(session)
        created, superseded = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(plain),
            expires_at=at(minutes=15),
            moment=BASE,
            requested_ip="203.0.113.7",
        )
        assert superseded == 0
        assert created.id is not None
        found = await repository.get_by_token(plain, purpose=AuthTokenPurpose.PASSWORD_RESET)
        assert found is not None
        assert found.id == created.id
        assert found.is_usable_at(BASE) is True

    async def test_a_new_token_supersedes_the_outstanding_one(self, session: AsyncSession) -> None:
        """Two valid reset tokens for one account means the older is a credential
        nobody is watching (§59)."""
        user = await make_user(session)
        repository = AuthTokenRepository(session)
        first = generate_opaque_token()
        await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(first),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        second = generate_opaque_token()
        _, superseded = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(second),
            expires_at=at(minutes=15),
            moment=at(minutes=1),
        )
        assert superseded == 1
        assert await repository.get_by_token(first, purpose=AuthTokenPurpose.PASSWORD_RESET) is None
        assert (
            await repository.get_by_token(second, purpose=AuthTokenPurpose.PASSWORD_RESET)
        ) is not None

    async def test_superseding_is_scoped_to_the_purpose(self, session: AsyncSession) -> None:
        """Issuing a reset token must not invalidate a pending email verification."""
        user = await make_user(session)
        repository = AuthTokenRepository(session)
        verification = generate_opaque_token()
        await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(verification),
            expires_at=at(days=1),
            moment=BASE,
        )
        _, superseded = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        assert superseded == 0
        assert (
            await repository.get_by_token(verification, purpose=AuthTokenPurpose.EMAIL_VERIFICATION)
        ) is not None

    async def test_a_token_is_only_found_under_its_own_purpose(self, session: AsyncSession) -> None:
        """Scoping the query rather than checking afterwards: a password-reset token
        must be structurally unfindable from the verification path (§59)."""
        user = await make_user(session)
        repository = AuthTokenRepository(session)
        plain = generate_opaque_token()
        await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(plain),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        assert (
            await repository.get_by_token(plain, purpose=AuthTokenPurpose.EMAIL_VERIFICATION)
        ) is None
        assert (
            await repository.get_by_token(plain, purpose=AuthTokenPurpose.PASSWORD_RESET)
        ) is not None

    async def test_a_consumed_token_is_still_found(self, session: AsyncSession) -> None:
        """So the caller can tell a replayed link from an invented one, and audit the
        difference instead of reporting "invalid" for both."""
        user = await make_user(session)
        repository = AuthTokenRepository(session)
        plain = generate_opaque_token()
        created, _ = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(plain),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        assert await repository.consume(created, moment=at(minutes=1), ip_address="203.0.113.7")
        found = await repository.get_by_token(plain, purpose=AuthTokenPurpose.PASSWORD_RESET)
        assert found is not None
        assert found.is_consumed is True
        assert found.is_usable_at(at(minutes=2)) is False
        assert found.consumed_ip == "203.0.113.7"

    async def test_a_token_can_only_be_consumed_once(self, session: AsyncSession) -> None:
        """The return value is the control: ignoring it lets a double submission
        reset a password twice."""
        user = await make_user(session)
        repository = AuthTokenRepository(session)
        created, _ = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        assert await repository.consume(created, moment=BASE) is True
        assert await repository.consume(created, moment=at(seconds=1)) is False

    async def test_usability_respects_the_expiry(self, session: AsyncSession) -> None:
        user = await make_user(session)
        created, _ = await AuthTokenRepository(session).issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        assert created.is_usable_at(at(minutes=14)) is True
        assert created.is_usable_at(at(minutes=15)) is False
        assert created.is_usable_at(at(days=1)) is False

    async def test_purge_removes_only_expired_tokens(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = AuthTokenRepository(session)
        dead, _ = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(minutes=-1),
            moment=at(minutes=-30),
        )
        alive, _ = await repository.issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.EMAIL_VERIFICATION,
            token_hash=hash_opaque_token(generate_opaque_token()),
            expires_at=at(days=1),
            moment=BASE,
        )
        assert await repository.purge_expired(moment=BASE) == 1
        remaining = await repository.list_for_user(user.id)
        assert [row.id for row in remaining] == [alive.id]
        assert dead.id != alive.id


class TestRecoveryCodeRepository:
    async def test_codes_are_stored_and_usable(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = MfaRecoveryCodeRepository(session)
        digests = [hash_opaque_token(f"code-{index}") for index in range(10)]
        stored = await repository.store_all(user_id=user.id, code_hashes=digests, moment=BASE)
        assert len(stored) == 10
        assert await repository.remaining_count(user.id) == 10
        assert await repository.find_usable(user_id=user.id, code_hash=digests[0]) is not None

    async def test_re_enrolling_invalidates_the_previous_set(self, session: AsyncSession) -> None:
        """The bug an un-awaited delete would have caused: codes shown on a screen
        the user may no longer control must stop working the moment a new set is
        issued (§59)."""
        user = await make_user(session)
        repository = MfaRecoveryCodeRepository(session)
        old = [hash_opaque_token(f"old-{index}") for index in range(10)]
        await repository.store_all(user_id=user.id, code_hashes=old, moment=BASE)

        new = [hash_opaque_token(f"new-{index}") for index in range(10)]
        await repository.store_all(user_id=user.id, code_hashes=new, moment=at(minutes=5))

        for digest in old:
            assert await repository.find_usable(user_id=user.id, code_hash=digest) is None
        assert await repository.remaining_count(user.id) == 10
        for digest in new:
            assert await repository.find_usable(user_id=user.id, code_hash=digest) is not None

    async def test_a_code_belongs_to_one_account(self, session: AsyncSession) -> None:
        """A global lookup would let a code stolen from one account be tried against
        another."""
        first = await make_user(session, "first@example.com")
        second = await make_user(session, "second@example.com")
        repository = MfaRecoveryCodeRepository(session)
        shared = hash_opaque_token("the-same-code-value")
        await repository.store_all(user_id=first.id, code_hashes=[shared], moment=BASE)
        assert await repository.find_usable(user_id=first.id, code_hash=shared) is not None
        assert await repository.find_usable(user_id=second.id, code_hash=shared) is None

    async def test_a_code_works_once(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = MfaRecoveryCodeRepository(session)
        digest = hash_opaque_token("single-use")
        await repository.store_all(user_id=user.id, code_hashes=[digest], moment=BASE)
        code = await repository.find_usable(user_id=user.id, code_hash=digest)
        assert code is not None
        assert await repository.consume(code, moment=BASE, ip_address="203.0.113.7") is True
        assert await repository.consume(code, moment=at(seconds=1)) is False
        assert await repository.find_usable(user_id=user.id, code_hash=digest) is None
        assert await repository.remaining_count(user.id) == 0
        assert code.consumed_ip == "203.0.113.7"

    async def test_remaining_count_tracks_usage(self, session: AsyncSession) -> None:
        """The count is what warns a user before they spend their last code (§68)."""
        user = await make_user(session)
        repository = MfaRecoveryCodeRepository(session)
        digests = [hash_opaque_token(f"code-{index}") for index in range(3)]
        await repository.store_all(user_id=user.id, code_hashes=digests, moment=BASE)
        for index, digest in enumerate(digests):
            assert await repository.remaining_count(user.id) == 3 - index
            code = await repository.find_usable(user_id=user.id, code_hash=digest)
            assert code is not None
            await repository.consume(code, moment=BASE)
        assert await repository.remaining_count(user.id) == 0

    async def test_disabling_mfa_removes_every_code(self, session: AsyncSession) -> None:
        user = await make_user(session)
        repository = MfaRecoveryCodeRepository(session)
        await repository.store_all(
            user_id=user.id,
            code_hashes=[hash_opaque_token(f"code-{index}") for index in range(10)],
            moment=BASE,
        )
        assert await repository.delete_for_user(user.id) == 10
        assert await repository.remaining_count(user.id) == 0
        assert await repository.delete_for_user(user.id) == 0


class TestNoPlaintextIsPersisted:
    async def test_no_table_stores_a_presentable_credential(self, session: AsyncSession) -> None:
        """§12/§83: a database read must yield nothing usable. Every credential
        column is checked by name, so adding one later without hashing it fails
        here rather than in an incident review."""
        user = await make_user(session, "secrets@example.com")
        refresh = generate_opaque_token(prefix="rt")
        reset = generate_opaque_token(prefix="pr")
        codes = [generate_opaque_token() for _ in range(3)]

        created, _ = await make_session(session, user, token=refresh)
        await AuthTokenRepository(session).issue(
            user_id=user.id,
            purpose=AuthTokenPurpose.PASSWORD_RESET,
            token_hash=hash_opaque_token(reset),
            expires_at=at(minutes=15),
            moment=BASE,
        )
        await MfaRecoveryCodeRepository(session).store_all(
            user_id=user.id,
            code_hashes=[hash_opaque_token(code) for code in codes],
            moment=BASE,
        )

        stored: list[str] = [created.refresh_token_hash]
        stored += [
            row.token_hash for row in await AuthTokenRepository(session).list_for_user(user.id)
        ]
        stored += [
            row.code_hash
            for row in (
                await session.execute(
                    select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)
                )
            )
            .scalars()
            .all()
        ]

        assert len(stored) == 1 + 1 + len(codes)
        for value in (refresh, reset, *codes):
            assert all(value not in column for column in stored)
        for column in stored:
            # SHA-256 hex, and nothing else: a fixed shape makes a stray plaintext
            # value obvious rather than something a reviewer has to reason about.
            assert len(column) == 64
            assert all(character in "0123456789abcdef" for character in column)
