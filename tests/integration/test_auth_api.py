"""Authentication endpoints and the services behind them (§59, §61, §62, §68).

These are integration tests through the real ASGI application: real middleware, real
dependency wiring, real SQLite, real argon2 and real HMAC. Nothing is mocked except
Redis, which is fakeredis with Lua so the rate limiter runs its actual script.

Assertions are written against ``error.code`` rather than the HTTP status wherever
both are available, because §71 makes the code the contract: a client matches on
``INVALID_CREDENTIALS``, and a test that pins the status number instead would keep
passing after the code changed to something no client recognises.

The security properties being pinned here, in the order they appear:

* an unknown address and a wrong password are indistinguishable — same code, same
  message, and the same response body shape;
* a lockout actually locks, reports ``Retry-After``, and refuses even the correct
  password while it runs;
* a TOTP code cannot be spent twice inside its drift window (RFC 6238 §5.2);
* a recovery code cannot be spent twice at all;
* presenting an already-rotated refresh token kills the whole session family;
* a refresh without the CSRF header is refused even when the token is valid;
* changing a password ends every other session but not the caller's own;
* resetting a password ends all of them, including the caller's;
* a session id belonging to somebody else is a 404, not a revocation;
* failures are audited even though the request that caused them rolled back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from arb_core.clock import utc_now
from arb_core.security.totp import totp_code
from arb_persistence.models.audit import AuditLog
from arb_persistence.models.auth import User, UserSession
from arb_persistence.repositories.auth import UserRepository

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from httpx import Response

    from arb_core.db.session import Database

pytestmark = pytest.mark.integration

PASSWORD = "Zephyr-Correct-Horse-42"
OTHER_PASSWORD = "Marlin-Wrong-Horse-77"
WEAK_PASSWORD = "short"

#: Set by the test configuration: no mail server exists, and ``Environment.TEST`` is
#: not a deployed environment, so the two emailed-token endpoints hand the token back
#: in a ``dev_*`` field. That field is null in staging and production.
DEV_TOKEN_ALLOWED = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def error_code(response: Response) -> str:
    """The stable code from the §71 envelope."""
    return str(response.json()["error"]["code"])


def error_details(response: Response) -> dict[str, Any]:
    details = response.json()["error"].get("details")
    return dict(details) if isinstance(details, dict) else {}


async def register(client: AsyncClient, email: str, password: str = PASSWORD) -> Response:
    return await client.post("/api/v1/auth/register", json={"email": email, "password": password})


async def verify_email(client: AsyncClient, response: Response) -> Response:
    token = response.json()["dev_verification_token"]
    assert token, "the test environment must expose the verification token"
    return await client.post("/api/v1/auth/email/verify", json={"token": token})


async def active_user(client: AsyncClient, email: str, password: str = PASSWORD) -> Response:
    """Register an account and confirm its address, so it can sign in."""
    created = await register(client, email, password)
    assert created.status_code == 201, created.text
    confirmed = await verify_email(client, created)
    assert confirmed.status_code == 200, confirmed.text
    return created


async def login(client: AsyncClient, email: str, password: str = PASSWORD) -> Response:
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


async def signed_in(client: AsyncClient, email: str, password: str = PASSWORD) -> dict[str, Any]:
    """Register, verify and sign in; return the login payload."""
    await active_user(client, email, password)
    response = await login(client, email, password)
    assert response.status_code == 200, response.text
    return dict(response.json())


def bearer(body: dict[str, Any]) -> dict[str, str]:
    """An ``Authorization`` header for a login or refresh response."""
    return {"Authorization": f"Bearer {body['tokens']['access_token']}"}


async def rows(database: Database, statement: Any) -> list[Any]:
    async with database.session() as session:
        return list((await session.execute(statement)).scalars().all())


async def audit_actions(database: Database, action: str) -> list[AuditLog]:
    return await rows(database, select(AuditLog).where(AuditLog.action == action))


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
class TestRegistration:
    async def test_an_account_is_created_pending_verification(self, client: AsyncClient) -> None:
        response = await register(client, "trader@example.com")
        assert response.status_code == 201
        body = response.json()
        assert body["requires_email_verification"] is True
        assert body["user"]["status"] == "PENDING_VERIFICATION"
        assert body["user"]["email"] == "trader@example.com"
        assert body["user"]["role"] == "TRADER", "self-service sign-up confers no authority"

    async def test_no_credential_is_echoed_back(self, client: AsyncClient) -> None:
        """Not the password, not its digest, not a session token."""
        response = await register(client, "quiet@example.com")
        text = response.text.lower()
        assert PASSWORD.lower() not in text
        assert "password_hash" not in text
        assert "argon2" not in text
        assert "access_token" not in text

    async def test_an_address_is_stored_in_canonical_form(
        self, client: AsyncClient, database: Database
    ) -> None:
        await register(client, "Mixed.Case@Example.COM")
        users = await rows(database, select(User))
        assert [user.email for user in users] == ["mixed.case@example.com"]

    async def test_a_duplicate_address_is_refused(self, client: AsyncClient) -> None:
        await register(client, "twice@example.com")
        second = await register(client, "TWICE@example.com")
        assert error_code(second) == "EMAIL_ALREADY_REGISTERED"

    async def test_a_weak_password_is_refused_before_an_account_exists(
        self, client: AsyncClient, database: Database
    ) -> None:
        response = await register(client, "weak@example.com", WEAK_PASSWORD)
        assert response.status_code == 422 or error_code(response) == "PASSWORD_POLICY_REJECTED"
        assert await rows(database, select(User)) == []

    async def test_a_password_containing_the_email_address_is_refused(
        self, client: AsyncClient, database: Database
    ) -> None:
        response = await register(client, "selfie@example.com", "selfie@example.com-99")
        assert error_code(response) == "PASSWORD_POLICY_REJECTED"
        assert "password" in error_details(response)
        assert await rows(database, select(User)) == []

    async def test_an_unknown_field_is_rejected_rather_than_ignored(
        self, client: AsyncClient, database: Database
    ) -> None:
        """``extra="forbid"`` is what stops a request body from granting a role."""
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "sneaky@example.com", "password": PASSWORD, "role": "OWNER"},
        )
        assert response.status_code == 422
        assert await rows(database, select(User)) == []

    async def test_registration_can_be_switched_off(
        self, client: AsyncClient, container: Any
    ) -> None:
        container.settings.registration_enabled = False
        try:
            response = await register(client, "closed@example.com")
            assert error_code(response) == "REGISTRATION_DISABLED"
        finally:
            container.settings.registration_enabled = True


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------
class TestEmailVerification:
    async def test_confirming_activates_the_account(
        self, client: AsyncClient, database: Database
    ) -> None:
        created = await register(client, "confirm@example.com")
        assert (await verify_email(client, created)).status_code == 200
        users = await rows(database, select(User))
        assert users[0].status.value == "ACTIVE"
        assert users[0].email_verified_at is not None

    async def test_a_token_cannot_be_spent_twice(self, client: AsyncClient) -> None:
        created = await register(client, "once@example.com")
        token = created.json()["dev_verification_token"]
        assert (
            await client.post("/api/v1/auth/email/verify", json={"token": token})
        ).status_code == 200
        second = await client.post("/api/v1/auth/email/verify", json={"token": token})
        assert error_code(second) == "TOKEN_INVALID"

    async def test_an_invented_token_is_refused(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/auth/email/verify", json={"token": "ev" + "0" * 43})
        assert error_code(response) == "TOKEN_INVALID"

    async def test_a_reset_token_cannot_verify_an_address(self, client: AsyncClient) -> None:
        """The purpose is part of the lookup, so the wrong flow cannot find the row."""
        created = await register(client, "crossed@example.com")
        await verify_email(client, created)
        reset = await client.post(
            "/api/v1/auth/password/reset", json={"email": "crossed@example.com"}
        )
        token = reset.json()["dev_reset_token"]
        assert token
        response = await client.post("/api/v1/auth/email/verify", json={"token": token})
        assert error_code(response) == "TOKEN_INVALID"

    async def test_resending_does_not_reveal_whether_the_address_exists(
        self, client: AsyncClient
    ) -> None:
        known = await client.post(
            "/api/v1/auth/email/verify/request", json={"email": "nobody@example.com"}
        )
        assert known.status_code == 202
        assert "new link is on its way" in known.json()["message"]


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------
class TestLogin:
    async def test_a_correct_password_issues_a_credential_set(self, client: AsyncClient) -> None:
        await active_user(client, "happy@example.com")
        response = await login(client, "happy@example.com")
        assert response.status_code == 200
        tokens = response.json()["tokens"]
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] > 0
        assert len(tokens["refresh_token"]) > 30
        assert len(tokens["csrf_token"]) > 20

    async def test_the_refresh_and_csrf_cookies_are_set(
        self, client: AsyncClient, container: Any
    ) -> None:
        await active_user(client, "cookies@example.com")
        await login(client, "cookies@example.com")
        settings = container.settings
        assert client.cookies.get(settings.refresh_cookie_name)
        assert client.cookies.get(settings.csrf_cookie_name)

    async def test_a_wrong_password_and_an_unknown_address_are_indistinguishable(
        self, client: AsyncClient
    ) -> None:
        """The enumeration guarantee, stated as an equality of responses."""
        await active_user(client, "known@example.com")
        wrong = await login(client, "known@example.com", OTHER_PASSWORD)
        unknown = await login(client, "never-registered@example.com", OTHER_PASSWORD)

        assert error_code(wrong) == error_code(unknown) == "INVALID_CREDENTIALS"
        assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]
        assert wrong.status_code == unknown.status_code
        assert wrong.headers.get("WWW-Authenticate") == unknown.headers.get("WWW-Authenticate")

    async def test_an_unverified_account_cannot_sign_in(self, client: AsyncClient) -> None:
        await register(client, "pending@example.com")
        response = await login(client, "pending@example.com")
        assert error_code(response) == "EMAIL_NOT_VERIFIED"

    async def test_a_disabled_account_cannot_sign_in(
        self, client: AsyncClient, database: Database
    ) -> None:
        await active_user(client, "disabled@example.com")
        async with database.unit_of_work() as session:
            user = await UserRepository(session).get_by_email("disabled@example.com")
            assert user is not None
            from arb_persistence.models.enums import UserStatus

            user.status = UserStatus.DISABLED
        response = await login(client, "disabled@example.com")
        assert error_code(response) == "ACCOUNT_DISABLED"

    async def test_no_session_row_is_created_by_a_failed_sign_in(
        self, client: AsyncClient, database: Database
    ) -> None:
        await active_user(client, "nosession@example.com")
        await login(client, "nosession@example.com", OTHER_PASSWORD)
        assert await rows(database, select(UserSession)) == []


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------
class TestLockout:
    async def test_repeated_failures_lock_the_account_and_report_retry_after(
        self, client: AsyncClient, container: Any
    ) -> None:
        await active_user(client, "locked@example.com")
        attempts = container.settings.login_max_failed_attempts
        for _ in range(attempts):
            response = await login(client, "locked@example.com", OTHER_PASSWORD)
            assert error_code(response) in {"INVALID_CREDENTIALS", "ACCOUNT_LOCKED"}

        locked = await login(client, "locked@example.com", OTHER_PASSWORD)
        assert error_code(locked) == "ACCOUNT_LOCKED"
        assert int(locked.headers["Retry-After"]) > 0

    async def test_a_locked_account_refuses_the_correct_password_too(
        self, client: AsyncClient, container: Any
    ) -> None:
        """The lock is checked before verification, so it also bounds hashing work."""
        await active_user(client, "brute@example.com")
        for _ in range(container.settings.login_max_failed_attempts + 1):
            await login(client, "brute@example.com", OTHER_PASSWORD)
        response = await login(client, "brute@example.com", PASSWORD)
        assert error_code(response) == "ACCOUNT_LOCKED"

    async def test_attempts_during_a_lock_do_not_extend_it(
        self, client: AsyncClient, container: Any, database: Database
    ) -> None:
        """Extending the lock per hit would turn a defence into a denial of service."""
        await active_user(client, "anti-dos@example.com")
        for _ in range(container.settings.login_max_failed_attempts + 1):
            await login(client, "anti-dos@example.com", OTHER_PASSWORD)

        first = await rows(database, select(User))
        locked_until = first[0].locked_until
        assert locked_until is not None

        for _ in range(5):
            await login(client, "anti-dos@example.com", OTHER_PASSWORD)

        second = await rows(database, select(User))
        assert second[0].locked_until == locked_until

    async def test_a_successful_sign_in_clears_the_failure_counter(
        self, client: AsyncClient, database: Database
    ) -> None:
        await active_user(client, "cleared@example.com")
        await login(client, "cleared@example.com", OTHER_PASSWORD)
        await login(client, "cleared@example.com", OTHER_PASSWORD)
        assert (await rows(database, select(User)))[0].failed_login_count == 2

        assert (await login(client, "cleared@example.com")).status_code == 200
        assert (await rows(database, select(User)))[0].failed_login_count == 0


# ---------------------------------------------------------------------------
# Second factor
# ---------------------------------------------------------------------------
class TestMultiFactor:
    async def enrollment(self, client: AsyncClient, body: dict[str, Any]) -> dict[str, Any]:
        started = await client.post("/api/v1/auth/mfa/enroll", headers=bearer(body))
        assert started.status_code == 200, started.text
        return dict(started.json())

    async def test_enrollment_returns_a_secret_uri_and_recovery_codes(
        self, client: AsyncClient
    ) -> None:
        body = await signed_in(client, "enroll@example.com")
        enrollment = await self.enrollment(client, body)
        assert enrollment["provisioning_uri"].startswith("otpauth://totp/")
        assert len(enrollment["secret"]) >= 32
        assert len(enrollment["recovery_codes"]) == 10
        assert len({*enrollment["recovery_codes"]}) == 10, "codes must be distinct"

    async def test_enrollment_alone_does_not_enable_mfa(
        self, client: AsyncClient, database: Database
    ) -> None:
        """Generating a secret is not proving possession of it."""
        body = await signed_in(client, "halfway@example.com")
        await self.enrollment(client, body)
        assert (await rows(database, select(User)))[0].mfa_enabled is False

        status_response = await client.get("/api/v1/auth/mfa", headers=bearer(body))
        assert status_response.json()["enabled"] is False

    async def test_confirming_with_a_real_code_enables_mfa(self, client: AsyncClient) -> None:
        body = await signed_in(client, "confirm-mfa@example.com")
        enrollment = await self.enrollment(client, body)
        code = totp_code(enrollment["secret"], at=utc_now())
        confirmed = await client.post(
            "/api/v1/auth/mfa/confirm", json={"code": code}, headers=bearer(body)
        )
        assert confirmed.status_code == 200, confirmed.text

        status_response = await client.get("/api/v1/auth/mfa", headers=bearer(body))
        payload = status_response.json()
        assert payload["enabled"] is True
        assert payload["recovery_codes_remaining"] == 10

    async def test_confirming_with_a_wrong_code_leaves_mfa_off(self, client: AsyncClient) -> None:
        body = await signed_in(client, "wrongcode@example.com")
        await self.enrollment(client, body)
        response = await client.post(
            "/api/v1/auth/mfa/confirm", json={"code": "000000"}, headers=bearer(body)
        )
        assert error_code(response) == "MFA_INVALID"

    async def test_sign_in_then_demands_the_second_factor(self, client: AsyncClient) -> None:
        body = await signed_in(client, "twofactor@example.com")
        enrollment = await self.enrollment(client, body)
        await client.post(
            "/api/v1/auth/mfa/confirm",
            json={"code": totp_code(enrollment["secret"], at=utc_now())},
            headers=bearer(body),
        )

        challenge = await login(client, "twofactor@example.com")
        assert challenge.status_code == 401, "a half-finished login must not look like success"
        assert error_code(challenge) == "MFA_REQUIRED"
        assert error_details(challenge)["mfa_challenge"]
        assert "tokens" not in challenge.json().get("error", {})

        completed = await client.post(
            "/api/v1/auth/mfa/login",
            json={
                "challenge": error_details(challenge)["mfa_challenge"],
                "code": totp_code(enrollment["secret"], at=utc_now()),
            },
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["tokens"]["access_token"]

    async def test_a_totp_code_cannot_be_spent_twice(self, client: AsyncClient) -> None:
        """RFC 6238 §5.2: the second attempt with a valid OTP must be refused.

        The drift window that tolerates a skewed clock is three steps wide, so without
        the recorded step a code seen once could be replayed for over a minute.
        """
        body = await signed_in(client, "replay-totp@example.com")
        enrollment = await self.enrollment(client, body)
        code = totp_code(enrollment["secret"], at=utc_now())
        await client.post("/api/v1/auth/mfa/confirm", json={"code": code}, headers=bearer(body))

        challenge = await login(client, "replay-totp@example.com")
        first = await client.post(
            "/api/v1/auth/mfa/login",
            json={"challenge": error_details(challenge)["mfa_challenge"], "code": code},
        )
        assert first.status_code == 200, first.text

        second_challenge = await login(client, "replay-totp@example.com")
        second = await client.post(
            "/api/v1/auth/mfa/login",
            json={
                "challenge": error_details(second_challenge)["mfa_challenge"],
                "code": code,
            },
        )
        assert error_code(second) == "MFA_INVALID"

    async def test_a_recovery_code_signs_in_once(self, client: AsyncClient) -> None:
        body = await signed_in(client, "recovery@example.com")
        enrollment = await self.enrollment(client, body)
        await client.post(
            "/api/v1/auth/mfa/confirm",
            json={"code": totp_code(enrollment["secret"], at=utc_now())},
            headers=bearer(body),
        )
        code = enrollment["recovery_codes"][0]

        challenge = await login(client, "recovery@example.com")
        used = await client.post(
            "/api/v1/auth/mfa/login",
            json={"challenge": error_details(challenge)["mfa_challenge"], "code": code},
        )
        assert used.status_code == 200, used.text

        again = await login(client, "recovery@example.com")
        reused = await client.post(
            "/api/v1/auth/mfa/login",
            json={"challenge": error_details(again)["mfa_challenge"], "code": code},
        )
        assert error_code(reused) == "MFA_INVALID"

        status_response = await client.get("/api/v1/auth/mfa", headers=bearer(used.json()))
        assert status_response.json()["recovery_codes_remaining"] == 9

    async def test_a_recovery_code_is_accepted_with_separators(self, client: AsyncClient) -> None:
        """Codes are read aloud and typed by hand; punctuation must not break them."""
        body = await signed_in(client, "separated@example.com")
        enrollment = await self.enrollment(client, body)
        await client.post(
            "/api/v1/auth/mfa/confirm",
            json={"code": totp_code(enrollment["secret"], at=utc_now())},
            headers=bearer(body),
        )
        code = enrollment["recovery_codes"][1]
        spaced = f"{code[:5]}-{code[5:]}".lower()

        challenge = await login(client, "separated@example.com")
        response = await client.post(
            "/api/v1/auth/mfa/login",
            json={"challenge": error_details(challenge)["mfa_challenge"], "code": spaced},
        )
        assert response.status_code == 200, response.text

    async def test_disabling_requires_the_password(self, client: AsyncClient) -> None:
        body = await signed_in(client, "disable-mfa@example.com")
        enrollment = await self.enrollment(client, body)
        await client.post(
            "/api/v1/auth/mfa/confirm",
            json={"code": totp_code(enrollment["secret"], at=utc_now())},
            headers=bearer(body),
        )

        refused = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": OTHER_PASSWORD},
            headers=bearer(body),
        )
        assert error_code(refused) == "INVALID_CREDENTIALS"

        allowed = await client.post(
            "/api/v1/auth/mfa/disable", json={"password": PASSWORD}, headers=bearer(body)
        )
        assert allowed.status_code == 200, allowed.text

        # The account is back to a single factor, so sign-in no longer challenges.
        plain = await login(client, "disable-mfa@example.com")
        assert plain.status_code == 200

    async def test_mfa_endpoints_require_authentication(self, client: AsyncClient) -> None:
        # Annotated rather than left to inference: a bare tuple of lambdas gives mypy
        # no common type to settle on, and the calls below then type as unknown.
        calls: list[Callable[[], Awaitable[Response]]] = [
            lambda: client.post("/api/v1/auth/mfa/enroll"),
            lambda: client.get("/api/v1/auth/mfa"),
            lambda: client.post("/api/v1/auth/mfa/disable", json={"password": PASSWORD}),
        ]
        for call in calls:
            response = await call()
            assert response.status_code == 401
            assert error_code(response) == "UNAUTHENTICATED"


# ---------------------------------------------------------------------------
# Refresh rotation and replay
# ---------------------------------------------------------------------------
class TestRefreshRotation:
    async def test_a_refresh_returns_a_new_credential_set(self, client: AsyncClient) -> None:
        body = await signed_in(client, "rotate@example.com")
        old = body["tokens"]
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old["refresh_token"]},
            headers={"X-CSRF-Token": old["csrf_token"]},
        )
        assert response.status_code == 200, response.text
        new = response.json()
        assert new["refresh_token"] != old["refresh_token"]
        assert new["access_token"] != old["access_token"]
        assert new["session_id"] != old["session_id"]

    async def test_a_refresh_without_the_csrf_header_is_refused(self, client: AsyncClient) -> None:
        """Even with a valid token in the body.

        A cross-site form can post a JSON-looking body under a content type that
        provokes no CORS preflight, so "the token was in the body, not a cookie" is
        not on its own proof of same-origin intent.
        """
        body = await signed_in(client, "csrf@example.com")
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": body["tokens"]["refresh_token"]}
        )
        assert error_code(response) == "CSRF_FAILED"

    async def test_a_wrong_csrf_token_is_refused(self, client: AsyncClient) -> None:
        body = await signed_in(client, "csrf-wrong@example.com")
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": body["tokens"]["refresh_token"]},
            headers={"X-CSRF-Token": "not-the-right-token"},
        )
        assert error_code(response) == "CSRF_FAILED"

    async def test_the_cookie_alone_can_refresh(self, client: AsyncClient) -> None:
        """The browser path: the token travels in the cookie, the proof in a header."""
        body = await signed_in(client, "cookie-refresh@example.com")
        response = await client.post(
            "/api/v1/auth/refresh",
            json={},
            headers={"X-CSRF-Token": body["tokens"]["csrf_token"]},
        )
        assert response.status_code == 200, response.text
        assert response.json()["refresh_token"] != body["tokens"]["refresh_token"]

    async def test_replaying_a_rotated_token_kills_the_whole_family(
        self, client: AsyncClient, database: Database
    ) -> None:
        """The reuse-detection property, end to end.

        Somebody exchanged the first token and somebody else is still holding it. One
        of them is the account owner and nothing server-side can say which, so every
        session descended from that sign-in is revoked and both parties must sign in
        again.
        """
        body = await signed_in(client, "stolen@example.com")
        first = body["tokens"]

        rotated = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": first["refresh_token"]},
            headers={"X-CSRF-Token": first["csrf_token"]},
        )
        assert rotated.status_code == 200
        second = rotated.json()

        replay = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": first["refresh_token"]},
            headers={"X-CSRF-Token": first["csrf_token"]},
        )
        assert error_code(replay) == "SESSION_REVOKED"

        # The attacker's own token died with the family: that is the point.
        after = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": second["refresh_token"]},
            headers={"X-CSRF-Token": second["csrf_token"]},
        )
        assert error_code(after) == "SESSION_REVOKED"

        assert await audit_actions(database, "AUTH_SESSION_REFRESH_TOKEN_REPLAY")

    async def test_an_invented_refresh_token_is_refused(self, client: AsyncClient) -> None:
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "rt" + "0" * 43},
            headers={"X-CSRF-Token": "irrelevant"},
        )
        assert error_code(response) == "SESSION_REVOKED"

    async def test_a_refreshed_token_keeps_working_until_the_family_deadline(
        self, client: AsyncClient, database: Database
    ) -> None:
        """Rotation inherits the deadline rather than extending it."""
        body = await signed_in(client, "deadline@example.com")
        before = await rows(database, select(UserSession))
        original_expiry = max(row.expires_at for row in before)

        rotated = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": body["tokens"]["refresh_token"]},
            headers={"X-CSRF-Token": body["tokens"]["csrf_token"]},
        )
        assert rotated.status_code == 200

        after = await rows(database, select(UserSession))
        assert max(row.expires_at for row in after) == original_expiry


# ---------------------------------------------------------------------------
# The authenticated caller
# ---------------------------------------------------------------------------
class TestAuthenticatedAccess:
    async def test_me_returns_the_account_without_credentials(self, client: AsyncClient) -> None:
        body = await signed_in(client, "me@example.com")
        response = await client.get("/api/v1/auth/me", headers=bearer(body))
        assert response.status_code == 200
        payload = response.json()
        assert payload["email"] == "me@example.com"
        assert "password" not in response.text.lower().replace("must_change_password", "")

    async def test_a_missing_or_malformed_authorization_header_is_refused(
        self, client: AsyncClient
    ) -> None:
        for headers in ({}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}):
            response = await client.get("/api/v1/auth/me", headers=headers)
            assert response.status_code == 401
            assert error_code(response) == "UNAUTHENTICATED"

    async def test_a_forged_token_is_refused(self, client: AsyncClient) -> None:
        forged = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.not-a-real-signature"
        response = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    async def test_a_revoked_session_stops_working_immediately(self, client: AsyncClient) -> None:
        """Authority is read from the database per request, not from the token (§60).

        A token-only scheme would keep honouring this access token for the rest of its
        fifteen minutes. Revoking has to mean now.
        """
        body = await signed_in(client, "revoke-now@example.com")
        headers = bearer(body)
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200

        assert (await client.post("/api/v1/auth/logout", headers=headers)).status_code == 200

        refused = await client.get("/api/v1/auth/me", headers=headers)
        assert refused.status_code == 401
        assert error_code(refused) == "SESSION_REVOKED"

    async def test_a_session_predating_a_password_change_stops_working(
        self, client: AsyncClient, app: Any
    ) -> None:
        """The reason ``password_changed_at`` is compared against ``created_at``.

        Somebody who changes a password because they suspect it is known elsewhere
        means "end anything that got in with the old one". A session established
        before the change was authenticated with a credential that has just stopped
        being valid, so it goes — while the session that made the change is spared,
        because it proved moments ago that it holds the new one.
        """
        body = await signed_in(client, "stale-session@example.com")
        headers = bearer(body)

        # A second device signs in *before* anything changes, so it is the older one.
        other = await parallel_session(app, "stale-session@example.com", PASSWORD)
        assert (await client.get("/api/v1/auth/me", headers=other)).status_code == 200

        changed = await client.post(
            "/api/v1/auth/password/change",
            json={"current_password": PASSWORD, "new_password": OTHER_PASSWORD},
            headers=headers,
        )
        assert changed.status_code == 200, changed.text
        renewed = bearer(changed.json())

        # The device that changed the password is signed in again with the new
        # credential, so it carries on working - with the replacement token, not the
        # one it used to make the request.
        assert (await client.get("/api/v1/auth/me", headers=renewed)).status_code == 200
        assert error_code(await client.get("/api/v1/auth/me", headers=headers)) == (
            "SESSION_REVOKED"
        )

        refused = await client.get("/api/v1/auth/me", headers=other)
        assert refused.status_code == 401
        assert error_code(refused) == "SESSION_REVOKED"


async def parallel_session(app: Any, email: str, password: str = PASSWORD) -> dict[str, str]:
    """Sign in through a second client, so two sessions coexist for one account.

    A separate :class:`AsyncClient` has its own cookie jar, which is what makes it a
    second device rather than a second header on the same one. Built from the ``app``
    fixture rather than borrowed from the first client, so no test reaches into a
    private attribute of httpx.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as separate:
        response = await login(separate, email, password)
        assert response.status_code == 200, response.text
        return bearer(response.json())


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------
class TestSessionManagement:
    async def test_sessions_are_listed_with_the_current_one_marked(
        self, client: AsyncClient
    ) -> None:
        body = await signed_in(client, "devices@example.com")
        response = await client.get("/api/v1/auth/sessions", headers=bearer(body))
        assert response.status_code == 200
        payload = response.json()
        assert payload["count"] == 1
        assert payload["sessions"][0]["current"] is True
        assert "refresh_token" not in response.text

    async def test_another_accounts_session_cannot_be_revoked(
        self, client: AsyncClient, database: Database
    ) -> None:
        victim = await signed_in(client, "victim@example.com")
        attacker = await signed_in(client, "attacker@example.com")
        victim_session = victim["tokens"]["session_id"]

        response = await client.delete(
            f"/api/v1/auth/sessions/{victim_session}", headers=bearer(attacker)
        )
        assert response.status_code == 404
        assert error_code(response) == "NOT_FOUND"

        # The victim's session is untouched.
        alive = await client.get("/api/v1/auth/me", headers=bearer(victim))
        assert alive.status_code == 200

    async def test_a_session_can_be_revoked_by_id(self, client: AsyncClient) -> None:
        body = await signed_in(client, "byid@example.com")
        response = await client.delete(
            f"/api/v1/auth/sessions/{body['tokens']['session_id']}", headers=bearer(body)
        )
        assert response.status_code == 200
        refused = await client.get("/api/v1/auth/me", headers=bearer(body))
        assert refused.status_code == 401

    async def test_logout_everywhere_spares_the_caller(self, client: AsyncClient, app: Any) -> None:
        body = await signed_in(client, "everywhere@example.com")
        other = await parallel_session(app, "everywhere@example.com")
        assert (await client.get("/api/v1/auth/me", headers=other)).status_code == 200

        response = await client.post("/api/v1/auth/logout-all", headers=bearer(body))
        assert response.status_code == 200
        assert "1 other session" in response.json()["message"]

        assert (await client.get("/api/v1/auth/me", headers=bearer(body))).status_code == 200
        assert (await client.get("/api/v1/auth/me", headers=other)).status_code == 401


# ---------------------------------------------------------------------------
# Password lifecycle
# ---------------------------------------------------------------------------
class TestPasswordLifecycle:
    async def test_changing_a_password_requires_the_current_one(self, client: AsyncClient) -> None:
        body = await signed_in(client, "change@example.com")
        response = await client.post(
            "/api/v1/auth/password/change",
            json={"current_password": OTHER_PASSWORD, "new_password": "Brand-New-Horse-88"},
            headers=bearer(body),
        )
        assert error_code(response) == "INVALID_CREDENTIALS"

    async def test_reusing_the_current_password_is_refused(self, client: AsyncClient) -> None:
        body = await signed_in(client, "reuse@example.com")
        response = await client.post(
            "/api/v1/auth/password/change",
            json={"current_password": PASSWORD, "new_password": PASSWORD},
            headers=bearer(body),
        )
        assert error_code(response) == "PASSWORD_POLICY_REJECTED"
        assert response.json()["error"]["details"]["policy"]

    async def test_a_new_password_works_and_the_old_one_does_not(self, client: AsyncClient) -> None:
        body = await signed_in(client, "rotated-pw@example.com")
        changed = await client.post(
            "/api/v1/auth/password/change",
            json={"current_password": PASSWORD, "new_password": OTHER_PASSWORD},
            headers=bearer(body),
        )
        assert changed.status_code == 200
        payload = changed.json()
        assert payload["sessions_revoked"] >= 1
        assert payload["tokens"]["access_token"], "the caller is signed in again"
        assert (await client.get("/api/v1/auth/me", headers=bearer(payload))).status_code == 200

        assert (await login(client, "rotated-pw@example.com", OTHER_PASSWORD)).status_code == 200
        assert error_code(await login(client, "rotated-pw@example.com", PASSWORD)) == (
            "INVALID_CREDENTIALS"
        )

    async def test_a_reset_request_answers_the_same_way_for_any_address(
        self, client: AsyncClient
    ) -> None:
        await active_user(client, "resettable@example.com")
        known = await client.post(
            "/api/v1/auth/password/reset", json={"email": "resettable@example.com"}
        )
        unknown = await client.post(
            "/api/v1/auth/password/reset", json={"email": "ghost@example.com"}
        )
        assert known.status_code == unknown.status_code == 202
        assert known.json()["message"] == unknown.json()["message"]
        assert unknown.json()["dev_reset_token"] is None

    async def test_a_reset_token_sets_a_new_password_and_ends_every_session(
        self, client: AsyncClient
    ) -> None:
        body = await signed_in(client, "reset-me@example.com")
        requested = await client.post(
            "/api/v1/auth/password/reset", json={"email": "reset-me@example.com"}
        )
        token = requested.json()["dev_reset_token"]
        assert token

        confirmed = await client.post(
            "/api/v1/auth/password/reset/confirm",
            json={"token": token, "new_password": OTHER_PASSWORD},
        )
        assert confirmed.status_code == 200, confirmed.text

        # Including the session that requested it: a reset arrives by email, so the
        # person clicking the link is not necessarily the person holding the session.
        refused = await client.get("/api/v1/auth/me", headers=bearer(body))
        assert refused.status_code == 401

        assert (await login(client, "reset-me@example.com", OTHER_PASSWORD)).status_code == 200

    async def test_a_reset_token_cannot_be_spent_twice(self, client: AsyncClient) -> None:
        await active_user(client, "double-reset@example.com")
        requested = await client.post(
            "/api/v1/auth/password/reset", json={"email": "double-reset@example.com"}
        )
        token = requested.json()["dev_reset_token"]
        first = await client.post(
            "/api/v1/auth/password/reset/confirm",
            json={"token": token, "new_password": OTHER_PASSWORD},
        )
        assert first.status_code == 200
        second = await client.post(
            "/api/v1/auth/password/reset/confirm",
            json={"token": token, "new_password": "Another-Horse-99"},
        )
        assert error_code(second) == "TOKEN_INVALID"

    async def test_a_newer_reset_token_invalidates_the_older_one(self, client: AsyncClient) -> None:
        """Two live tokens would make "the link from the earlier email" an attack."""
        await active_user(client, "supersede@example.com")
        older = (
            await client.post(
                "/api/v1/auth/password/reset", json={"email": "supersede@example.com"}
            )
        ).json()["dev_reset_token"]
        newer = (
            await client.post(
                "/api/v1/auth/password/reset", json={"email": "supersede@example.com"}
            )
        ).json()["dev_reset_token"]
        assert older != newer

        refused = await client.post(
            "/api/v1/auth/password/reset/confirm",
            json={"token": older, "new_password": OTHER_PASSWORD},
        )
        assert error_code(refused) == "TOKEN_INVALID"

        accepted = await client.post(
            "/api/v1/auth/password/reset/confirm",
            json={"token": newer, "new_password": OTHER_PASSWORD},
        )
        assert accepted.status_code == 200


# ---------------------------------------------------------------------------
# The audit trail
# ---------------------------------------------------------------------------
class TestAuditTrail:
    async def test_a_failed_sign_in_is_audited_even_though_the_request_rolled_back(
        self, client: AsyncClient, database: Database
    ) -> None:
        """The whole reason failure entries get a transaction of their own.

        A refusal raises, the request's transaction rolls back, and an entry written
        into that transaction would vanish along with the event it describes — leaving
        an audit log full of successes and no record of anything anybody tried (§53).
        """
        await active_user(client, "audited@example.com")
        response = await login(client, "audited@example.com", OTHER_PASSWORD)
        assert response.status_code == 401

        entries = await audit_actions(database, "AUTH_LOGIN")
        assert entries, "a failed sign-in must leave an audit entry"
        failures = [entry for entry in entries if entry.result.value == "FAILURE"]
        assert failures
        assert failures[0].reason
        assert OTHER_PASSWORD not in (failures[0].reason or "")

    async def test_a_successful_sign_in_is_audited(
        self, client: AsyncClient, database: Database
    ) -> None:
        await signed_in(client, "audited-ok@example.com")
        entries = await audit_actions(database, "AUTH_LOGIN")
        assert [entry for entry in entries if entry.result.value == "SUCCESS"]

    async def test_no_audit_entry_contains_a_submitted_credential(
        self, client: AsyncClient, database: Database
    ) -> None:
        await active_user(client, "leaky@example.com")
        await login(client, "leaky@example.com", OTHER_PASSWORD)
        await client.post("/api/v1/auth/password/reset", json={"email": "leaky@example.com"})

        for entry in await rows(database, select(AuditLog)):
            blob = repr(
                (entry.action, entry.reason, entry.old_value_safe, entry.new_value_safe)
            ).lower()
            assert PASSWORD.lower() not in blob
            assert OTHER_PASSWORD.lower() not in blob
