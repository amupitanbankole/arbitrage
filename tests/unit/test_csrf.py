"""Session-bound CSRF tokens (§59, §61).

The threat model here is a browser that will attach cookies to a cross-site
request on an attacker's behalf. What has to hold:

* a token from one session must not work for another — otherwise an attacker who
  can get a victim's browser to submit *the attacker's own* token has a bypass
  (this is cookie tossing, and it is why the token is bound to the session rather
  than merely compared against a second cookie);
* a token must not be forgeable without the server secret;
* absent, empty and malformed values must all be a plain ``False``;
* an unauthenticated request must never be treated as "no CSRF needed".
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest

from arb_core.security.csrf import CsrfProtector
from arb_core.security.tokens import TokenService, TokenType
from tests.support.config import TEST_JWT_SECRET, TEST_SESSION_SECRET

if TYPE_CHECKING:
    from arb_core.config import Settings

SECRET = TEST_SESSION_SECRET
OTHER_SECRET = "a-different-session-secret-for-cross-key-tests-0123456789abcdefghijklm"

SESSION_ID = UUID("01890b1e-1111-7000-8000-00000000000a")
OTHER_SESSION_ID = UUID("01890b1e-2222-7000-8000-00000000000b")


@pytest.fixture
def protector() -> CsrfProtector:
    return CsrfProtector(secret=SECRET)


@pytest.fixture
def token(protector: CsrfProtector) -> str:
    return protector.issue(session_id=SESSION_ID)


class TestIssuing:
    def test_a_token_is_issued_for_a_session(self, protector: CsrfProtector, token: str) -> None:
        assert token
        assert len(token) == 43  # 32-byte HMAC-SHA256, base64url, unpadded

    def test_the_token_is_cookie_and_header_safe(self, token: str) -> None:
        """It travels in a cookie and a header, so no separators or whitespace."""
        assert all(character.isalnum() or character in "-_" for character in token)
        assert token == token.strip()

    def test_it_is_deterministic_for_a_session(self, protector: CsrfProtector, token: str) -> None:
        """The client must never have to reconcile two live tokens for one session."""
        assert protector.issue(session_id=SESSION_ID) == token

    def test_it_differs_between_sessions(self, protector: CsrfProtector, token: str) -> None:
        assert protector.issue(session_id=OTHER_SESSION_ID) != token

    def test_every_session_gets_its_own_token(self, protector: CsrfProtector) -> None:
        tokens = {protector.issue(session_id=uuid4()) for _ in range(200)}
        assert len(tokens) == 200

    def test_a_session_id_string_is_accepted(self, protector: CsrfProtector, token: str) -> None:
        assert protector.issue(session_id=str(SESSION_ID)) == token

    def test_the_token_discloses_nothing_about_the_session(
        self, protector: CsrfProtector, token: str
    ) -> None:
        """The cookie is readable by the site's own JavaScript, so it is not
        HttpOnly: nothing in it may be worth reading."""
        assert str(SESSION_ID) not in token
        assert SESSION_ID.hex not in token
        assert str(SESSION_ID.bytes) not in token

    def test_the_secret_is_not_embedded(self, token: str) -> None:
        assert SECRET not in token
        assert SECRET[:16] not in token

    def test_the_repr_hides_the_secret(self, protector: CsrfProtector) -> None:
        """A repr can reach a log line via any traceback that formats its holder."""
        assert SECRET not in repr(protector)


class TestVerification:
    def test_a_valid_token_verifies(self, protector: CsrfProtector, token: str) -> None:
        assert protector.verify(token, session_id=SESSION_ID) is True

    def test_a_valid_token_verifies_with_a_string_session_id(
        self, protector: CsrfProtector, token: str
    ) -> None:
        assert protector.verify(token, session_id=str(SESSION_ID)) is True

    def test_surrounding_whitespace_is_tolerated(
        self, protector: CsrfProtector, token: str
    ) -> None:
        """A header value can pick up a space; that is not an attack."""
        assert protector.verify(f"  {token} ", session_id=SESSION_ID) is True

    def test_a_token_from_another_session_is_rejected(
        self, protector: CsrfProtector, token: str
    ) -> None:
        """The cookie-tossing bypass: an attacker submits a token that is valid
        for *their* session against a request authenticated as the victim's."""
        assert protector.verify(token, session_id=OTHER_SESSION_ID) is False

    def test_a_token_cannot_be_moved_between_sessions_in_either_direction(
        self, protector: CsrfProtector
    ) -> None:
        first = protector.issue(session_id=SESSION_ID)
        second = protector.issue(session_id=OTHER_SESSION_ID)
        assert protector.verify(first, session_id=OTHER_SESSION_ID) is False
        assert protector.verify(second, session_id=SESSION_ID) is False

    def test_a_token_from_another_secret_is_rejected(self, token: str) -> None:
        assert CsrfProtector(secret=OTHER_SECRET).verify(token, session_id=SESSION_ID) is False

    @pytest.mark.parametrize("shift", [0, 1, 10, 21, 42])
    def test_a_tampered_token_is_rejected(
        self, protector: CsrfProtector, token: str, shift: int
    ) -> None:
        """Each single-character edit must fail, whatever its position."""
        position = shift % len(token)
        replacement = "A" if token[position] != "A" else "B"
        tampered = token[:position] + replacement + token[position + 1 :]
        assert tampered != token
        assert protector.verify(tampered, session_id=SESSION_ID) is False

    def test_a_truncated_token_is_rejected(self, protector: CsrfProtector, token: str) -> None:
        assert protector.verify(token[:-1], session_id=SESSION_ID) is False
        assert protector.verify(token[:8], session_id=SESSION_ID) is False

    def test_a_padded_token_is_rejected(self, protector: CsrfProtector, token: str) -> None:
        """Base64 padding changes the encoding, not the meaning — and must not
        become a way to make two different tokens compare equal."""
        assert protector.verify(token + "=", session_id=SESSION_ID) is False
        assert protector.verify(token + "==", session_id=SESSION_ID) is False


class TestAbsentAndHostileInput:
    @pytest.mark.parametrize(
        "presented",
        [
            "",
            "   ",
            "\t\n",
            "!",
            "null",
            "undefined",
            "None",
            "true",
            ".",
            "..",
            "a" * 43,
            "Bearer " + "a" * 43,
            f"{SESSION_ID}",
            "arb_csrf=abc",
        ],
    )
    def test_any_wrong_value_is_simply_false(
        self, protector: CsrfProtector, presented: str
    ) -> None:
        """One answer for absent, empty, malformed and incorrect. Distinguishing
        them would let an attacker probe the scheme, and no legitimate client
        needs to know which mistake it made (§71)."""
        assert protector.verify(presented, session_id=SESSION_ID) is False

    @pytest.mark.parametrize("presented", [None, 12345, b"bytes", ["a"], {"token": "x"}, True])
    def test_non_string_values_are_false_not_errors(
        self, protector: CsrfProtector, presented: object
    ) -> None:
        """These come straight off a request, so a hostile type is an ordinary
        input. Raising would turn a bad request into a 500 (§71)."""
        assert protector.verify(presented, session_id=SESSION_ID) is False  # type: ignore[arg-type]

    def test_no_session_means_no_valid_token(self, protector: CsrfProtector, token: str) -> None:
        """Treating "no session" as "no CSRF required" would make *dropping* the
        session cookie a way past the check."""
        assert protector.verify(token, session_id=None) is False

    def test_no_session_and_no_token_is_still_false(self, protector: CsrfProtector) -> None:
        assert protector.verify(None, session_id=None) is False
        assert protector.verify("", session_id=None) is False


class TestConstruction:
    @pytest.mark.parametrize("secret", ["", "   ", "\t"])
    def test_an_empty_secret_is_refused(self, secret: str) -> None:
        """Failing here rather than issuing MACs under an empty key."""
        with pytest.raises(ValueError, match="secret"):
            CsrfProtector(secret=secret)

    @pytest.mark.parametrize("secret", [None, 12345, b"bytes"])
    def test_a_non_string_secret_is_refused(self, secret: object) -> None:
        with pytest.raises(ValueError, match="secret"):
            CsrfProtector(secret=secret)  # type: ignore[arg-type]

    def test_a_malformed_session_id_is_refused(self, protector: CsrfProtector) -> None:
        with pytest.raises(ValueError, match="not a valid UUID"):
            protector.issue(session_id="not-a-uuid")

    def test_a_non_identifier_session_id_is_refused(self, protector: CsrfProtector) -> None:
        with pytest.raises(TypeError, match="UUID or a string"):
            protector.issue(session_id=42)  # type: ignore[arg-type]


class TestKeySeparation:
    def test_from_settings_uses_the_session_secret(self, settings: Settings) -> None:
        from_settings = CsrfProtector.from_settings(settings)
        hand_built = CsrfProtector(secret=TEST_SESSION_SECRET)
        assert from_settings.issue(session_id=SESSION_ID) == hand_built.issue(session_id=SESSION_ID)

    def test_the_jwt_secret_cannot_produce_a_csrf_token(self, settings: Settings) -> None:
        """§60: the two schemes share no key material, so a leak in one does not
        let an attacker mint tokens for the other."""
        csrf = CsrfProtector.from_settings(settings)
        using_jwt_secret = CsrfProtector(secret=TEST_JWT_SECRET)
        token = csrf.issue(session_id=SESSION_ID)
        assert using_jwt_secret.issue(session_id=SESSION_ID) != token
        assert csrf.verify(
            using_jwt_secret.issue(session_id=SESSION_ID), session_id=SESSION_ID
        ) is (False)

    def test_a_csrf_token_is_not_an_access_token(self, settings: Settings, token: str) -> None:
        """Cross-scheme replay in both directions: a CSRF token must not pass as a
        bearer token, and an access token must not pass as a CSRF token."""
        tokens = TokenService.from_settings(settings)
        csrf = CsrfProtector.from_settings(settings)
        access = tokens.issue_access_token(
            user_id=uuid4(), session_id=SESSION_ID, ttl=settings.access_token_ttl
        )
        assert csrf.verify(access, session_id=SESSION_ID) is False
        with pytest.raises(Exception):  # noqa: B017 - any refusal is the point
            tokens.decode(token, expected_type=TokenType.ACCESS)

    def test_the_domain_separation_prefix_is_applied(self, token: str) -> None:
        """A raw HMAC of the session id would let any other MAC over that id be
        replayed here; the ``arb-csrf-v1:`` prefix makes that impossible."""
        import base64
        import hashlib
        import hmac

        naive = (
            base64.urlsafe_b64encode(
                hmac.new(
                    TEST_SESSION_SECRET.encode(), str(SESSION_ID).encode(), hashlib.sha256
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        assert naive != token
