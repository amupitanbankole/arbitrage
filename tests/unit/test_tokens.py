"""JWT access tokens and opaque bearer credentials (§59, §60).

The tests here concentrate on the ways a token check can pass when it should not:
a tampered payload, a token signed with the wrong key, ``alg: none``, a valid
signature but the wrong purpose, a valid token whose session claim is missing, and
two absent secrets comparing equal. Each of those is a complete authentication
bypass rather than a degradation, and none of them is visible in a happy-path test.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from uuid import UUID

import jwt
import pytest

from arb_core.clock import utc_now
from arb_core.errors import AuthenticationError, ConfigurationError, TokenExpiredError
from arb_core.security.tokens import (
    TOKEN_BYTES,
    TokenService,
    TokenType,
    generate_opaque_token,
    hash_opaque_token,
    secrets_equal,
)

# All three are >= 64 bytes so any HMAC algorithm in the platform's allowlist
# accepts them (RFC 7518 3.2 requires the key to be at least the hash output
# length). Shorter test secrets would fail for a reason unrelated to the property
# under test.
SECRET = "unit-test-signing-secret-that-is-long-enough-to-be-plausible-0123456789"
OTHER_SECRET = "a-completely-different-signing-secret-used-for-cross-key-tests-0123456789"
SESSION_SECRET = "the-session-secret-must-never-sign-an-access-token-either-0123456789abcd"
ISSUER = "arbitrage-platform"
AUDIENCE = "arbitrage-platform-api"

USER_ID = UUID("01890b1e-0000-7000-8000-000000000001")
SESSION_ID = UUID("01890b1e-0000-7000-8000-000000000002")


@pytest.fixture
def service() -> TokenService:
    return TokenService(secret=SECRET, issuer=ISSUER, audience=AUDIENCE)


@pytest.fixture
def access_token(service: TokenService) -> str:
    return service.issue_access_token(
        user_id=USER_ID, session_id=SESSION_ID, ttl=timedelta(minutes=15)
    )


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def craft(
    payload: dict[str, object],
    *,
    secret: str = SECRET,
    algorithm: str = "HS256",
    header: dict[str, object] | None = None,
) -> str:
    """Build a JWT by hand, for tests that need a token the service would not issue."""
    if header is not None:
        segments = [
            b64url(json.dumps(header).encode()),
            b64url(json.dumps(payload).encode()),
            "",
        ]
        return ".".join(segments)
    return jwt.encode(payload, secret, algorithm=algorithm)


def epoch(moment: datetime) -> int:
    """Numeric date, as RFC 7519 defines it.

    Integers rather than ``datetime`` objects so the payload can also be
    serialised by hand — which is what forging an ``alg: none`` token requires.
    """
    return int(moment.timestamp())


def valid_payload(**overrides: object) -> dict[str, object]:
    now = utc_now()
    payload: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": str(USER_ID),
        "jti": "01890b1e-0000-7000-8000-0000000000ff",
        "token_use": TokenType.ACCESS.value,
        "sid": str(SESSION_ID),
        "iat": epoch(now),
        "nbf": epoch(now),
        "exp": epoch(now + timedelta(minutes=15)),
    }
    payload.update(overrides)
    return payload


class TestIssuingAndDecoding:
    def test_an_access_token_round_trips(self, service: TokenService, access_token: str) -> None:
        claims = service.decode(access_token, expected_type=TokenType.ACCESS)
        assert claims.subject == USER_ID
        assert claims.session_id == SESSION_ID
        assert claims.token_type is TokenType.ACCESS
        assert claims.issuer == ISSUER
        assert claims.audience == AUDIENCE

    def test_expiry_matches_the_requested_lifetime(
        self, service: TokenService, access_token: str
    ) -> None:
        claims = service.decode(access_token, expected_type=TokenType.ACCESS)
        expected = utc_now() + timedelta(minutes=15)
        assert abs((claims.expires_at - expected).total_seconds()) < 5
        assert 0 < claims.remaining_seconds <= 15 * 60

    def test_every_token_gets_a_unique_identifier(self, service: TokenService) -> None:
        """``jti`` is how an audit entry names a token without quoting it (§53)."""
        ids = {
            service.decode(
                service.issue_access_token(
                    user_id=USER_ID, session_id=SESSION_ID, ttl=timedelta(minutes=5)
                ),
                expected_type=TokenType.ACCESS,
            ).token_id
            for _ in range(20)
        }
        assert len(ids) == 20

    def test_an_mfa_challenge_carries_no_session(self, service: TokenService) -> None:
        """No session exists yet, and creating one early would be the bypass (§59)."""
        token = service.issue_mfa_challenge(user_id=USER_ID, ttl=timedelta(minutes=5))
        claims = service.decode(token, expected_type=TokenType.MFA_CHALLENGE)
        assert claims.session_id is None
        assert claims.subject == USER_ID

    def test_the_token_is_three_base64url_segments(self, access_token: str) -> None:
        assert len(access_token.split(".")) == 3

    @pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1)])
    def test_a_non_positive_lifetime_is_refused(
        self, service: TokenService, ttl: timedelta
    ) -> None:
        """A token that never expires is a credential that can never be rotated."""
        with pytest.raises(ValueError, match="positive"):
            service.issue_access_token(user_id=USER_ID, session_id=SESSION_ID, ttl=ttl)

    @pytest.mark.parametrize(
        ("algorithm", "length", "accepted"),
        [
            ("HS256", 32, True),
            ("HS256", 31, False),
            ("HS384", 48, True),
            ("HS384", 47, False),
            ("HS512", 64, True),
            ("HS512", 63, False),
        ],
    )
    def test_the_key_must_be_long_enough_for_the_algorithm(
        self, algorithm: str, length: int, accepted: bool
    ) -> None:
        """RFC 7518 3.2: an HMAC key must be at least as long as its hash output.

        PyJWT only *warns* about this. A warning in a container log is not a
        control, so the service refuses to be constructed at all — the platform
        would otherwise sign every access token with a key an attacker can
        brute-force offline after any single token leaks.
        """
        secret = "k" * length
        if accepted:
            assert TokenService(
                secret=secret, issuer=ISSUER, audience=AUDIENCE, algorithm=algorithm
            )
        else:
            with pytest.raises(ConfigurationError, match=algorithm):
                TokenService(secret=secret, issuer=ISSUER, audience=AUDIENCE, algorithm=algorithm)

    def test_the_service_requires_its_material(self) -> None:
        with pytest.raises(ValueError, match="signing secret"):
            TokenService(secret="", issuer=ISSUER, audience=AUDIENCE)
        with pytest.raises(ValueError, match="issuer and audience"):
            TokenService(secret=SECRET, issuer="", audience=AUDIENCE)
        with pytest.raises(ValueError, match="issuer and audience"):
            TokenService(secret=SECRET, issuer=ISSUER, audience="")
        with pytest.raises(ValueError, match="leeway"):
            TokenService(secret=SECRET, issuer=ISSUER, audience=AUDIENCE, leeway_seconds=-1)

    def test_from_settings_uses_operator_configuration(self) -> None:
        from arb_core.config import Environment, Settings

        settings = Settings(
            _env_files=None,
            environment=Environment.TEST,
            jwt_secret="a-settings-provided-secret-of-sufficient-length-here-0123456789abcdef",
            jwt_algorithm="HS512",
            jwt_issuer="custom-issuer",
            jwt_audience="custom-audience",
        )
        service = TokenService.from_settings(settings)
        token = service.issue_access_token(
            user_id=USER_ID, session_id=SESSION_ID, ttl=timedelta(minutes=1)
        )
        claims = service.decode(token, expected_type=TokenType.ACCESS)
        assert (claims.issuer, claims.audience) == ("custom-issuer", "custom-audience")
        assert (
            json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==").decode())["alg"]
            == "HS512"
        )


class TestTokenPurposeIsEnforced:
    def test_an_mfa_challenge_is_not_an_access_token(self, service: TokenService) -> None:
        """The central MFA bypass: a correctly-signed token of the wrong purpose.

        The challenge is handed out *after* the password checks but *before* the
        second factor, so accepting it as an access token would reduce MFA to a
        password-only login for every account that enabled it.
        """
        challenge = service.issue_mfa_challenge(user_id=USER_ID, ttl=timedelta(minutes=5))
        with pytest.raises(AuthenticationError) as excinfo:
            service.decode(challenge, expected_type=TokenType.ACCESS)
        assert excinfo.value.context["reason"] == "token_use_mismatch"

    def test_an_access_token_is_not_an_mfa_challenge(
        self, service: TokenService, access_token: str
    ) -> None:
        with pytest.raises(AuthenticationError):
            service.decode(access_token, expected_type=TokenType.MFA_CHALLENGE)

    def test_an_unknown_purpose_is_rejected(self, service: TokenService) -> None:
        token = craft(valid_payload(token_use="admin"))
        with pytest.raises(AuthenticationError) as excinfo:
            service.decode(token, expected_type=TokenType.ACCESS)
        assert excinfo.value.context["reason"] == "unknown_token_use"

    def test_an_access_token_without_a_session_is_rejected(self, service: TokenService) -> None:
        """It would be cryptographically valid and impossible to revoke (§60)."""
        payload = valid_payload()
        payload.pop("sid")
        token = craft(payload)
        with pytest.raises(AuthenticationError) as excinfo:
            service.decode(token, expected_type=TokenType.ACCESS)
        assert excinfo.value.context["reason"] == "missing_session"


class TestSignatureAndClaimValidation:
    def test_a_tampered_payload_is_rejected(self, service: TokenService, access_token: str) -> None:
        header, payload, signature = access_token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "==").decode())
        claims["sub"] = "01890b1e-0000-7000-8000-000000000009"
        forged = ".".join([header, b64url(json.dumps(claims).encode()), signature])
        with pytest.raises(AuthenticationError):
            service.decode(forged, expected_type=TokenType.ACCESS)

    def test_a_tampered_signature_is_rejected(
        self, service: TokenService, access_token: str
    ) -> None:
        header, payload, _ = access_token.split(".")
        with pytest.raises(AuthenticationError):
            service.decode(
                ".".join([header, payload, b64url(b"not-the-real-signature")]),
                expected_type=TokenType.ACCESS,
            )

    def test_a_token_signed_with_another_key_is_rejected(self, service: TokenService) -> None:
        with pytest.raises(AuthenticationError):
            service.decode(
                craft(valid_payload(), secret=OTHER_SECRET), expected_type=TokenType.ACCESS
            )

    def test_the_session_secret_cannot_sign_an_access_token(self, service: TokenService) -> None:
        """Key separation: a leak in one scheme must not compromise the other (§60, §61)."""
        with pytest.raises(AuthenticationError):
            service.decode(
                craft(valid_payload(), secret=SESSION_SECRET), expected_type=TokenType.ACCESS
            )

    def test_alg_none_is_rejected(self, service: TokenService) -> None:
        """The classic JWT forgery: drop the signature and declare no algorithm."""
        token = craft(valid_payload(), header={"alg": "none", "typ": "JWT"})
        assert token.endswith(".")
        with pytest.raises(AuthenticationError):
            service.decode(token, expected_type=TokenType.ACCESS)

    def test_a_different_hmac_strength_is_rejected(self, service: TokenService) -> None:
        """The allowlist is one algorithm, so HS512 cannot be substituted for HS256."""
        with pytest.raises(AuthenticationError):
            service.decode(
                craft(valid_payload(), algorithm="HS512"), expected_type=TokenType.ACCESS
            )

    def test_a_wrong_audience_is_rejected(self, service: TokenService) -> None:
        """A token minted for another service sharing the secret must not work here."""
        with pytest.raises(AuthenticationError):
            service.decode(
                craft(valid_payload(aud="some-other-service")), expected_type=TokenType.ACCESS
            )

    def test_a_wrong_issuer_is_rejected(self, service: TokenService) -> None:
        with pytest.raises(AuthenticationError):
            service.decode(
                craft(valid_payload(iss="not-this-platform")), expected_type=TokenType.ACCESS
            )

    @pytest.mark.parametrize(
        "claim", ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "token_use"]
    )
    def test_a_missing_required_claim_is_rejected(self, service: TokenService, claim: str) -> None:
        """Especially ``exp``: without it a token is immortal."""
        payload = valid_payload()
        payload.pop(claim)
        with pytest.raises(AuthenticationError):
            service.decode(craft(payload), expected_type=TokenType.ACCESS)

    @pytest.mark.parametrize("claim", ["sub", "jti", "sid"])
    def test_a_malformed_identifier_is_rejected(self, service: TokenService, claim: str) -> None:
        with pytest.raises(AuthenticationError) as excinfo:
            service.decode(
                craft(valid_payload(**{claim: "not-a-uuid"})), expected_type=TokenType.ACCESS
            )
        assert excinfo.value.context["reason"] == f"malformed_{claim}"


class TestExpiry:
    def test_an_expired_token_raises_the_refreshable_error(self, service: TokenService) -> None:
        """Distinct from "invalid": the client should refresh, not force a re-login."""
        now = utc_now()
        payload = valid_payload(
            iat=epoch(now - timedelta(hours=2)),
            nbf=epoch(now - timedelta(hours=2)),
            exp=epoch(now - timedelta(minutes=5)),
        )
        with pytest.raises(TokenExpiredError):
            service.decode(craft(payload), expected_type=TokenType.ACCESS)

    def test_a_token_not_yet_valid_is_rejected(self, service: TokenService) -> None:
        now = utc_now()
        payload = valid_payload(
            iat=epoch(now + timedelta(minutes=10)),
            nbf=epoch(now + timedelta(minutes=10)),
            exp=epoch(now + timedelta(minutes=20)),
        )
        with pytest.raises(AuthenticationError):
            service.decode(craft(payload), expected_type=TokenType.ACCESS)

    def test_small_clock_skew_is_tolerated(self, service: TokenService) -> None:
        """Replicas disagree by a second or two even under NTP."""
        now = utc_now()
        payload = valid_payload(
            iat=epoch(now - timedelta(minutes=16)),
            nbf=epoch(now - timedelta(minutes=16)),
            exp=epoch(now - timedelta(seconds=10)),
        )
        claims = service.decode(craft(payload), expected_type=TokenType.ACCESS)
        assert claims.subject == USER_ID

    def test_skew_beyond_the_leeway_is_rejected(self, service: TokenService) -> None:
        now = utc_now()
        payload = valid_payload(
            iat=epoch(now - timedelta(hours=2)),
            nbf=epoch(now - timedelta(hours=2)),
            exp=epoch(now - timedelta(minutes=2)),
        )
        with pytest.raises(TokenExpiredError):
            service.decode(craft(payload), expected_type=TokenType.ACCESS)

    def test_leeway_is_configurable(self) -> None:
        strict = TokenService(secret=SECRET, issuer=ISSUER, audience=AUDIENCE, leeway_seconds=0)
        now = utc_now()
        payload = valid_payload(
            iat=epoch(now - timedelta(minutes=16)),
            nbf=epoch(now - timedelta(minutes=16)),
            exp=epoch(now - timedelta(seconds=1)),
        )
        with pytest.raises(TokenExpiredError):
            strict.decode(craft(payload), expected_type=TokenType.ACCESS)


class TestMalformedInput:
    @pytest.mark.parametrize(
        "presented",
        ["", "   ", "not-a-jwt", "a.b", "a.b.c.d", "Bearer ", "....", "\x00\x01\x02"],
    )
    def test_garbage_is_an_authentication_error_not_a_crash(
        self, service: TokenService, presented: str
    ) -> None:
        """A malformed header must never become a 500 (§71)."""
        with pytest.raises(AuthenticationError):
            service.decode(presented, expected_type=TokenType.ACCESS)

    @pytest.mark.parametrize("presented", [None, 12345, b"raw-bytes", ["a", "b", "c"]])
    def test_non_string_input_is_refused(self, service: TokenService, presented: object) -> None:
        with pytest.raises(AuthenticationError):
            service.decode(presented, expected_type=TokenType.ACCESS)  # type: ignore[arg-type]

    def test_the_rejection_does_not_echo_the_token(self, service: TokenService) -> None:
        """§71/§127: a bearer credential must not be reflected into a log or a response."""
        token = craft(valid_payload(), secret=OTHER_SECRET)
        with pytest.raises(AuthenticationError) as excinfo:
            service.decode(token, expected_type=TokenType.ACCESS)
        rendered = f"{excinfo.value} {excinfo.value.message} {excinfo.value.details}"
        assert token not in rendered
        assert OTHER_SECRET not in rendered
        # The exception type is enough for an operator; the message is not included.
        assert excinfo.value.context["reason"]


class TestOpaqueTokens:
    def test_tokens_are_url_safe_and_unique(self) -> None:
        tokens = {generate_opaque_token() for _ in range(500)}
        assert len(tokens) == 500
        for token in tokens:
            assert token
            assert all(character.isalnum() or character in "-_" for character in token)

    def test_entropy_is_at_least_256_bits(self) -> None:
        # 32 random bytes render as 43 base64url characters.
        assert len(generate_opaque_token()) >= 43
        assert TOKEN_BYTES == 32

    def test_a_prefix_marks_the_token_type_without_disclosing_it(self) -> None:
        token = generate_opaque_token(prefix="rt")
        assert token.startswith("rt_")
        assert all(character.isalnum() or character in "-_" for character in token[3:])

    @pytest.mark.parametrize("nbytes", [0, 8, 15])
    def test_short_tokens_are_refused(self, nbytes: int) -> None:
        with pytest.raises(ValueError, match="128 bits"):
            generate_opaque_token(nbytes=nbytes)


class TestTokenDigests:
    def test_the_digest_is_deterministic_and_fixed_length(self) -> None:
        first = hash_opaque_token("a-refresh-token-value")
        assert first == hash_opaque_token("a-refresh-token-value")
        assert len(first) == 64
        assert all(character in "0123456789abcdef" for character in first)

    def test_different_tokens_digest_differently(self) -> None:
        assert hash_opaque_token("token-a") != hash_opaque_token("token-b")

    def test_the_digest_does_not_contain_the_token(self) -> None:
        """A leaked database must not yield presentable credentials (§83)."""
        token = generate_opaque_token()
        assert token not in hash_opaque_token(token)

    def test_a_generated_token_survives_the_digest_round_trip(self) -> None:
        token = generate_opaque_token(prefix="pw")
        assert secrets_equal(hash_opaque_token(token), hash_opaque_token(token))

    def test_unicode_is_handled_without_error(self) -> None:
        assert len(hash_opaque_token("tökén-value")) == 64


class TestSecretsEqual:
    def test_equal_secrets_match(self) -> None:
        assert secrets_equal("abcdef", "abcdef") is True

    def test_different_secrets_do_not(self) -> None:
        assert secrets_equal("abcdef", "abcdeg") is False
        assert secrets_equal("abcdef", "abcdefg") is False

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (None, None),
            (None, "a-value"),
            ("a-value", None),
            ("", None),
            (None, ""),
        ],
    )
    def test_absent_secrets_never_match(self, left: str | None, right: str | None) -> None:
        """``None == None`` must not become "the CSRF check passed".

        Both values come from request headers and cookies, where "missing" is an
        ordinary input. If two absent values compared equal, omitting a CSRF cookie
        *and* its header would satisfy the check — a bypass reachable by simply
        sending less.
        """
        assert secrets_equal(left, right) is False

    def test_empty_strings_compare_by_value(self) -> None:
        assert secrets_equal("", "") is True
        assert secrets_equal("", "x") is False
