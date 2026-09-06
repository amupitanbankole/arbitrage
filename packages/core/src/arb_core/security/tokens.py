"""Bearer credentials: JWT access tokens and opaque one-time tokens (§59, §60).

Two kinds of credential live here, and the difference is deliberate.

**Access tokens are JWTs.** Short-lived (15 minutes by default), carried in the
``Authorization`` header, and verified cryptographically without a database read.
A JWT proves three things: that this service issued it, that it has not been
tampered with, and that it has not expired. It deliberately does **not** carry a
role or a permission set. Authority is read from the database on every request
instead, because a claim baked into a token is a snapshot: an administrator who
suspends an account or strips a role would otherwise have to wait out the token's
remaining lifetime, and "wait up to 15 minutes for the suspension to take effect"
is not an acceptable answer for a platform that can place live orders (§43).

What the JWT also cannot prove is that the session behind it is still alive. That
is what the server-side session row is for, and both checks are required: the
signature proves the token is genuine, the session row proves it has not been
revoked. Logout, "sign out everywhere" and an administrator's suspension all take
effect on the next request rather than on token expiry.

**Refresh tokens and one-time tokens are opaque random values.** Not JWTs. A
revocable JWT needs a denylist, and a denylist is a database read on every use —
at which point the self-contained structure has bought nothing while creating a
credential that keeps working wherever the denylist is not consulted. A 256-bit
random value whose SHA-256 digest sits in a session row is simpler, strictly
revocable, and leaks nothing about its contents if it is ever written to a log.

Only digests are stored, for refresh tokens exactly as for password-reset and
email-verification tokens: a database read — a leaked backup, a replica, a
compromised analytics query — must not yield a credential that can be presented to
the API (§59, §60, §83).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

import jwt
from jwt import PyJWTError
from jwt.exceptions import ExpiredSignatureError

from arb_core.clock import utc_now
from arb_core.errors import AuthenticationError, ConfigurationError, TokenExpiredError
from arb_core.identifiers import uuid7

if TYPE_CHECKING:
    from arb_core.config import Settings

__all__ = [
    "TOKEN_BYTES",
    "TokenClaims",
    "TokenService",
    "TokenType",
    "generate_opaque_token",
    "hash_opaque_token",
    "secrets_equal",
]

#: Entropy in a generated bearer token. 256 bits is far beyond what is needed to
#: resist guessing; the reason not to go lower is that these values are compared
#: by digest, so a short token would make the digest table worth brute-forcing.
TOKEN_BYTES: Final[int] = 32

#: Claim carrying the token's purpose. Named ``token_use`` rather than ``typ``
#: because ``typ`` already means something else in JOSE (the media type in the
#: *header*), and a reader who confuses the two will mis-review this code.
# S105 (hardcoded password) fires because the identifier contains "token". This is
# a JWT claim *name*, not a credential; suppressed on this line alone.
_TOKEN_USE_CLAIM: Final[str] = "token_use"  # noqa: S105
_SESSION_CLAIM: Final[str] = "sid"

#: Clock skew tolerated when validating ``exp``/``nbf``. Servers in a cluster
#: disagree by a second or two even with NTP, and without leeway a token can be
#: rejected by the replica that happens to be ahead. 30 seconds is small relative
#: to a 15-minute lifetime, so it does not meaningfully extend it.
_DEFAULT_LEEWAY_SECONDS: Final[int] = 30

#: RFC 7518 §3.2 minimum key size per HMAC algorithm: the key must be at least as
#: long as the hash output. Enforced here rather than left to a library warning,
#: because a warning is something an operator may never see while the service
#: happily signs tokens with a key an attacker can brute-force.
_MINIMUM_KEY_BYTES: Final[dict[str, int]] = {"HS256": 32, "HS384": 48, "HS512": 64}

#: Claims every token this service issues must carry. PyJWT enforces presence, so
#: a token minted without an expiry is rejected rather than treated as immortal.
_REQUIRED_CLAIMS: Final[tuple[str, ...]] = (
    "exp",
    "iat",
    "nbf",
    "iss",
    "aud",
    "sub",
    "jti",
    _TOKEN_USE_CLAIM,
)


class TokenType(StrEnum):
    """What a token may be used for.

    Enforced on decode, not on issue: presenting an MFA-challenge token — which is
    handed out *before* the second factor has been verified — to an endpoint that
    expects an access token must fail. Treating "a valid signature" as "sufficient"
    is how MFA gets bypassed entirely (§59).
    """

    #: A fully authenticated request credential.
    ACCESS = "access"
    #: Proof that the password was correct while the second factor is still owed.
    MFA_CHALLENGE = "mfa"


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """A decoded, validated token.

    Every field has been checked: the signature verified, the issuer and audience
    matched, the expiry honoured, the purpose matched what the caller expected, and
    the identifiers parsed. A ``TokenClaims`` instance is therefore safe to act on.
    """

    subject: UUID
    token_id: UUID
    token_type: TokenType
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    issuer: str
    audience: str
    #: The session this token belongs to. ``None`` for an MFA challenge, which is
    #: issued before a session exists.
    session_id: UUID | None

    @property
    def remaining_seconds(self) -> int:
        """Whole seconds of validity left, floored at zero."""
        return max(0, int((self.expires_at - utc_now()).total_seconds()))


class TokenService:
    """Issues and verifies JWTs for this service.

    Stateless and immutable once built, so one instance is shared process-wide.
    """

    __slots__ = ("_algorithm", "_audience", "_issuer", "_leeway", "_secret")

    def __init__(
        self,
        *,
        secret: str,
        issuer: str,
        audience: str,
        algorithm: str = "HS256",
        leeway_seconds: int = _DEFAULT_LEEWAY_SECONDS,
    ) -> None:
        if not secret:
            msg = "a signing secret is required"
            raise ValueError(msg)
        if not issuer or not audience:
            msg = "issuer and audience are both required"
            raise ValueError(msg)
        if leeway_seconds < 0:
            msg = "leeway cannot be negative"
            raise ValueError(msg)
        # An empty secret or issuer is a programming mistake; a *present but weak*
        # key is a deployment misconfiguration, and is reported as one so the
        # operator sees which environment variable to fix.
        minimum = _MINIMUM_KEY_BYTES.get(algorithm)
        key_bytes = len(secret.encode("utf-8"))
        if minimum is not None and key_bytes < minimum:
            msg = (
                f"{algorithm} requires a signing secret of at least {minimum} bytes "
                f"(RFC 7518 3.2); JWT_SECRET is {key_bytes} bytes. Either lengthen "
                f"JWT_SECRET or choose a weaker-hash algorithm deliberately."
            )
            raise ConfigurationError(msg)
        # The algorithm is pinned here and passed as a one-element allowlist on
        # every decode. Accepting whatever the token's header claims is the
        # classic JWT vulnerability: "alg": "none" drops the signature check, and
        # an RS256 token verified with an HS256 key lets a public key be used as
        # an HMAC secret. Configuration already rejects "none" outright.
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._audience = audience
        self._leeway = timedelta(seconds=leeway_seconds)

    @classmethod
    def from_settings(cls, settings: Settings) -> TokenService:
        """Build the service from platform configuration."""
        return cls(
            secret=settings.jwt_secret.get_secret_value(),
            algorithm=settings.jwt_algorithm,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )

    # --- issuing ---------------------------------------------------------
    def issue_access_token(self, *, user_id: UUID, session_id: UUID, ttl: timedelta) -> str:
        """Mint an access token bound to one server-side session (§60)."""
        return self._issue(
            token_type=TokenType.ACCESS,
            user_id=user_id,
            ttl=ttl,
            session_id=session_id,
        )

    def issue_mfa_challenge(self, *, user_id: UUID, ttl: timedelta) -> str:
        """Mint the short-lived "password correct, second factor owed" token.

        Carries no session identifier, because no session exists yet: creating one
        before the second factor is verified would give an attacker who knows a
        password a live session for an MFA-protected account (§59).
        """
        return self._issue(token_type=TokenType.MFA_CHALLENGE, user_id=user_id, ttl=ttl)

    def _issue(
        self,
        *,
        token_type: TokenType,
        user_id: UUID,
        ttl: timedelta,
        session_id: UUID | None = None,
    ) -> str:
        if ttl <= timedelta(0):
            msg = "token lifetime must be positive"
            raise ValueError(msg)
        now = utc_now()
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            # A unique id per token, so a specific token can be named in an audit
            # entry or a revocation list without quoting the token itself (§53).
            "jti": str(uuid7()),
            _TOKEN_USE_CLAIM: token_type.value,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
        }
        if session_id is not None:
            claims[_SESSION_CLAIM] = str(session_id)
        return jwt.encode(claims, self._secret, algorithm=self._algorithm)

    # --- verifying -------------------------------------------------------
    def decode(self, token: str, *, expected_type: TokenType) -> TokenClaims:
        """Validate a token and return its claims, or raise.

        Raises :class:`~arb_core.errors.TokenExpiredError` when the only thing
        wrong is the clock — the client can refresh and retry — and
        :class:`~arb_core.errors.AuthenticationError` for everything else. The two
        are separated because they need different client behaviour, not because
        either discloses more than it should.

        Failure detail goes to ``context``, which is logged server-side and never
        returned to a client (§71, §111): the exception *type* is enough for an
        operator to diagnose, and anything more helps whoever is probing.
        """
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError("Authentication is required.")
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": list(_REQUIRED_CLAIMS)},
            )
        except ExpiredSignatureError as exc:
            raise TokenExpiredError(context={"reason": type(exc).__name__}) from exc
        except PyJWTError as exc:
            # Covers bad signatures, wrong issuer/audience, missing claims,
            # malformed segments and rejected algorithms alike. One answer for all
            # of them: a caller cannot use the differences to learn anything.
            raise AuthenticationError(
                "That sign-in token is not valid.", context={"reason": type(exc).__name__}
            ) from exc

        token_type = _parse_token_type(payload.get(_TOKEN_USE_CLAIM))
        if token_type is not expected_type:
            raise AuthenticationError(
                "That token cannot be used for this operation.",
                context={
                    "presented": token_type.value,
                    "expected": expected_type.value,
                    "reason": "token_use_mismatch",
                },
            )

        session_id = payload.get(_SESSION_CLAIM)
        if token_type is TokenType.ACCESS and session_id is None:
            # An access token with no session cannot be revoked, so it is not an
            # access token this service is willing to honour.
            raise AuthenticationError(
                "That sign-in token is not valid.", context={"reason": "missing_session"}
            )

        return TokenClaims(
            subject=_parse_uuid(payload["sub"], claim="sub"),
            token_id=_parse_uuid(payload["jti"], claim="jti"),
            token_type=token_type,
            issued_at=_parse_timestamp(payload["iat"], claim="iat"),
            not_before=_parse_timestamp(payload["nbf"], claim="nbf"),
            expires_at=_parse_timestamp(payload["exp"], claim="exp"),
            issuer=str(payload["iss"]),
            audience=str(payload["aud"]),
            session_id=_parse_uuid(session_id, claim=_SESSION_CLAIM) if session_id else None,
        )


def _parse_token_type(value: Any) -> TokenType:
    """Return the declared purpose, rejecting anything not in the enum."""
    if isinstance(value, str):
        try:
            return TokenType(value)
        except ValueError:
            pass
    raise AuthenticationError(
        "That sign-in token is not valid.", context={"reason": "unknown_token_use"}
    )


def _parse_uuid(value: Any, *, claim: str) -> UUID:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            pass
    raise AuthenticationError(
        "That sign-in token is not valid.", context={"reason": f"malformed_{claim}"}
    )


def _parse_timestamp(value: Any, *, claim: str) -> datetime:
    """PyJWT yields ``int`` for numeric dates; accept a ``datetime`` too."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, UTC)
    raise AuthenticationError(
        "That sign-in token is not valid.", context={"reason": f"malformed_{claim}"}
    )


# ---------------------------------------------------------------------------
# Opaque bearer tokens
# ---------------------------------------------------------------------------
def generate_opaque_token(*, prefix: str | None = None, nbytes: int = TOKEN_BYTES) -> str:
    """Return a URL-safe random bearer token from the OS CSPRNG.

    An optional short prefix (``rt_``, ``pw_``, ``ev_``) makes a token found in a
    log or pasted into a ticket identifiable by type without disclosing anything
    about it — which is how a leaked credential gets rotated fast.
    """
    if nbytes < 16:
        msg = "bearer tokens must carry at least 128 bits of entropy"
        raise ValueError(msg)
    value = secrets.token_urlsafe(nbytes)
    return f"{prefix}_{value}" if prefix else value


def hash_opaque_token(token: str) -> str:
    """Return the SHA-256 digest stored in place of a bearer token.

    Unsalted and fast, deliberately: the input is a 256-bit random value, so there
    is no dictionary to grind through and a memory-hard hash would add latency to
    every login while buying nothing. Contrast :mod:`arb_core.security.passwords`,
    where the input *is* a human-chosen secret and slow hashing is the whole point.

    Compare digests with :func:`secrets_equal`, never ``==``.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def secrets_equal(left: str | None, right: str | None) -> bool:
    """Compare two secrets in time that does not depend on where they differ.

    ``==`` on strings short-circuits at the first differing byte, which leaks how
    much of a guess was right. For a 256-bit token that is not exploitable, but the
    same helper is used for CSRF tokens and recovery-code digests, where the input
    space is small enough for it to matter — so there is one safe way to do it.

    ``None`` never equals anything, **including another ``None``**. That is not
    pedantry: the values compared here arrive from request headers and cookies, so
    "absent" is a normal input, and if two absent values compared equal then
    omitting both a CSRF cookie and its header would satisfy the check.
    """
    if left is None or right is None:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
