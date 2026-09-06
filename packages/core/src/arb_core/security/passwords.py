"""Password hashing and policy (§59).

Two separate concerns live here because conflating them is how weak-password bugs
survive review:

* :class:`PasswordHasher` — the cryptographic part. Which algorithm, which
  parameters, how a stored hash is verified, and when a hash must be re-issued.
* :class:`PasswordPolicy` — the product rule. What a user may choose in the first
  place.

Hashing
-------
``argon2id`` is the default: OWASP's first recommendation, and memory-hard, so a
GPU farm buys an attacker far less than it does against bcrypt or PBKDF2.
``bcrypt`` remains selectable for hosts where a 64 MiB per-hash memory cost is not
affordable.

:meth:`PasswordHasher.verify` dispatches on the scheme encoded **in the stored
hash**, not on the configured one. That single detail is what makes a scheme change
survivable: after an operator flips ``PASSWORD_HASH_SCHEME`` from bcrypt to
argon2id, existing accounts still authenticate, :meth:`needs_rehash` reports
``True`` for them, and the login path re-hashes onto the new scheme transparently.
Verifying against the *configured* scheme instead would lock every existing user
out at the moment of the switch.

Timing
------
A login attempt for an account that does not exist would otherwise return in
microseconds while a real account costs ~100 ms of argon2 work. That difference is
measurable over a network and is a user-enumeration oracle as reliable as an error
message. :meth:`PasswordHasher.verify_unknown_account` spends equivalent CPU on a
throwaway hash so both paths take the same time.

Policy
------
The rules follow NIST SP 800-63B §5.1.1.2 rather than the older convention of
demanding mixed character classes:

* a minimum length (12 by default) and a maximum,
* comparison against the account's own email address and display name,
* comparison against a list of commonly-used passwords,
* **no** composition rules and **no** periodic expiry.

Forcing "Tr0ub4dor&3" does not make passwords harder to guess — it makes them
harder to remember, which pushes people towards writing them down and reusing them
across sites. Length and blocklist screening are what actually raise the cost of an
attack. Screening against a breached-password corpus (the k-anonymity API published
by Have I Been Pwned) is **not implemented**: it needs an outbound network call on
the request path, which this platform does not make. The bundled blocklist is a
local floor, not a substitute, and :meth:`PasswordPolicy.describe` says so
explicitly rather than implying a check that does not happen.

Nothing in this module ever puts a password into an error message, a log field or
an exception ``repr`` (§71, §127, §133).
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

import argon2
import bcrypt
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from arb_core.errors import PasswordPolicyError, ValidationError

if TYPE_CHECKING:
    from arb_core.config import PasswordHashScheme, Settings

__all__ = [
    "BCRYPT_MAX_INPUT_BYTES",
    "PasswordHasher",
    "PasswordPolicy",
    "normalize_password",
    "scheme_of",
]

#: Scheme identifiers as they appear in a stored hash's ``$...$`` prefix.
ARGON2_PREFIXES: Final[frozenset[str]] = frozenset({"argon2id", "argon2i", "argon2d"})
BCRYPT_PREFIXES: Final[frozenset[str]] = frozenset({"2a", "2b", "2y", "2x"})

#: bcrypt's hard input limit, in **bytes**. Everything past it is discarded
#: silently, which is why the hasher rejects longer input rather than truncating
#: it — see :meth:`PasswordHasher._encode`.
BCRYPT_MAX_INPUT_BYTES: Final[int] = 72

_HASH_LENGTH: Final[int] = 32
_SALT_LENGTH: Final[int] = 16
_BCRYPT_SCHEME: Final[str] = "bcrypt"
_BCRYPT_ROUNDS_DEFAULT: Final[int] = 12
_BCRYPT_ROUNDS_RE: Final[re.Pattern[str]] = re.compile(r"^\$2[abxy]\$(\d{2})\$")

#: Commonly-chosen passwords, screened locally (§59).
#:
#: A floor rather than a defence in depth: the top few dozen guesses account for a
#: large share of successful credential stuffing, and rejecting them costs
#: nothing. A real breached-corpus check needs a network call and is not
#: implemented — see the module docstring.
_COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "111111",
        "123123",
        "abcdef",
        "abcdefg",
        "abcd1234",
        "admin",
        "administrator",
        "arbitrage",
        "arbitrageplatform",
        "bitcoin",
        "changeme",
        "crypto",
        "cryptocurrency",
        "default",
        "ethereum",
        "hunter2",
        "iloveyou",
        "letmein",
        "monkey",
        "mustchangepassword",
        "p@ssw0rd",
        "passw0rd",
        "password",
        "password1",
        "password123",
        "password1234",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "secret",
        "superuser",
        "test",
        "test1234",
        "trader",
        "trading",
        "trustno1",
        "welcome",
        "welcome1",
        "zaq12wsx",
    }
)

#: Identifiers shorter than this are not screened against the password: "Al" or
#: "Jo" appear inside ordinary passphrases, and rejecting on them is noise that
#: teaches people to distrust the rule.
_MIN_IDENTIFIER_LENGTH: Final[int] = 4


def _require_text(value: object) -> str:
    """Return ``value`` when it is text, and raise otherwise.

    The public signatures are annotated ``str``, so a checker treats the negative
    branch as unreachable. The guard still earns its place: a caller holding
    ``Any`` — a decoded JSON body, an untyped worker payload — can pass ``bytes``,
    and quietly encoding those with a guessed codec would let two different
    passwords produce the same hash. Refusing is the only safe answer.
    """
    if not isinstance(value, str):
        msg = "password must be a str"
        raise TypeError(msg)
    return value


def normalize_password(password: str) -> str:
    """Return the canonical form of a password before hashing.

    Unicode NFKC, per NIST SP 800-63B §5.1.1.2. Without it, two visually identical
    passwords that differ in composition — a precomposed ``é`` versus ``e`` plus a
    combining acute, or full-width digits from a CJK input method — hash
    differently, and a user retyping their password on another device is locked out
    of their own account with no way to diagnose why.

    Whitespace is deliberately **not** stripped: leading and trailing spaces are
    part of a passphrase, and silently removing them would make two different
    passphrases equivalent.
    """
    return unicodedata.normalize("NFKC", password)


def scheme_of(stored_hash: str | None) -> str | None:
    """Return the algorithm encoded in a stored password hash, or ``None``.

    Used to report how many accounts remain on a superseded scheme — an operator
    migrating from bcrypt to argon2id needs that number to know when the migration
    has finished, since it only advances as people sign in.
    """
    if not stored_hash or not stored_hash.startswith("$"):
        return None
    parts = stored_hash.split("$")
    if len(parts) < 3:
        return None
    identifier = parts[1]
    if identifier in ARGON2_PREFIXES:
        return identifier
    if identifier in BCRYPT_PREFIXES:
        return _BCRYPT_SCHEME
    return None


class PasswordHasher:
    """Hash and verify passwords with the configured scheme (§59).

    Instances are immutable once built and cheap to hold, so one is created per
    process from settings rather than per request.
    """

    __slots__ = ("_argon2", "_bcrypt_rounds", "_dummy_hash", "_scheme")

    def __init__(
        self,
        *,
        scheme: PasswordHashScheme,
        time_cost: int = 3,
        memory_cost_kib: int = 65536,
        parallelism: int = 4,
        bcrypt_rounds: int = _BCRYPT_ROUNDS_DEFAULT,
    ) -> None:
        if time_cost < 1 or memory_cost_kib < 1 or parallelism < 1:
            msg = "argon2 cost parameters must all be positive"
            raise ValueError(msg)
        self._scheme = str(scheme)
        self._bcrypt_rounds = bcrypt_rounds
        self._argon2 = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=_HASH_LENGTH,
            salt_len=_SALT_LENGTH,
            type=argon2.Type.ID,
        )
        # Built on first use: a process that never handles an unknown-account
        # login should not pay for a hash it will never need.
        self._dummy_hash: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> PasswordHasher:
        """Build a hasher from platform configuration."""
        return cls(
            scheme=settings.password_hash_scheme,
            time_cost=settings.argon2_time_cost,
            memory_cost_kib=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            bcrypt_rounds=settings.bcrypt_rounds,
        )

    # --- introspection ---------------------------------------------------
    @property
    def scheme(self) -> str:
        """The scheme new hashes are written with."""
        return self._scheme

    def __repr__(self) -> str:
        # Parameters only. Nothing here is secret, but a repr that can reach a log
        # line must never be able to carry one.
        return f"PasswordHasher(scheme={self._scheme!r})"

    # --- hashing ---------------------------------------------------------
    def hash(self, password: str) -> str:
        """Return a salted hash of ``password`` in the configured scheme.

        The salt is generated by the underlying library from the OS CSPRNG and is
        embedded in the returned string, which is the standard self-describing
        modular-crypt format (``$argon2id$v=19$m=...,t=...,p=...$salt$hash``).
        """
        encoded = self._encode(password)
        if self._scheme == _BCRYPT_SCHEME:
            salt = bcrypt.gensalt(rounds=self._bcrypt_rounds)
            return bcrypt.hashpw(encoded, salt).decode("ascii")
        return self._argon2.hash(encoded)

    def verify(self, password: str, stored_hash: str | None) -> bool:
        """Return whether ``password`` matches ``stored_hash``.

        Never raises for a wrong password, a malformed hash, a hash from an
        unrecognised scheme, or input that cannot be encoded: all of those are
        simply "not a match", and the caller turns that into one identical
        :class:`~arb_core.errors.InvalidCredentialsError`. Letting a corrupt hash
        surface as a 500 would tell an attacker which accounts hold one.
        """
        if not stored_hash or not isinstance(password, str) or "\x00" in password:
            return False
        scheme = scheme_of(stored_hash)
        if scheme is None:
            return False
        encoded = normalize_password(password).encode("utf-8")
        try:
            if scheme == _BCRYPT_SCHEME:
                # A password longer than bcrypt's input limit cannot have produced
                # this hash; checkpw would raise, so answer directly.
                if len(encoded) > BCRYPT_MAX_INPUT_BYTES:
                    return False
                return bcrypt.checkpw(encoded, stored_hash.encode("ascii"))
            return self._argon2.verify(stored_hash, encoded)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        except (ValueError, TypeError, UnicodeError):
            # A stored hash that is not decodable, or a bcrypt variant this build
            # rejects. Still "no match"; the caller's audit path records the
            # failure without the password.
            return False

    def verify_unknown_account(self, password: str) -> None:
        """Spend the CPU a real verification would have spent, then discard it.

        Called on the path where the email address matched no account. Its only
        purpose is to make that path indistinguishable by timing from one where a
        real hash was checked.
        """
        if self._dummy_hash is None:
            # A throwaway hash of a random password, generated per process so no
            # attacker can precompute against a known constant.
            self._dummy_hash = self.hash(secrets.token_urlsafe(32))
        self.verify(password, self._dummy_hash)

    def needs_rehash(self, stored_hash: str | None) -> bool:
        """Return whether a successful verification should re-issue the hash.

        ``True`` when the hash is missing, unrecognised, written by a different
        scheme than the configured one, or written with weaker parameters than the
        current configuration. This is what lets an operator raise
        ``ARGON2_TIME_COST`` or migrate off bcrypt and have the account population
        follow, one sign-in at a time, without a forced password reset.
        """
        scheme = scheme_of(stored_hash)
        if scheme is None:
            return True
        if scheme != self._scheme:
            return True
        if scheme == _BCRYPT_SCHEME:
            match = _BCRYPT_ROUNDS_RE.match(stored_hash or "")
            if match is None:
                return True
            return int(match.group(1)) != self._bcrypt_rounds
        return self._argon2.check_needs_rehash(stored_hash or "")

    # --- internals -------------------------------------------------------
    def _encode(self, password: str) -> bytes:
        """Normalise and encode a password, refusing input that cannot be hashed.

        The checks raise rather than clamp. Silently truncating a password is
        exactly what bcrypt does by default, and it is a vulnerability: two
        passwords sharing a 72-byte prefix become interchangeable, so an attacker
        who learns one can authenticate as the other.
        """
        password = _require_text(password)
        if "\x00" in password:
            # Both libraries reject NUL, but with an internal error that would
            # surface as a 500 on the registration path.
            raise ValidationError(
                "passwords may not contain NUL characters",
                details={"password": ["must not contain NUL characters"]},
            )
        normalised = normalize_password(password)
        encoded = normalised.encode("utf-8")
        if self._scheme == _BCRYPT_SCHEME and len(encoded) > BCRYPT_MAX_INPUT_BYTES:
            raise ValidationError(
                f"password exceeds bcrypt's {BCRYPT_MAX_INPUT_BYTES}-byte input limit",
                details={"password": [f"must be at most {BCRYPT_MAX_INPUT_BYTES} bytes"]},
            )
        return encoded


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """What a user may choose as a password (§59).

    Immutable and cheap, so it is built once from settings and shared.

    ``max_bytes`` is ``None`` unless the configured scheme has a byte-level input
    limit (bcrypt's 72). It is a field rather than something derived at validation
    time so that the policy stays a plain value object and stays testable without
    constructing a hasher.
    """

    min_length: int = 12
    max_length: int = 128
    max_bytes: int | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> PasswordPolicy:
        """Build the policy from platform configuration."""
        is_bcrypt = str(settings.password_hash_scheme) == _BCRYPT_SCHEME
        return cls(
            min_length=settings.password_min_length,
            max_length=settings.password_max_length,
            max_bytes=BCRYPT_MAX_INPUT_BYTES if is_bcrypt else None,
        )

    def validate(
        self,
        password: str,
        *,
        email: str | None = None,
        display_name: str | None = None,
    ) -> None:
        """Raise :class:`~arb_core.errors.PasswordPolicyError` if unacceptable.

        Every rejection reason is safe to show the person choosing the password —
        telling them is the point — but none of them echoes the password back, in
        whole or in part (§71).
        """
        normalised = normalize_password(_require_text(password))
        problems: list[str] = []

        if len(normalised) < self.min_length:
            problems.append(f"must be at least {self.min_length} characters")
        if len(normalised) > self.max_length:
            problems.append(f"must be at most {self.max_length} characters")
        if normalised and not normalised.strip():
            problems.append("must contain non-whitespace characters")
        if self.max_bytes is not None and len(normalised.encode("utf-8")) > self.max_bytes:
            problems.append(f"must be at most {self.max_bytes} bytes")

        if not problems:
            problems.extend(
                self._screen_content(normalised, email=email, display_name=display_name)
            )

        if problems:
            raise PasswordPolicyError(
                details={"password": problems},
                # Server-side context only, and even here the password is reduced
                # to its length: enough to settle a policy dispute, never enough to
                # write the secret into a log line (§127).
                context={
                    "password_length": len(normalised),
                    "email_present": email is not None,
                    "min_length": self.min_length,
                },
            )

    def _screen_content(
        self, normalised: str, *, email: str | None, display_name: str | None
    ) -> list[str]:
        """Blocklist and account-identifier screening; length rules already passed."""
        lowered = normalised.lower()
        # Screening also tries the trimmed form. Whitespace is *kept* in the
        # password — a trailing space is part of a passphrase and stripping it
        # would merge two different secrets — but "  password1234  " is the same
        # weak guess with padding, usually from a paste, and must not get through
        # just because the blocklist entry has no spaces.
        trimmed = lowered.strip()
        if lowered in _COMMON_PASSWORDS or trimmed in _COMMON_PASSWORDS:
            return ["is a commonly-used password"]
        if trimmed and len(set(trimmed)) == 1:
            return ["must not be a single repeated character"]

        for value, label in ((email, "email address"), (display_name, "display name")):
            if not value:
                continue
            candidate = value.strip().lower()
            if len(candidate) < _MIN_IDENTIFIER_LENGTH:
                continue
            local_part = candidate.split("@", 1)[0]
            if lowered == candidate or candidate in lowered:
                return [f"must not contain your {label}"]
            if len(local_part) >= _MIN_IDENTIFIER_LENGTH and local_part in lowered:
                return [f"must not contain your {label}"]
        return []

    def describe(self) -> dict[str, Any]:
        """The policy as a client-safe dictionary, for the sign-up form (§68).

        Published so the frontend can check before submitting, which is a
        convenience only: :meth:`validate` on the server is the control (§43). The
        two ``False`` values are as important as the ``True`` ones — they state
        which checks this platform does *not* perform.
        """
        return {
            "min_length": self.min_length,
            "max_length": self.max_length,
            "max_bytes": self.max_bytes,
            "checks_common_passwords": True,
            "checks_account_identifiers": True,
            "requires_character_classes": False,
            "expires_periodically": False,
            "screened_against_breach_corpus": False,
        }
