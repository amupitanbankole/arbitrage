"""Time-based one-time passwords — RFC 6238 / RFC 4226 (§59).

The second factor for sign-in, and the only MFA scheme implemented. TOTP is
chosen over SMS because a phone number is portable by an attacker through carrier
social engineering, and over WebAuthn because a passkey cannot be handed to a
support agent over the phone — which matters for a platform whose users trade real
money and will call when they are locked out.

Correctness here is checkable rather than arguable: :func:`hotp` and
:func:`totp_code` reproduce the published test vectors from RFC 4226 Appendix D and
RFC 6238 Appendix B exactly, including the SHA-256 and SHA-512 variants. A test
that only asserted "the code I generated verifies" would pass for an implementation
that no authenticator app agrees with, which is the failure mode that matters —
the user's phone is the second implementation, and it is not ours to change.

Security notes:

* **Constant-time comparison.** Candidate codes are compared with
  :func:`hmac.compare_digest`. Every candidate in the drift window is compared and
  the result accumulated, rather than returning on the first match, so the time
  taken does not depend on where in the window the code landed.
* **The drift window is a brute-force surface.** Each extra accepted step widens
  the window in which a guessed 6-digit code succeeds by two attempts' worth. The
  default is one step either side (±30 s), which absorbs ordinary phone-vs-server
  clock skew; configuration caps it at four.
* **Replay is not prevented here.** A code that has been used must be rejected at
  the service layer by recording the step it was consumed at — see
  ``users.last_totp_step``. This module is stateless by design.
* **Secrets are encrypted at rest** by the caller (:mod:`arb_core.security.crypto`),
  never stored as plaintext: a TOTP secret is a permanent credential, and unlike a
  password it cannot be reset by the person who owns it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import secrets
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

from arb_core.errors import ValidationError

if TYPE_CHECKING:
    from datetime import datetime

    from arb_core.config import Settings

__all__ = [
    "RECOVERY_CODE_LENGTH",
    "TotpConfig",
    "generate_recovery_codes",
    "hash_recovery_code",
    "hotp",
    "new_totp_secret",
    "normalise_recovery_code",
    "provisioning_uri",
    "totp_code",
    "totp_step",
    "verify_totp",
]

#: 160-bit secrets, per RFC 4226 §4's recommendation.
_SECRET_BYTES: Final[int] = 20

#: Recovery-code alphabet excludes ``I``, ``O``, ``0`` and ``1``. These codes are
#: read aloud over the phone and typed by hand into a form; an alphabet where
#: ``O`` and ``0`` are distinct symbols turns a support call into a guessing game.
_RECOVERY_ALPHABET: Final[str] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECOVERY_CODE_LENGTH: Final[int] = 10

# SHA-1 here is not a weakness to fix: RFC 6238 defines the HMAC construction and
# every authenticator app implements SHA-1 by default. HMAC-SHA1 has no known
# practical attack — the breaks against SHA-1 are collisions on the bare hash,
# which HMAC does not rely on — and refusing it would mean refusing to
# interoperate with Google Authenticator and every app like it. SHA-256/512 are
# supported for deployments that want them.
#
# Values are digest *names* rather than hashlib constructors: ``hmac.new`` accepts
# a name, and a name keeps this table an allowlist instead of a place where an
# arbitrary callable could be registered.
_ALGORITHMS: Final[dict[str, str]] = {
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA512": "sha512",
}

_MAX_DIGITS: Final[int] = 10


@dataclass(frozen=True, slots=True)
class TotpConfig:
    """TOTP parameters. Immutable, so one instance can be shared safely."""

    period_seconds: int = 30
    digits: int = 6
    algorithm: str = "SHA1"
    #: Accepted steps either side of the current one (see the module docstring).
    drift_steps: int = 1

    def __post_init__(self) -> None:
        if self.period_seconds < 1:
            msg = "TOTP period must be at least one second"
            raise ValueError(msg)
        if not 1 <= self.digits <= _MAX_DIGITS:
            msg = f"TOTP digits must be between 1 and {_MAX_DIGITS}"
            raise ValueError(msg)
        if self.algorithm not in _ALGORITHMS:
            msg = f"unsupported TOTP algorithm {self.algorithm!r}; allowed: {sorted(_ALGORITHMS)}"
            raise ValueError(msg)
        if self.drift_steps < 0:
            msg = "TOTP drift window cannot be negative"
            raise ValueError(msg)

    @classmethod
    def from_settings(cls, settings: Settings) -> TotpConfig:
        """Build the configuration an operator has chosen."""
        return cls(
            period_seconds=settings.mfa_totp_period_seconds,
            digits=settings.mfa_totp_digits,
            drift_steps=settings.mfa_totp_drift_steps,
        )

    @property
    def candidate_steps(self) -> tuple[int, ...]:
        """Step offsets to try, current step first then alternating outwards.

        Ordered so the overwhelmingly common case — no skew at all — is the first
        comparison, and so the ordering is not itself a hint about skew direction.
        """
        offsets: list[int] = [0]
        for delta in range(1, self.drift_steps + 1):
            offsets.extend((-delta, delta))
        return tuple(offsets)


def _decode_secret(secret: object) -> bytes:
    """Decode a base32 secret, tolerating the formatting humans actually type.

    Authenticator apps and printed recovery sheets present secrets in groups of
    four characters, sometimes lower-case, sometimes with the ``=`` padding
    stripped. Rejecting those forms would fail users who copied their secret
    correctly.
    """
    text = _as_text(secret)
    if text is None:
        msg = "TOTP secret must be a str"
        raise TypeError(msg)
    compact = "".join(text.split()).replace("-", "").upper().rstrip("=")
    if not compact:
        raise ValidationError("A two-factor secret is required.", details={"secret": ["required"]})
    # base32 operates on 8-character groups; restore the padding the app omitted.
    padded = compact + "=" * (-len(compact) % 8)
    try:
        decoded = base64.b32decode(padded, casefold=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError(
            "That two-factor secret is not valid.", details={"secret": ["not base32"]}
        ) from exc
    if not decoded:
        raise ValidationError("That two-factor secret is not valid.", details={"secret": ["empty"]})
    return decoded


def _as_text(value: object) -> str | None:
    """Return ``value`` when it is text, otherwise ``None``.

    The public signatures are annotated ``str``, but these values arrive from a
    request body, a database column or a QR-scanning client. On an authentication
    path a non-string must produce "reject", never ``AttributeError`` turning into
    a 500 — a 500 on login is both a worse answer and a louder signal than a
    failed code.
    """
    return value if isinstance(value, str) else None


def new_totp_secret(*, length_bytes: int = _SECRET_BYTES) -> str:
    """Return a fresh base32 TOTP secret from the OS CSPRNG."""
    if length_bytes < 16:
        # RFC 4226 requires at least 128 bits; 160 is the recommended default.
        msg = "TOTP secret must be at least 16 bytes"
        raise ValueError(msg)
    return base64.b32encode(secrets.token_bytes(length_bytes)).decode("ascii").rstrip("=")


def totp_step(at: datetime, *, period_seconds: int = 30) -> int:
    """Return the RFC 6238 time step for an aware UTC timestamp.

    Naive timestamps are refused rather than assumed to be UTC. Guessing here would
    make a code verify for eight hours on one machine and not another (§75).
    """
    if at.tzinfo is None or at.tzinfo.utcoffset(at) is None:
        msg = "TOTP timestamps must be timezone-aware UTC"
        raise ValueError(msg)
    return math.floor(at.timestamp() / period_seconds)


def hotp(key: bytes, counter: int, *, digits: int = 6, algorithm: str = "SHA1") -> str:
    """RFC 4226 HOTP: the truncated HMAC of a counter."""
    if counter < 0:
        msg = "HOTP counter cannot be negative"
        raise ValueError(msg)
    digest = hmac.new(key, struct.pack(">Q", counter), _ALGORITHMS[algorithm]).digest()
    # Dynamic truncation (RFC 4226 §5.3): the low nibble of the final byte is an
    # offset into the digest, and four bytes from there become the code.
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp_code(secret: str, *, at: datetime, config: TotpConfig | None = None) -> str:
    """Return the code an authenticator app displays for ``secret`` at ``at``."""
    resolved = config or TotpConfig()
    key = _decode_secret(secret)
    step = totp_step(at, period_seconds=resolved.period_seconds)
    return hotp(key, step, digits=resolved.digits, algorithm=resolved.algorithm)


def verify_totp(
    secret: str,
    code: str,
    *,
    at: datetime,
    config: TotpConfig | None = None,
) -> int | None:
    """Return the step ``code`` matched, or ``None`` if it did not.

    The returned step is what the caller records as "consumed", so a code cannot be
    replayed inside its own drift window. ``None`` means reject.

    Every candidate is compared and the outcome accumulated rather than returning
    on the first hit, so the elapsed time does not reveal where in the window a
    correct code sat.
    """
    resolved = config or TotpConfig()
    presented = _normalise_code(code, digits=resolved.digits)
    if presented is None:
        return None
    key = _decode_secret(secret)
    current = totp_step(at, period_seconds=resolved.period_seconds)

    matched: int | None = None
    for offset in resolved.candidate_steps:
        step = current + offset
        if step < 0:
            continue
        expected = hotp(key, step, digits=resolved.digits, algorithm=resolved.algorithm)
        # compare_digest, not ==: a byte-at-a-time comparison of a 6-digit code
        # leaks its prefix through timing, and a 10^6 keyspace is small enough for
        # that to matter.
        if hmac.compare_digest(expected, presented) and matched is None:
            matched = step
    return matched


def _normalise_code(code: object, *, digits: int) -> str | None:
    """Return a code as exactly ``digits`` characters, or ``None`` if malformed.

    Spaces and dashes are removed because authenticator apps and recovery sheets
    both group digits. A code of the wrong length is rejected outright: comparing
    it would either fail anyway or, with a zero-padded comparison, accept something
    the user did not actually have.
    """
    text = _as_text(code)
    if text is None:
        return None
    compact = "".join(text.split()).replace("-", "")
    if len(compact) != digits or not compact.isdigit():
        return None
    return compact


def provisioning_uri(
    secret: str,
    *,
    account_name: str,
    issuer: str,
    config: TotpConfig | None = None,
) -> str:
    """Return the ``otpauth://`` URI an authenticator app scans (§59).

    The issuer is embedded in the label as well as given as a parameter, because
    several apps display only the label — without it, a user with accounts on two
    platforms sees two identical entries and cannot tell which is which.
    """
    resolved = config or TotpConfig()
    if not account_name.strip():
        msg = "account_name is required for a provisioning URI"
        raise ValueError(msg)
    if not issuer.strip():
        msg = "issuer is required for a provisioning URI"
        raise ValueError(msg)
    label = quote(f"{issuer}:{account_name}", safe="")
    params = "&".join(
        (
            f"secret={quote(secret, safe='')}",
            f"issuer={quote(issuer, safe='')}",
            f"algorithm={quote(resolved.algorithm, safe='')}",
            f"digits={resolved.digits}",
            f"period={resolved.period_seconds}",
        )
    )
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------
def generate_recovery_codes(count: int, *, length: int = RECOVERY_CODE_LENGTH) -> tuple[str, ...]:
    """Return ``count`` single-use recovery codes in a human-transcribable form.

    Codes are returned in plaintext exactly once, at generation. Only their digests
    are stored (:func:`hash_recovery_code`), so a database compromise does not hand
    over the one credential that bypasses the second factor.
    """
    if count < 1:
        msg = "at least one recovery code is required"
        raise ValueError(msg)
    if length < 8:
        msg = "recovery codes must be at least 8 characters"
        raise ValueError(msg)
    codes: list[str] = []
    seen: set[str] = set()
    while len(codes) < count:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(length))
        if raw in seen:
            continue
        seen.add(raw)
        midpoint = length // 2
        codes.append(f"{raw[:midpoint]}-{raw[midpoint:]}")
    return tuple(codes)


def normalise_recovery_code(code: str) -> str:
    """Canonical form of a recovery code: upper-case, alphanumeric only."""
    text = _as_text(code)
    if text is None:
        msg = "recovery code must be a str"
        raise TypeError(msg)
    return "".join(ch for ch in text.upper() if ch.isalnum())


def hash_recovery_code(code: str) -> str:
    """Return the SHA-256 digest stored in place of a recovery code.

    Unsalted, deliberately: the value being hashed is a 50-bit random secret, so
    there is no dictionary to attack and a salt would only make the stored digest
    bigger. Contrast :func:`hash_secret_token`'s reasoning — same conclusion, same
    reason.

    Callers must compare digests with :func:`hmac.compare_digest`.
    """
    return hashlib.sha256(normalise_recovery_code(code).encode("utf-8")).hexdigest()
