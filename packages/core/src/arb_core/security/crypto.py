"""Envelope encryption for secrets at rest (§12).

Exchange API secrets, TOTP secrets and notification credentials are stored
encrypted in PostgreSQL. The platform is non-custodial — it never holds user funds
and never asks for withdrawal permission — but an API key that can *trade* is still
worth stealing, and a database read must not hand one over in usable form (§12,
§83, §133).

AES-256-GCM, with three properties that matter here:

* **Authenticated.** GCM's tag means a modified ciphertext fails to decrypt rather
  than decrypting to garbage. An attacker with database write access cannot edit an
  encrypted API secret into a different one and wait for the platform to use it.
* **Bound to a context and a purpose.** Both are supplied as additional
  authenticated data, so ciphertext lifted from one row cannot be replayed into
  another. Copying an encrypted TOTP secret into the ``api_secret`` column of a
  different user's exchange credential fails the tag check instead of silently
  decrypting somebody else's second factor.
* **A fresh random nonce per encryption.** Nonce reuse under one GCM key is
  catastrophic — it permits both forgery and recovery of the XOR of two plaintexts.
  The 96-bit random nonce is safe to roughly 2^32 messages per key by the birthday
  bound, which is orders of magnitude beyond this platform's volume, and rotating
  ``ENCRYPTION_KEY`` resets the count.

The stored string is ``v1.<base64url(nonce || ciphertext || tag)>``. The version
prefix exists so a future move to a different construction can be made without a
guess: :meth:`SecretBox.decrypt` reads the prefix and refuses a version it does not
know, rather than trying every scheme until one happens to work.

Key handling: ``ENCRYPTION_KEY`` is the url-safe base64 encoding of 32 random bytes,
validated at startup by :mod:`arb_core.config`. It is never logged — the settings
object stores it as a ``SecretStr`` and :mod:`arb_core.security.redaction` catches
the key name in any mapping that reaches a log handler.
"""

from __future__ import annotations

import base64
import binascii
import os
from typing import TYPE_CHECKING, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from arb_core.errors import ConfigurationError

if TYPE_CHECKING:
    from arb_core.config import Settings

__all__ = ["KEY_BYTES", "SecretBox", "decode_encryption_key"]

#: AES-256.
KEY_BYTES: Final[int] = 32
#: The 96-bit nonce GCM is specified and optimised for.
_NONCE_BYTES: Final[int] = 12
#: Bumped only when the construction changes, never for a data migration.
_FORMAT_VERSION: Final[str] = "v1"
#: Separates context from purpose inside the AAD, so neither may contain it.
_AAD_SEPARATOR: Final[str] = ":"

_KEY_REMEDIATION: Final[str] = (
    "ENCRYPTION_KEY must be a url-safe base64-encoded 32-byte key. Generate one "
    'with: python -c "from cryptography.fernet import Fernet;'
    'print(Fernet.generate_key().decode())"'
)


def decode_encryption_key(value: str) -> bytes:
    """Decode ``ENCRYPTION_KEY`` into the 32 raw bytes AES-256 needs.

    Raises :class:`~arb_core.errors.ConfigurationError` with the remediation
    command rather than a bare decoding error, because this fails at startup and
    the operator needs the fix, not the traceback.
    """
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(_KEY_REMEDIATION)
    try:
        key = base64.urlsafe_b64decode(value.strip().encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise ConfigurationError(_KEY_REMEDIATION) from exc
    if len(key) != KEY_BYTES:
        raise ConfigurationError(
            f"ENCRYPTION_KEY must decode to exactly {KEY_BYTES} bytes, got {len(key)}. "
            f"{_KEY_REMEDIATION}"
        )
    return key


class SecretBox:
    """Encrypts and decrypts application secrets with AES-256-GCM.

    Immutable and cheap to hold, so one instance is built per process from
    settings and shared. It carries no cache: a cache of decrypted secrets would
    be a second copy of every credential sitting in process memory.
    """

    __slots__ = ("_context", "_key")

    def __init__(self, *, key: bytes, context: str) -> None:
        if len(key) != KEY_BYTES:
            msg = f"encryption key must be exactly {KEY_BYTES} bytes"
            raise ValueError(msg)
        if not context.strip():
            msg = "an encryption context is required to bind ciphertext"
            raise ValueError(msg)
        if _AAD_SEPARATOR in context:
            # "a:b" as a context would collide with context "a" and purpose "b",
            # which is exactly the replay the AAD is there to prevent.
            msg = f"encryption context may not contain {_AAD_SEPARATOR!r}"
            raise ValueError(msg)
        self._key = key
        self._context = context.strip()

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretBox:
        """Build the box from platform configuration."""
        return cls(
            key=decode_encryption_key(settings.encryption_key.get_secret_value()),
            context=settings.encryption_context,
        )

    @property
    def context(self) -> str:
        """The binding context, safe to log (it is not a secret)."""
        return self._context

    def __repr__(self) -> str:
        # Never the key. A repr that can reach a log line must not be able to
        # carry the material that decrypts every stored credential (§127).
        return f"SecretBox(context={self._context!r})"

    def encrypt(self, plaintext: str, *, purpose: str) -> str:
        """Return the versioned, base64url ciphertext for ``plaintext``.

        ``purpose`` names what the value is — ``exchange_api_secret``,
        ``totp_secret`` — and is bound into the authentication data, so a
        ciphertext cannot be moved between columns or records.
        """
        text = _require_text(plaintext)
        aad = self._aad(purpose)
        nonce = os.urandom(_NONCE_BYTES)
        sealed = AESGCM(self._key).encrypt(nonce, text.encode("utf-8"), aad)
        payload = base64.urlsafe_b64encode(nonce + sealed).decode("ascii")
        return f"{_FORMAT_VERSION}.{payload}"

    def decrypt(self, ciphertext: str, *, purpose: str) -> str:
        """Return the plaintext, or raise.

        Every failure — malformed, wrong version, tampered, wrong purpose, wrong
        context, wrong key — raises the same
        :class:`~arb_core.errors.ConfigurationError`. Distinguishing them would
        tell an attacker with database write access which of their edits was
        detected, and none of the distinctions change what an operator does: the
        stored value cannot be read with the configured key.

        The error message names the purpose and never carries the ciphertext or
        any fragment of the plaintext (§71, §127, §133).
        """
        stored = _require_text(ciphertext)
        # The purpose is validated before the stored value is parsed. It is a
        # caller contract, and reporting "you passed no purpose" is more useful
        # than reporting that some unreadable blob was unreadable.
        aad = self._aad(purpose)
        version, _, payload = stored.partition(".")
        if version != _FORMAT_VERSION or not payload:
            raise ConfigurationError(
                f"stored secret for {purpose!r} is not in a recognised format",
                context={"purpose": purpose, "reason": "unknown_format_version"},
            )
        try:
            raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
            raise ConfigurationError(
                f"stored secret for {purpose!r} could not be decoded",
                context={"purpose": purpose, "reason": "malformed_payload"},
            ) from exc
        if len(raw) <= _NONCE_BYTES:
            raise ConfigurationError(
                f"stored secret for {purpose!r} is truncated",
                context={"purpose": purpose, "reason": "truncated_payload"},
            )
        nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        try:
            plaintext = AESGCM(self._key).decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            # Raised for tampering, a wrong key, a wrong purpose and a wrong
            # context alike. GCM does not say which, and neither do we.
            raise ConfigurationError(
                f"stored secret for {purpose!r} could not be decrypted with the "
                f"configured key and context",
                context={"purpose": purpose, "reason": "authentication_failed"},
            ) from exc
        return plaintext.decode("utf-8")

    def _aad(self, purpose: str) -> bytes:
        """Build the additional authenticated data binding context and purpose."""
        label = _require_text(purpose).strip()
        if not label:
            msg = "a purpose is required to bind ciphertext"
            raise ValueError(msg)
        if _AAD_SEPARATOR in label:
            msg = f"purpose may not contain {_AAD_SEPARATOR!r}"
            raise ValueError(msg)
        return f"{self._context}{_AAD_SEPARATOR}{label}".encode()


def _require_text(value: object) -> str:
    """Return ``value`` when it is text, and raise otherwise.

    Encrypting ``bytes`` would mean guessing an encoding, and guessing wrong
    produces a ciphertext that decrypts to mojibake long after whoever stored it
    has left — an unrecoverable credential rather than an error at the call site.
    """
    if not isinstance(value, str):
        msg = "value must be a str"
        raise TypeError(msg)
    return value
