"""Envelope encryption for secrets at rest (§12, §83, §133).

The property under test is not "encrypt then decrypt returns the input" — that
passes for almost any implementation, including broken ones. It is that a stored
ciphertext cannot be read, moved or edited:

* a modified ciphertext must fail rather than decrypt to garbage (authentication);
* a ciphertext must not work under a different purpose, context or key (binding);
* encrypting the same secret twice must not produce the same bytes (nonce freshness);
* no failure path may disclose the plaintext or the ciphertext.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from arb_core.errors import ConfigurationError
from arb_core.security.crypto import KEY_BYTES, SecretBox, decode_encryption_key
from tests.support.config import TEST_ENCRYPTION_KEY

if TYPE_CHECKING:
    from arb_core.config import Settings

# A second valid key, for the "wrong key" cases. Both are real 32-byte keys in
# url-safe base64, so a failure means the binding failed and not that parsing did.
OTHER_KEY = "gwJkzppyb-OX5v7mGKJIUFt3DSu102YbslIAaAtUMdI="

SECRET_VALUE = "exchange-api-secret-that-must-never-be-readable-from-a-database-dump"
PURPOSE = "exchange_api_secret"
CONTEXT = "arbitrage-platform"


@pytest.fixture
def box() -> SecretBox:
    return SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context=CONTEXT)


@pytest.fixture
def sealed(box: SecretBox) -> str:
    return box.encrypt(SECRET_VALUE, purpose=PURPOSE)


def payload_of(ciphertext: str) -> bytes:
    """The raw ``nonce || ciphertext || tag`` bytes behind the version prefix."""
    version, _, body = ciphertext.partition(".")
    assert version == "v1"
    return base64.urlsafe_b64decode(body.encode("ascii"))


def mutate(ciphertext: str, *, byte_index: int = -1, xor: int = 0x01) -> str:
    """Flip one bit of the stored payload, as an attacker with DB write access would."""
    raw = bytearray(payload_of(ciphertext))
    raw[byte_index] ^= xor
    return "v1." + base64.urlsafe_b64encode(bytes(raw)).decode("ascii")


class TestRoundTrip:
    def test_a_secret_survives_encryption(self, box: SecretBox, sealed: str) -> None:
        assert box.decrypt(sealed, purpose=PURPOSE) == SECRET_VALUE

    def test_the_stored_form_is_versioned_and_url_safe(self, sealed: str) -> None:
        version, _, body = sealed.partition(".")
        assert version == "v1"
        assert body
        assert all(character.isalnum() or character in "-_=" for character in body)

    @pytest.mark.parametrize(
        "plaintext",
        ["", "a", "x" * 10_000, "ключ-مفتاح-密钥", "emoji 🔐 in a secret", "line\nbreak\tand tab"],
    )
    def test_any_text_round_trips(self, box: SecretBox, plaintext: str) -> None:
        assert box.decrypt(box.encrypt(plaintext, purpose=PURPOSE), purpose=PURPOSE) == plaintext

    def test_the_layout_is_nonce_ciphertext_tag(self, sealed: str) -> None:
        """12-byte nonce, then ciphertext, then GCM's 16-byte tag."""
        raw = payload_of(sealed)
        assert len(raw) == 12 + len(SECRET_VALUE.encode()) + 16


class TestNonceFreshness:
    def test_encrypting_the_same_secret_twice_differs(self, box: SecretBox) -> None:
        """Nonce reuse under one GCM key permits forgery and leaks the XOR of two
        plaintexts, so identical ciphertexts would be a critical defect."""
        assert box.encrypt(SECRET_VALUE, purpose=PURPOSE) != box.encrypt(
            SECRET_VALUE, purpose=PURPOSE
        )

    def test_many_encryptions_produce_many_ciphertexts(self, box: SecretBox) -> None:
        sealed_set = {box.encrypt("the-same-value", purpose=PURPOSE) for _ in range(300)}
        assert len(sealed_set) == 300

    def test_the_nonces_themselves_differ(self, box: SecretBox) -> None:
        nonces = {payload_of(box.encrypt("v", purpose=PURPOSE))[:12] for _ in range(200)}
        assert len(nonces) == 200

    def test_every_variant_still_decrypts(self, box: SecretBox) -> None:
        for _ in range(20):
            assert box.decrypt(box.encrypt(SECRET_VALUE, purpose=PURPOSE), purpose=PURPOSE) == (
                SECRET_VALUE
            )


class TestTamperingIsDetected:
    def test_a_flipped_bit_in_the_ciphertext_fails(self, box: SecretBox, sealed: str) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            box.decrypt(mutate(sealed), purpose=PURPOSE)
        assert excinfo.value.context["reason"] == "authentication_failed"

    def test_a_flipped_bit_in_the_nonce_fails(self, box: SecretBox, sealed: str) -> None:
        with pytest.raises(ConfigurationError):
            box.decrypt(mutate(sealed, byte_index=0), purpose=PURPOSE)

    def test_a_flipped_bit_in_the_tag_fails(self, box: SecretBox, sealed: str) -> None:
        with pytest.raises(ConfigurationError):
            box.decrypt(mutate(sealed, byte_index=-16), purpose=PURPOSE)

    @pytest.mark.parametrize("cut", [1, 5, 12, 20])
    def test_a_truncated_payload_fails(self, box: SecretBox, sealed: str, cut: int) -> None:
        """An attacker who can write to the column cannot shorten a secret into a
        different valid one."""
        raw = payload_of(sealed)[:-cut]
        with pytest.raises(ConfigurationError):
            box.decrypt("v1." + base64.urlsafe_b64encode(raw).decode("ascii"), purpose=PURPOSE)

    def test_an_appended_byte_fails(self, box: SecretBox, sealed: str) -> None:
        raw = payload_of(sealed) + b"\x00"
        with pytest.raises(ConfigurationError):
            box.decrypt("v1." + base64.urlsafe_b64encode(raw).decode("ascii"), purpose=PURPOSE)

    def test_swapping_two_secrets_between_columns_fails(self, box: SecretBox) -> None:
        """Editing one row's ciphertext into another row's column must not decrypt."""
        api_secret = box.encrypt("api-secret-value", purpose="exchange_api_secret")
        totp_secret = box.encrypt("totp-secret-value", purpose="totp_secret")
        with pytest.raises(ConfigurationError):
            box.decrypt(totp_secret, purpose="exchange_api_secret")
        with pytest.raises(ConfigurationError):
            box.decrypt(api_secret, purpose="totp_secret")


class TestCiphertextIsBound:
    def test_a_different_purpose_cannot_read_it(self, box: SecretBox, sealed: str) -> None:
        with pytest.raises(ConfigurationError):
            box.decrypt(sealed, purpose="totp_secret")

    def test_a_different_context_cannot_read_it(self, box: SecretBox, sealed: str) -> None:
        """Ciphertext lifted from one environment or tenant is useless in another."""
        other = SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context="another-context")
        with pytest.raises(ConfigurationError):
            other.decrypt(sealed, purpose=PURPOSE)
        # And the reverse direction fails too, so this is binding and not a fluke.
        with pytest.raises(ConfigurationError):
            box.decrypt(other.encrypt(SECRET_VALUE, purpose=PURPOSE), purpose=PURPOSE)

    def test_a_different_key_cannot_read_it(self, box: SecretBox, sealed: str) -> None:
        other = SecretBox(key=decode_encryption_key(OTHER_KEY), context=CONTEXT)
        with pytest.raises(ConfigurationError):
            other.decrypt(sealed, purpose=PURPOSE)

    def test_binding_survives_a_rebuilt_box(self, box: SecretBox, sealed: str) -> None:
        """The box is stateless: a fresh instance with the same material reads it."""
        twin = SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context=CONTEXT)
        assert twin.decrypt(sealed, purpose=PURPOSE) == SECRET_VALUE

    def test_the_same_plaintext_under_two_contexts_differs(self, box: SecretBox) -> None:
        other = SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context="another-context")
        assert box.encrypt("shared", purpose=PURPOSE) != other.encrypt("shared", purpose=PURPOSE)


class TestMalformedStorage:
    @pytest.mark.parametrize(
        ("stored", "reason"),
        [
            ("v2." + "A" * 40, "unknown_format_version"),
            ("v0." + "A" * 40, "unknown_format_version"),
            ("not-a-ciphertext", "unknown_format_version"),
            ("", "unknown_format_version"),
            ("v1.", "unknown_format_version"),
            (".AAAA", "unknown_format_version"),
            ("v1.!!!not base64!!!", "malformed_payload"),
            ("v1.QUJD", "truncated_payload"),
        ],
    )
    def test_unreadable_values_fail_with_a_reason(
        self, box: SecretBox, stored: str, reason: str
    ) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            box.decrypt(stored, purpose=PURPOSE)
        assert excinfo.value.context["reason"] == reason

    def test_an_unreadable_value_is_a_500_not_a_401(self, box: SecretBox) -> None:
        """The caller did nothing wrong; the platform cannot read its own data."""
        with pytest.raises(ConfigurationError) as excinfo:
            box.decrypt("v1.QUJD", purpose=PURPOSE)
        assert excinfo.value.http_status == 500


class TestKeyHandling:
    def test_the_platform_key_decodes_to_32_bytes(self) -> None:
        key = decode_encryption_key(TEST_ENCRYPTION_KEY)
        assert len(key) == KEY_BYTES == 32

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "!!!not-base64!!!",
            base64.urlsafe_b64encode(b"short").decode(),
            base64.urlsafe_b64encode(b"x" * 64).decode(),
        ],
    )
    def test_a_bad_key_is_refused_at_startup(self, value: str) -> None:
        """The message names the environment variable and the command to fix it,
        because this fails during boot with an operator reading a log."""
        with pytest.raises(ConfigurationError) as excinfo:
            decode_encryption_key(value)
        assert "ENCRYPTION_KEY" in str(excinfo.value)

    @pytest.mark.parametrize("value", [None, 12345, b"raw-bytes"])
    def test_a_non_string_key_is_refused(self, value: object) -> None:
        with pytest.raises(ConfigurationError):
            decode_encryption_key(value)  # type: ignore[arg-type]

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        """A trailing newline in an env file must not break every decryption."""
        assert decode_encryption_key(f"  {TEST_ENCRYPTION_KEY}\n") == decode_encryption_key(
            TEST_ENCRYPTION_KEY
        )

    def test_a_short_key_cannot_build_a_box(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            SecretBox(key=b"too-short", context=CONTEXT)

    def test_from_settings_uses_the_configured_key_and_context(
        self, settings: Settings, box: SecretBox
    ) -> None:
        from_settings = SecretBox.from_settings(settings)
        assert from_settings.context == settings.encryption_context
        # Interoperable with the hand-built box only if the material matches.
        assert (
            from_settings.decrypt(box.encrypt(SECRET_VALUE, purpose=PURPOSE), purpose=PURPOSE)
            == SECRET_VALUE
        )


class TestPurposeValidation:
    def test_a_purpose_is_required(self, box: SecretBox) -> None:
        """Without a purpose there is no binding, and binding is the point."""
        with pytest.raises(ValueError, match="purpose"):
            box.encrypt(SECRET_VALUE, purpose="")
        with pytest.raises(ValueError, match="purpose"):
            box.decrypt("v1.AAAA", purpose="   ")

    def test_a_purpose_cannot_contain_the_separator(self, box: SecretBox) -> None:
        """``context "a"`` + ``purpose "b:c"`` would produce the same AAD as
        ``context "a:b"`` + ``purpose "c"``, which is the replay AAD prevents."""
        with pytest.raises(ValueError, match="may not contain"):
            box.encrypt(SECRET_VALUE, purpose="totp:secret")

    def test_a_context_cannot_contain_the_separator(self) -> None:
        with pytest.raises(ValueError, match="may not contain"):
            SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context="tenant:one")

    def test_the_context_is_trimmed(self) -> None:
        padded = SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context=f"  {CONTEXT}  ")
        plain = SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context=CONTEXT)
        assert padded.context == CONTEXT
        assert plain.decrypt(padded.encrypt("v", purpose=PURPOSE), purpose=PURPOSE) == "v"

    def test_an_empty_context_is_refused(self) -> None:
        with pytest.raises(ValueError, match="context"):
            SecretBox(key=decode_encryption_key(TEST_ENCRYPTION_KEY), context="   ")

    @pytest.mark.parametrize("value", [None, 12345, b"bytes", ["a"]])
    def test_non_text_values_are_refused(self, box: SecretBox, value: object) -> None:
        """Encrypting bytes would mean guessing an encoding, and guessing wrong
        yields a credential that decrypts to mojibake years later."""
        with pytest.raises(TypeError, match="must be a str"):
            box.encrypt(value, purpose=PURPOSE)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="must be a str"):
            box.decrypt(value, purpose=PURPOSE)  # type: ignore[arg-type]


class TestNothingLeaks:
    def test_the_repr_carries_no_key_material(self, box: SecretBox) -> None:
        rendered = repr(box)
        assert TEST_ENCRYPTION_KEY not in rendered
        assert decode_encryption_key(TEST_ENCRYPTION_KEY).hex() not in rendered
        assert "context=" in rendered

    def test_a_failure_names_the_purpose_only(self, box: SecretBox, sealed: str) -> None:
        """§71/§127/§133: an error from this module can reach a log line or an
        error response, and must not carry the secret or the stored bytes."""
        with pytest.raises(ConfigurationError) as excinfo:
            box.decrypt(mutate(sealed), purpose=PURPOSE)
        error = excinfo.value
        rendered = f"{error} {error.message} {error.details}"
        assert SECRET_VALUE not in rendered
        assert sealed not in rendered
        assert payload_of(sealed).hex() not in rendered
        assert TEST_ENCRYPTION_KEY not in rendered
        assert error.context == {"purpose": PURPOSE, "reason": "authentication_failed"}

    def test_the_ciphertext_does_not_contain_the_plaintext(self, sealed: str) -> None:
        assert SECRET_VALUE not in sealed
        assert SECRET_VALUE.encode().hex() not in sealed

    def test_every_wrong_purpose_fails_identically(self, box: SecretBox, sealed: str) -> None:
        """An attacker probing purposes learns only that the guess was wrong.

        No wrong purpose is reported differently from any other, and none of them
        hints at which purpose the value was sealed under.
        """
        # The correct purpose reads it, so the failures below are about the purpose
        # and not about some unrelated problem with the ciphertext.
        assert box.decrypt(sealed, purpose=PURPOSE) == SECRET_VALUE
        messages = set()
        for guess in ["totp_secret", "exchange_api_key", "password", "nonsense", PURPOSE.upper()]:
            with pytest.raises(ConfigurationError) as excinfo:
                box.decrypt(sealed, purpose=guess)
            messages.add(excinfo.value.context["reason"])
        assert messages == {"authentication_failed"}
