"""Time-based one-time passwords (§59).

Every expected value below is transcribed from RFC 4226 Appendix D and RFC 6238
Appendix B, and the intermediate HMAC digests from RFC 4226 Table 1 are asserted
too. That is deliberate.

A TOTP test that only asserts "the code my generator produced is accepted by my
verifier" passes for an implementation that no authenticator app agrees with —
the failure surfaces as every user being unable to complete sign-in, discovered
only after MFA has been switched on. Testing against published vectors, including
the digest that feeds truncation, is what makes interoperability a checked
property rather than a hope.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from datetime import UTC, datetime
from typing import cast
from zoneinfo import ZoneInfo

import pytest

from arb_core.config import Environment, Settings
from arb_core.errors import ValidationError
from arb_core.security.totp import (
    RECOVERY_CODE_LENGTH,
    TotpConfig,
    generate_recovery_codes,
    hash_recovery_code,
    hotp,
    new_totp_secret,
    normalise_recovery_code,
    provisioning_uri,
    totp_code,
    totp_step,
    verify_totp,
)

#: RFC 4226/6238 test secret: the ASCII string "12345678901234567890".
RFC_SECRET_BYTES = b"12345678901234567890"
RFC_SECRET = base64.b32encode(RFC_SECRET_BYTES).decode()
#: RFC 6238 uses longer seeds for the SHA-256 and SHA-512 modes.
RFC_SECRET_SHA256_BYTES = b"12345678901234567890123456789012"
RFC_SECRET_SHA512_BYTES = b"1234567890123456789012345678901234567890123456789012345678901234"

#: RFC 4226 Appendix D, Table 1 — HMAC-SHA1(secret, count).
RFC4226_HMAC = {
    0: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
    1: "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
    2: "0bacb7fa082fef30782211938bc1c5e70416ff44",
    3: "66c28227d03a2d5529262ff016a1e6ef76557ece",
    4: "a904c900a64b35909874b33e61c5938a8e15ed1c",
    5: "a37e783d7b7233c083d4f62926c7a25f238d0316",
    6: "bc9cd28561042c83f219324d3c607256c03272ae",
    7: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
    8: "1b3c89f65e6c9e883012052823443f048b4332db",
    9: "1637409809a679dc698207310c8c7fc07290d9e5",
}

#: RFC 4226 Appendix D, Table 2 — truncated value and the resulting HOTP.
RFC4226_TRUNCATED = {
    0: ("4c93cf18", 1284755224, "755224"),
    1: ("41397eea", 1094287082, "287082"),
    2: ("82fef30", 137359152, "359152"),
    3: ("66ef7655", 1726969429, "969429"),
    4: ("61c5938a", 1640338314, "338314"),
    5: ("33c083d4", 868254676, "254676"),
    6: ("7256c032", 1918287922, "287922"),
    7: ("4e5b397", 82162583, "162583"),
    8: ("2823443f", 673399871, "399871"),
    9: ("2679dc69", 645520489, "520489"),
}

#: RFC 6238 Appendix B, Table 1 — (timestamp, mode) -> 8-digit TOTP.
RFC6238_VECTORS = {
    (59, "SHA1"): "94287082",
    (59, "SHA256"): "46119246",
    (59, "SHA512"): "90693936",
    (1111111109, "SHA1"): "07081804",
    (1111111109, "SHA256"): "68084774",
    (1111111109, "SHA512"): "25091201",
    (1111111111, "SHA1"): "14050471",
    (1111111111, "SHA256"): "67062674",
    (1111111111, "SHA512"): "99943326",
    (1234567890, "SHA1"): "89005924",
    (1234567890, "SHA256"): "91819424",
    (1234567890, "SHA512"): "93441116",
    (2000000000, "SHA1"): "69279037",
    (2000000000, "SHA256"): "90698825",
    (2000000000, "SHA512"): "38618901",
    (20000000000, "SHA1"): "65353130",
    (20000000000, "SHA256"): "77737706",
    (20000000000, "SHA512"): "47863826",
}

#: RFC 6238 Appendix B also fixes the counter value for each timestamp.
RFC6238_STEPS = {
    59: "0000000000000001",
    1111111109: "00000000023523EC",
    1111111111: "00000000023523ED",
    1234567890: "000000000273EF07",
    2000000000: "0000000003F940AA",
    20000000000: "0000000027BC86AA",
}

_MODE_SECRETS = {
    "SHA1": RFC_SECRET_BYTES,
    "SHA256": RFC_SECRET_SHA256_BYTES,
    "SHA512": RFC_SECRET_SHA512_BYTES,
}


def _b32(raw: bytes) -> str:
    """Base32 without padding, the form authenticator apps display."""
    return base64.b32encode(raw).decode().rstrip("=")


def _at(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


class TestHotpMatchesRfc4226:
    @pytest.mark.parametrize("counter", sorted(RFC4226_HMAC))
    def test_the_digest_feeding_truncation_is_the_rfc_digest(self, counter: int) -> None:
        """Proves the counter encoding: 8 bytes, big-endian, no length prefix.

        Asserted with the standard library directly rather than through the module
        under test, so a mistake in the packing cannot be hidden by the same
        mistake appearing on both sides of the comparison.
        """
        digest = hmac.new(RFC_SECRET_BYTES, struct.pack(">Q", counter), hashlib.sha1).hexdigest()
        assert digest == RFC4226_HMAC[counter]

    @pytest.mark.parametrize("counter", sorted(RFC4226_TRUNCATED))
    def test_codes_match_table_two(self, counter: int) -> None:
        _, _, expected = RFC4226_TRUNCATED[counter]
        assert hotp(RFC_SECRET_BYTES, counter) == expected

    def test_truncation_offset_comes_from_the_last_nibble(self) -> None:
        """RFC 4226 §5.3 dynamic truncation, checked against Table 2's hex column.

        The low nibble of the final digest byte selects a 4-byte window; the top
        bit is masked off so the result is a positive 31-bit integer.
        """
        for counter, (truncated_hex, truncated_decimal, _) in RFC4226_TRUNCATED.items():
            digest = bytes.fromhex(RFC4226_HMAC[counter])
            offset = digest[-1] & 0x0F
            window = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
            # The RFC renders this column with inconsistent leading zeros
            # ("82fef30" for 0x082fef30), so compare as integers.
            assert window == int(truncated_hex, 16)
            assert window == truncated_decimal

    def test_negative_counter_is_refused(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            hotp(RFC_SECRET_BYTES, -1)

    def test_eight_digit_codes_are_zero_padded(self) -> None:
        # T=1111111109 SHA1 is 07081804: a leading zero that a naive
        # implementation loses by formatting an integer.
        assert hotp(RFC_SECRET_BYTES, 37037036, digits=8) == "07081804"


class TestTotpMatchesRfc6238:
    @pytest.mark.parametrize(("timestamp", "mode"), sorted(RFC6238_VECTORS))
    def test_codes_match_the_published_table(self, timestamp: int, mode: str) -> None:
        secret = _b32(_MODE_SECRETS[mode])
        config = TotpConfig(period_seconds=30, digits=8, algorithm=mode, drift_steps=0)
        assert (
            totp_code(secret, at=_at(timestamp), config=config)
            == RFC6238_VECTORS[(timestamp, mode)]
        )

    @pytest.mark.parametrize("timestamp", sorted(RFC6238_STEPS))
    def test_time_step_matches_the_published_counter(self, timestamp: int) -> None:
        step = totp_step(_at(timestamp), period_seconds=30)
        assert f"{step:016X}" == RFC6238_STEPS[timestamp]

    def test_six_digit_codes_are_the_last_six_of_the_eight_digit_vector(self) -> None:
        """The default configuration is 6 digits; the RFC table is 8."""
        config = TotpConfig(period_seconds=30, digits=6, drift_steps=0)
        assert totp_code(RFC_SECRET, at=_at(1234567890), config=config) == "005924"

    def test_a_code_holds_for_the_whole_step_then_changes(self) -> None:
        config = TotpConfig(drift_steps=0)
        first = totp_code(RFC_SECRET, at=_at(1234567890), config=config)
        assert totp_code(RFC_SECRET, at=_at(1234567890 + 29), config=config) == first
        assert totp_code(RFC_SECRET, at=_at(1234567890 + 30), config=config) != first

    def test_naive_timestamps_are_refused(self) -> None:
        """Guessing a timezone for a naive timestamp would shift the code by hours (§75)."""
        # DTZ006 suppressed on both lines: constructing a naive timestamp *is*
        # the behaviour under test.
        naive = datetime.fromtimestamp(1234567890)  # noqa: DTZ006
        with pytest.raises(ValueError, match="timezone-aware"):
            totp_step(naive)
        with pytest.raises(ValueError, match="timezone-aware"):
            totp_code(RFC_SECRET, at=naive)

    def test_non_utc_aware_timestamps_agree_with_utc(self) -> None:
        """An aware timestamp is an instant; the zone it is expressed in is irrelevant."""
        lagos = datetime.fromtimestamp(1234567890, ZoneInfo("Africa/Lagos"))
        config = TotpConfig(drift_steps=0)
        assert totp_code(RFC_SECRET, at=lagos, config=config) == totp_code(
            RFC_SECRET, at=_at(1234567890), config=config
        )


class TestVerifyTotp:
    def test_accepts_the_current_code_and_reports_its_step(self) -> None:
        now = _at(1234567890)
        code = totp_code(RFC_SECRET, at=now, config=TotpConfig(drift_steps=0))
        # The returned step is what the caller records as consumed, so the same
        # code cannot be replayed inside its own drift window.
        assert verify_totp(RFC_SECRET, code, at=now, config=TotpConfig(drift_steps=0)) == totp_step(
            now
        )

    def test_drift_window_accepts_one_step_either_side(self) -> None:
        """A one-step window covers the previous and the next step, no further.

        The offsets are multiples of the period rather than "period + 1". The RFC
        timestamp 1234567890 falls *exactly* on a step boundary (it is divisible
        by 30), so subtracting 31 seconds crosses two boundaries and lands two
        steps back — an off-by-one that looks like a broken verifier and is not.
        """
        config = TotpConfig(drift_steps=1)
        code = totp_code(RFC_SECRET, at=_at(1234567890), config=config)
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 + 30), config=config) is not None
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 - 30), config=config) is not None

    def test_drift_window_is_bounded(self) -> None:
        config = TotpConfig(drift_steps=1)
        code = totp_code(RFC_SECRET, at=_at(1234567890), config=config)
        # Two steps out is outside a one-step window on either side.
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 + 60), config=config) is None
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 - 60), config=config) is None

    def test_zero_drift_accepts_only_the_current_step(self) -> None:
        config = TotpConfig(drift_steps=0)
        code = totp_code(RFC_SECRET, at=_at(1234567890), config=config)
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 + 30), config=config) is None

    def test_wider_drift_widens_the_accepted_window(self) -> None:
        code = totp_code(RFC_SECRET, at=_at(1234567890), config=TotpConfig(drift_steps=0))
        config = TotpConfig(drift_steps=4)
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 + 120), config=config) is not None
        assert verify_totp(RFC_SECRET, code, at=_at(1234567890 + 150), config=config) is None

    def test_a_wrong_code_is_rejected(self) -> None:
        now = _at(1234567890)
        correct = totp_code(RFC_SECRET, at=now, config=TotpConfig(drift_steps=0))
        wrong = "000000" if correct != "000000" else "000001"
        assert verify_totp(RFC_SECRET, wrong, at=now) is None

    def test_a_code_from_another_secret_is_rejected(self) -> None:
        now = _at(1234567890)
        other = totp_code(
            _b32(b"a-different-secret-value"), at=now, config=TotpConfig(drift_steps=0)
        )
        assert verify_totp(RFC_SECRET, other, at=now, config=TotpConfig(drift_steps=0)) is None

    @pytest.mark.parametrize(
        "presented",
        ["", " ", "12345", "1234567", "12ab56", "abcdef", "-", "None", "null"],
    )
    def test_malformed_codes_are_rejected_without_raising(self, presented: str) -> None:
        """A malformed code is a failed login, never a 500 (§71)."""
        assert verify_totp(RFC_SECRET, presented, at=_at(1234567890)) is None

    @pytest.mark.parametrize("presented", [b"123456", None, 123456, ["123456"]])
    def test_non_string_codes_are_rejected_without_raising(self, presented: object) -> None:
        """A JSON body can carry any type; the verifier must not assume ``str``."""
        assert verify_totp(RFC_SECRET, cast("str", presented), at=_at(1234567890)) is None

    def test_grouped_input_is_accepted(self) -> None:
        """Apps and recovery sheets group digits; users type what they see."""
        now = _at(1234567890)
        code = totp_code(RFC_SECRET, at=now, config=TotpConfig(drift_steps=0))
        for variant in (f"{code[:3]} {code[3:]}", f"{code[:3]}-{code[3:]}", f"  {code}  "):
            assert (
                verify_totp(RFC_SECRET, variant, at=now, config=TotpConfig(drift_steps=0))
                is not None
            )

    def test_invalid_secret_raises_a_validation_error(self) -> None:
        """Distinct from a wrong code: the *account's* secret is unusable.

        Surfacing this as a plain rejection would leave a user unable to sign in
        with no diagnostic and no way to fix it themselves.
        """
        with pytest.raises(ValidationError):
            verify_totp("not!valid!base32!", "123456", at=_at(1234567890))
        with pytest.raises(ValidationError):
            verify_totp("", "123456", at=_at(1234567890))

    def test_secret_formatting_variants_are_tolerated(self) -> None:
        now = _at(1234567890)
        expected = totp_code(RFC_SECRET, at=now, config=TotpConfig(drift_steps=0))
        padded = base64.b32encode(RFC_SECRET_BYTES).decode()
        grouped = "-".join(padded[i : i + 4] for i in range(0, len(padded), 4)).lower()
        for variant in (padded, grouped, padded.lower(), f" {padded} "):
            assert totp_code(variant, at=now, config=TotpConfig(drift_steps=0)) == expected


class TestTotpConfig:
    def test_defaults_match_the_common_authenticator_app(self) -> None:
        config = TotpConfig()
        assert (config.period_seconds, config.digits, config.algorithm) == (30, 6, "SHA1")

    @pytest.mark.parametrize("period", [0, -1])
    def test_period_must_be_positive(self, period: int) -> None:
        with pytest.raises(ValueError, match="period"):
            TotpConfig(period_seconds=period)

    @pytest.mark.parametrize("digits", [0, 11, -6])
    def test_digits_are_bounded(self, digits: int) -> None:
        with pytest.raises(ValueError, match="digits"):
            TotpConfig(digits=digits)

    def test_unknown_algorithm_is_refused(self) -> None:
        """An allowlist, so a typo cannot select a weak or absent digest."""
        with pytest.raises(ValueError, match="unsupported TOTP algorithm"):
            TotpConfig(algorithm="MD5")

    def test_negative_drift_is_refused(self) -> None:
        with pytest.raises(ValueError, match="drift"):
            TotpConfig(drift_steps=-1)

    def test_candidate_steps_try_the_current_step_first(self) -> None:
        """No skew is the common case, and the order must not hint at direction."""
        assert TotpConfig(drift_steps=0).candidate_steps == (0,)
        assert TotpConfig(drift_steps=1).candidate_steps == (0, -1, 1)
        assert TotpConfig(drift_steps=2).candidate_steps == (0, -1, 1, -2, 2)

    def test_from_settings_uses_operator_configuration(self) -> None:
        settings = Settings(
            _env_files=None,
            environment=Environment.TEST,
            mfa_totp_period_seconds=60,
            mfa_totp_digits=8,
            mfa_totp_drift_steps=2,
        )
        config = TotpConfig.from_settings(settings)
        assert (config.period_seconds, config.digits, config.drift_steps) == (60, 8, 2)


class TestSecretGeneration:
    def test_secret_is_base32_and_decodes_to_160_bits(self) -> None:
        secret = new_totp_secret()
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8))
        assert len(decoded) == 20

    def test_secrets_are_unique(self) -> None:
        assert len({new_totp_secret() for _ in range(200)}) == 200

    def test_short_secrets_are_refused(self) -> None:
        """RFC 4226 §4 requires at least 128 bits."""
        with pytest.raises(ValueError, match="at least 16 bytes"):
            new_totp_secret(length_bytes=10)

    def test_generated_secret_produces_verifiable_codes(self) -> None:
        secret = new_totp_secret()
        now = _at(1234567890)
        code = totp_code(secret, at=now, config=TotpConfig(drift_steps=0))
        assert verify_totp(secret, code, at=now, config=TotpConfig(drift_steps=0)) is not None


class TestProvisioningUri:
    def test_uri_carries_every_parameter_an_app_needs(self) -> None:
        uri = provisioning_uri(
            "JBSWY3DPEHPK3PXP",
            account_name="trader@example.com",
            issuer="Arbitrage Platform",
            config=TotpConfig(period_seconds=30, digits=6),
        )
        assert uri.startswith("otpauth://totp/")
        # The issuer appears in the label as well as as a parameter: several apps
        # render only the label, and without it two platforms look identical.
        assert "Arbitrage%20Platform%3Atrader%40example.com" in uri
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=Arbitrage%20Platform" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_label_and_parameter_values_cannot_inject(self) -> None:
        """An email address is attacker-influenced; the URI must not be.

        A registration address containing ``&`` or ``=`` could otherwise append
        parameters to the ``otpauth://`` URI — for instance overriding ``digits``
        or ``period`` — and the authenticator app would honour them.
        """
        uri = provisioning_uri(
            "JBSWY3DPEHPK3PXP",
            account_name="evil@example.com&digits=1&period=1#",
            issuer="Arb & Co",
        )
        assert uri.count("digits=") == 1
        assert uri.count("period=") == 1
        assert uri.endswith("digits=6&period=30")
        assert "%26" in uri and "%23" in uri

    @pytest.mark.parametrize(("account", "issuer"), [("", "Arb"), ("  ", "Arb"), ("a@b.co", "")])
    def test_label_parts_are_required(self, account: str, issuer: str) -> None:
        with pytest.raises(ValueError):
            provisioning_uri("JBSWY3DPEHPK3PXP", account_name=account, issuer=issuer)


class TestRecoveryCodes:
    def test_requested_count_is_returned_and_unique(self) -> None:
        codes = generate_recovery_codes(10)
        assert len(codes) == 10
        assert len(set(codes)) == 10

    def test_codes_avoid_characters_people_confuse(self) -> None:
        """These are read aloud on a support call and typed by hand."""
        codes = generate_recovery_codes(50)
        joined = "".join(codes).replace("-", "")
        assert not (set(joined) & set("IO01"))
        assert joined.isalnum() and joined.isupper()

    def test_codes_are_grouped_for_transcription(self) -> None:
        code = generate_recovery_codes(1)[0]
        left, right = code.split("-")
        assert len(left) + len(right) == RECOVERY_CODE_LENGTH

    def test_codes_carry_enough_entropy_to_be_unusable_to_guess(self) -> None:
        # 10 characters from a 32-symbol alphabet is 50 bits.
        entropy = RECOVERY_CODE_LENGTH * 5
        assert entropy >= 50

    def test_digest_is_stable_under_formatting(self) -> None:
        code = generate_recovery_codes(1)[0]
        digest = hash_recovery_code(code)
        assert digest == hash_recovery_code(code.lower())
        assert digest == hash_recovery_code(code.replace("-", ""))
        assert digest == hash_recovery_code(f"  {code}  ")
        assert len(digest) == 64

    def test_digests_are_unique_per_code(self) -> None:
        codes = generate_recovery_codes(10)
        assert len({hash_recovery_code(code) for code in codes}) == 10

    def test_normalisation_strips_separators_and_case(self) -> None:
        assert normalise_recovery_code(" ab-cd ") == "ABCD"

    def test_non_string_input_is_refused(self) -> None:
        with pytest.raises(TypeError):
            normalise_recovery_code(cast("str", b"ABCD-EFGH"))

    @pytest.mark.parametrize("count", [0, -1])
    def test_at_least_one_code_is_required(self, count: int) -> None:
        with pytest.raises(ValueError, match="at least one"):
            generate_recovery_codes(count)

    def test_short_codes_are_refused(self) -> None:
        with pytest.raises(ValueError, match="at least 8"):
            generate_recovery_codes(4, length=6)
