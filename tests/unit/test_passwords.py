"""Password hashing and policy (§59).

The security properties asserted here are the ones that fail silently in
production: a hash that verifies against the wrong scheme, a password truncated
instead of rejected, a rejection message that echoes the secret back, and a login
for a nonexistent account that answers fast enough to enumerate users by timing.
"""

from __future__ import annotations

import time
from typing import cast

import pytest

from arb_core.config import Environment, PasswordHashScheme, Settings
from arb_core.errors import PasswordPolicyError, ValidationError
from arb_core.security.passwords import (
    BCRYPT_MAX_INPUT_BYTES,
    PasswordHasher,
    PasswordPolicy,
    normalize_password,
    scheme_of,
)

GOOD_PASSWORD = "correct-horse-battery-staple"


def rejection_reasons(excinfo: pytest.ExceptionInfo[PasswordPolicyError]) -> str:
    """The per-field reasons, which is where the policy puts them (§71).

    ``message`` is the stable client-facing summary; the specific rule that failed
    is in ``details["password"]``, so assertions belong there.
    """
    return " | ".join(excinfo.value.details["password"])


@pytest.fixture
def hasher() -> PasswordHasher:
    """argon2id at the cheapest parameters the configuration permits.

    Production cost (3 iterations, 64 MiB) is ~100 ms per hash; a suite that
    hashed hundreds of passwords at that cost would take minutes. The properties
    under test do not depend on the cost parameters, and the parameter handling
    itself is asserted separately.
    """
    return PasswordHasher(
        scheme=PasswordHashScheme.ARGON2ID, time_cost=1, memory_cost_kib=8192, parallelism=1
    )


@pytest.fixture
def bcrypt_hasher() -> PasswordHasher:
    return PasswordHasher(scheme=PasswordHashScheme.BCRYPT, bcrypt_rounds=10)


def make_settings(**overrides: object) -> Settings:
    return Settings(
        _env_files=None,
        environment=Environment.TEST,
        argon2_time_cost=1,
        argon2_memory_cost_kib=8192,
        argon2_parallelism=1,
        **overrides,  # type: ignore[arg-type]
    )


class TestArgon2Hashing:
    def test_hash_uses_argon2id_and_embeds_its_parameters(self, hasher: PasswordHasher) -> None:
        """Parameters live in the hash, so raising them later is migratable."""
        digest = hasher.hash(GOOD_PASSWORD)
        assert digest.startswith("$argon2id$v=19$")
        assert "m=8192,t=1,p=1" in digest
        assert scheme_of(digest) == "argon2id"

    def test_round_trip(self, hasher: PasswordHasher) -> None:
        digest = hasher.hash(GOOD_PASSWORD)
        assert hasher.verify(GOOD_PASSWORD, digest) is True
        assert hasher.verify(GOOD_PASSWORD + "!", digest) is False

    def test_the_same_password_hashes_differently_every_time(self, hasher: PasswordHasher) -> None:
        """A fresh salt per hash: identical digests would reveal reused passwords."""
        first, second = hasher.hash(GOOD_PASSWORD), hasher.hash(GOOD_PASSWORD)
        assert first != second
        assert hasher.verify(GOOD_PASSWORD, first) is True
        assert hasher.verify(GOOD_PASSWORD, second) is True

    def test_a_new_hash_does_not_need_rehashing(self, hasher: PasswordHasher) -> None:
        assert hasher.needs_rehash(hasher.hash(GOOD_PASSWORD)) is False

    def test_weaker_parameters_are_flagged_for_rehash(self) -> None:
        """Raising cost must migrate the population, one sign-in at a time."""
        weak = PasswordHasher(
            scheme=PasswordHashScheme.ARGON2ID, time_cost=1, memory_cost_kib=8192, parallelism=1
        )
        strong = PasswordHasher(
            scheme=PasswordHashScheme.ARGON2ID, time_cost=2, memory_cost_kib=8192, parallelism=1
        )
        digest = weak.hash(GOOD_PASSWORD)
        assert weak.needs_rehash(digest) is False
        assert strong.needs_rehash(digest) is True
        # The stronger hasher can still verify the weaker hash, which is what
        # makes the upgrade possible without a forced password reset.
        assert strong.verify(GOOD_PASSWORD, digest) is True

    def test_cost_parameters_must_be_positive(self) -> None:
        for kwargs in (
            {"time_cost": 0},
            {"memory_cost_kib": 0},
            {"parallelism": 0},
        ):
            with pytest.raises(ValueError, match="positive"):
                PasswordHasher(scheme=PasswordHashScheme.ARGON2ID, **kwargs)

    def test_repr_carries_no_secret(self, hasher: PasswordHasher) -> None:
        hasher.hash(GOOD_PASSWORD)
        rendered = repr(hasher)
        assert GOOD_PASSWORD not in rendered
        assert hasher.scheme in rendered


class TestBcryptHashing:
    def test_hash_uses_the_configured_scheme_and_rounds(
        self, bcrypt_hasher: PasswordHasher
    ) -> None:
        digest = bcrypt_hasher.hash(GOOD_PASSWORD)
        assert digest.startswith("$2b$10$")
        assert scheme_of(digest) == "bcrypt"
        assert bcrypt_hasher.verify(GOOD_PASSWORD, digest) is True

    def test_rounds_change_flags_a_rehash(self) -> None:
        ten = PasswordHasher(scheme=PasswordHashScheme.BCRYPT, bcrypt_rounds=10)
        twelve = PasswordHasher(scheme=PasswordHashScheme.BCRYPT, bcrypt_rounds=12)
        digest = ten.hash(GOOD_PASSWORD)
        assert ten.needs_rehash(digest) is False
        assert twelve.needs_rehash(digest) is True
        assert twelve.verify(GOOD_PASSWORD, digest) is True

    def test_a_password_longer_than_bcrypt_can_hash_is_refused(
        self, bcrypt_hasher: PasswordHasher
    ) -> None:
        """bcrypt discards bytes past the 72nd *silently*.

        Accepting the password would mean two distinct passwords sharing a
        72-byte prefix authenticate as one account. Refusing is the only safe
        answer, and the error states the limit rather than truncating.
        """
        oversized = "ü" * BCRYPT_MAX_INPUT_BYTES  # 2 bytes per character
        assert len(oversized.encode()) > BCRYPT_MAX_INPUT_BYTES
        with pytest.raises(ValidationError) as excinfo:
            bcrypt_hasher.hash(oversized)
        assert f"{BCRYPT_MAX_INPUT_BYTES}" in str(excinfo.value.details)

    def test_exactly_72_bytes_is_accepted(self, bcrypt_hasher: PasswordHasher) -> None:
        exact = "a" * BCRYPT_MAX_INPUT_BYTES
        digest = bcrypt_hasher.hash(exact)
        assert bcrypt_hasher.verify(exact, digest) is True

    def test_verifying_an_oversized_password_returns_false_rather_than_raising(
        self, bcrypt_hasher: PasswordHasher
    ) -> None:
        """The login path must answer "no", never 500 (§71)."""
        digest = bcrypt_hasher.hash(GOOD_PASSWORD)
        assert bcrypt_hasher.verify("ü" * BCRYPT_MAX_INPUT_BYTES, digest) is False

    def test_argon2_never_silently_truncates_a_long_password(self, hasher: PasswordHasher) -> None:
        """The limit is bcrypt's, not the platform's: argon2 hashes the whole input."""
        long_password = "x" * 200
        digest = hasher.hash(long_password)
        assert hasher.verify(long_password, digest) is True
        # A password sharing only the first 72 characters must NOT verify.
        assert hasher.verify("x" * 72 + "y" * 128, digest) is False


class TestSchemeMigration:
    def test_a_bcrypt_hash_verifies_under_an_argon2id_configuration(
        self, hasher: PasswordHasher, bcrypt_hasher: PasswordHasher
    ) -> None:
        """Dispatch is on the *stored* hash, not the configured scheme.

        This is what stops an operator switching PASSWORD_HASH_SCHEME from
        locking every existing user out at the moment of the change.
        """
        legacy = bcrypt_hasher.hash(GOOD_PASSWORD)
        assert hasher.verify(GOOD_PASSWORD, legacy) is True
        assert hasher.verify("wrong-password", legacy) is False
        assert hasher.needs_rehash(legacy) is True

    def test_an_argon2id_hash_verifies_under_a_bcrypt_configuration(
        self, hasher: PasswordHasher, bcrypt_hasher: PasswordHasher
    ) -> None:
        current = hasher.hash(GOOD_PASSWORD)
        assert bcrypt_hasher.verify(GOOD_PASSWORD, current) is True
        assert bcrypt_hasher.needs_rehash(current) is True

    def test_scheme_of_recognises_both_families(self) -> None:
        assert scheme_of("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash") == "argon2id"
        assert scheme_of("$argon2i$v=19$m=4096,t=3,p=1$c2FsdA$hash") == "argon2i"
        assert scheme_of("$2b$12$abcdefghijklmnopqrstuv") == "bcrypt"
        assert scheme_of("$2a$10$abcdefghijklmnopqrstuv") == "bcrypt"

    @pytest.mark.parametrize(
        "stored", ["", "plaintext-password", "$$...", "$unknown$1$abc", "not-a-hash", None]
    )
    def test_unrecognised_hashes_are_not_a_scheme(self, stored: str | None) -> None:
        assert scheme_of(stored) is None


class TestVerificationIsAlwaysAnAnswer:
    """A failed verification must be indistinguishable from a wrong password."""

    @pytest.mark.parametrize(
        "stored",
        [
            None,
            "",
            "plaintext",
            "$argon2id$v=19$m=65536,t=3,p=4$invalid",
            "$2b$12$truncated",
            "$2b$99$abcdefghijklmnopqrstuv",
            "$argon2id$v=99$m=1,t=1,p=1$AAAA$BBBB",
        ],
    )
    def test_malformed_or_missing_hashes_return_false(
        self, hasher: PasswordHasher, stored: str | None
    ) -> None:
        """A corrupt hash surfacing as a 500 would reveal which accounts hold one."""
        assert hasher.verify(GOOD_PASSWORD, stored) is False

    def test_a_nul_in_the_password_is_a_rejection_not_an_error(
        self, hasher: PasswordHasher
    ) -> None:
        """Both libraries reject NUL internally; that must not become a 500."""
        assert hasher.verify("with\x00nul", hasher.hash(GOOD_PASSWORD)) is False

    def test_hashing_a_nul_is_refused_explicitly(self, hasher: PasswordHasher) -> None:
        with pytest.raises(ValidationError) as excinfo:
            hasher.hash("with\x00nul")
        assert "NUL" in str(excinfo.value.details)

    @pytest.mark.parametrize("value", [b"bytes-password", None, 12345, ["a"]])
    def test_non_string_passwords_raise_a_type_error(
        self, hasher: PasswordHasher, value: object
    ) -> None:
        """A ``bytes`` password encoded with a guessed codec would hash differently."""
        with pytest.raises(TypeError):
            hasher.hash(cast("str", value))

    def test_an_empty_password_is_simply_wrong(self, hasher: PasswordHasher) -> None:
        assert hasher.verify("", hasher.hash(GOOD_PASSWORD)) is False


class TestUnknownAccountTiming:
    def test_the_dummy_path_performs_real_work(self, hasher: PasswordHasher) -> None:
        """A nonexistent account must cost what a real verification costs.

        Otherwise login latency becomes a user-enumeration oracle as reliable as
        an error message: no account answers in microseconds, a real one in tens.
        """
        digest = hasher.hash(GOOD_PASSWORD)

        started = time.perf_counter()
        hasher.verify(GOOD_PASSWORD, digest)
        real_duration = time.perf_counter() - started

        started = time.perf_counter()
        hasher.verify_unknown_account(GOOD_PASSWORD)
        # The first call also builds the throwaway hash, so it is the expensive
        # one; that is fine, it happens once per process.
        unknown_duration = time.perf_counter() - started

        assert unknown_duration > 0.001, "the dummy path did no measurable work"
        assert unknown_duration >= real_duration * 0.2

    def test_the_dummy_hash_is_built_once_and_never_matches(self, hasher: PasswordHasher) -> None:
        hasher.verify_unknown_account("first-attempt")
        dummy = hasher._dummy_hash
        assert dummy is not None
        hasher.verify_unknown_account("second-attempt")
        assert hasher._dummy_hash == dummy
        # The throwaway password is random per process, so nothing a user submits
        # can match it.
        assert hasher.verify("first-attempt", dummy) is False


class TestNormalization:
    def test_equivalent_unicode_forms_normalize_identically(self) -> None:
        """NFKC, per NIST SP 800-63B §5.1.1.2.

        Without it, a user who set a password on a phone with a composed ``é``
        cannot reproduce it on a desktop that sends a combining accent — locked
        out of their own account with nothing to diagnose.
        """
        composed = "caf\u00e9-passphrase-long"
        decomposed = "cafe\u0301-passphrase-long"
        assert composed != decomposed
        assert normalize_password(composed) == normalize_password(decomposed)

    def test_full_width_digits_normalize_to_ascii(self) -> None:
        assert normalize_password("\uff11\uff12\uff13") == "123"

    def test_equivalent_forms_produce_interchangeable_hashes(self, hasher: PasswordHasher) -> None:
        digest = hasher.hash("caf\u00e9-passphrase-long")
        assert hasher.verify("cafe\u0301-passphrase-long", digest) is True

    def test_surrounding_whitespace_is_preserved(self, hasher: PasswordHasher) -> None:
        """Spaces are part of a passphrase; stripping them would merge two secrets."""
        digest = hasher.hash("  padded passphrase  ")
        assert hasher.verify("  padded passphrase  ", digest) is True
        assert hasher.verify("padded passphrase", digest) is False


class TestPasswordPolicy:
    @pytest.fixture
    def policy(self) -> PasswordPolicy:
        return PasswordPolicy(min_length=12, max_length=64)

    def test_accepts_a_long_passphrase(self, policy: PasswordPolicy) -> None:
        policy.validate("a perfectly reasonable passphrase")

    def test_accepts_a_password_with_no_symbols_or_capitals(self, policy: PasswordPolicy) -> None:
        """No composition rules, per NIST SP 800-63B.

        Demanding "Tr0ub4dor&3" does not raise the cost of an attack; it makes
        passwords harder to remember, which pushes people to reuse them.
        """
        policy.validate("eleven words are worth more than symbols")

    def test_rejects_a_short_password(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("short1")
        assert "at least 12 characters" in str(excinfo.value.details)

    def test_rejects_an_overlong_password(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("x" * 65)
        assert "at most 64 characters" in str(excinfo.value.details)

    def test_rejects_whitespace_only(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("              ")
        assert "non-whitespace" in str(excinfo.value.details)

    @pytest.mark.parametrize(
        "candidate",
        [
            "password1234",
            "PASSWORD1234",
            "  password1234  ",
            "mustchangepassword",
            "arbitrageplatform",
            "administrator",
            "cryptocurrency",
        ],
    )
    def test_rejects_commonly_used_passwords(self, policy: PasswordPolicy, candidate: str) -> None:
        """Screened case-insensitively and after trimming."""
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate(candidate)
        assert "commonly-used" in rejection_reasons(excinfo)

    @pytest.mark.parametrize("candidate", ["letmein", "arbitrage", "trustno1", "changeme"])
    def test_short_common_passwords_are_rejected_too(
        self, policy: PasswordPolicy, candidate: str
    ) -> None:
        """These fail on length before the blocklist is consulted — still refused."""
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate(candidate)
        assert "at least 12 characters" in rejection_reasons(excinfo)

    def test_padding_does_not_defeat_the_screen(self, policy: PasswordPolicy) -> None:
        """Whitespace is kept in the password but ignored when screening it.

        Both halves matter and they pull in opposite directions: stripping before
        *hashing* would merge two different passphrases, while refusing to strip
        before *screening* lets "  password1234  " — the same weak guess, usually
        from a paste — through untouched.
        """
        for padded in ("  password1234  ", "\tpassword1234\n", "PASSWORD1234   "):
            with pytest.raises(PasswordPolicyError) as excinfo:
                policy.validate(padded)
            assert "commonly-used" in rejection_reasons(excinfo)

    def test_padded_repeated_characters_are_screened(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("   aaaaaaaaaa   ")
        assert "single repeated character" in rejection_reasons(excinfo)

    def test_a_blocklist_entry_inside_a_passphrase_is_accepted(
        self, policy: PasswordPolicy
    ) -> None:
        """The screen is an exact match, not a substring search.

        Substring matching would reject "not-password1234-at-all", which is a
        strong passphrase. The blocklist exists to catch the exact guesses in an
        attacker's dictionary, and nothing more.
        """
        policy.validate("not-password1234-at-all")

    def test_rejects_a_single_repeated_character(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("aaaaaaaaaaaa")
        assert "single repeated character" in rejection_reasons(excinfo)

    def test_rejects_the_account_email(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("trader@example.com", email="trader@example.com")
        assert "email address" in rejection_reasons(excinfo)

    def test_rejects_the_email_local_part(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("i-am-trader-2026", email="trader@example.com")
        assert "email address" in rejection_reasons(excinfo)

    def test_rejects_a_password_containing_the_display_name(self, policy: PasswordPolicy) -> None:
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("Amupitan is my name", display_name="Amupitan")
        assert "display name" in rejection_reasons(excinfo)

    def test_short_identifiers_are_not_screened(self, policy: PasswordPolicy) -> None:
        """ "Al" appears inside ordinary passphrases; rejecting on it is noise."""
        policy.validate("a long passphrase", email="al@x.io", display_name="Al")

    def test_an_unrelated_password_passes_alongside_identifiers(
        self, policy: PasswordPolicy
    ) -> None:
        policy.validate(
            "seventeen unrelated syllables",
            email="trader@example.com",
            display_name="Bankole Amupitan",
        )

    def test_every_problem_is_reported_at_once(self, policy: PasswordPolicy) -> None:
        """One message, not one rejection per attempt at choosing a password."""
        with pytest.raises(PasswordPolicyError) as excinfo:
            policy.validate("   ")
        problems = excinfo.value.details["password"]
        assert len(problems) >= 2

    def test_the_rejection_never_contains_the_password(self) -> None:
        """§71: a submitted value must not be echoed back on any surface.

        The policy is given a deliberately small cap so that a *distinctive*
        passphrase is the thing being rejected — a rejection of "xxxx..." would
        pass this test even if the password were leaked, since "x" appears in the
        reason text anyway.
        """
        secret = "my-very-specific-passphrase-4417"
        strict = PasswordPolicy(min_length=12, max_length=20)
        with pytest.raises(PasswordPolicyError) as excinfo:
            strict.validate(secret)
        rendered = " ".join(
            [
                str(excinfo.value),
                str(excinfo.value.message),
                str(excinfo.value.details),
                str(excinfo.value.context),
                repr(excinfo.value),
            ]
        )
        assert secret not in rendered
        assert "specific" not in rendered
        assert "4417" not in rendered
        # Length is safe to disclose and is what makes a policy dispute debuggable.
        assert excinfo.value.context["password_length"] == len(secret)

    def test_non_string_input_raises_a_type_error(self, policy: PasswordPolicy) -> None:
        with pytest.raises(TypeError):
            policy.validate(cast("str", b"bytes-password"))

    def test_byte_limit_applies_only_to_bcrypt(self) -> None:
        argon2_policy = PasswordPolicy.from_settings(make_settings())
        assert argon2_policy.max_bytes is None
        bcrypt_policy = PasswordPolicy.from_settings(
            make_settings(password_hash_scheme=PasswordHashScheme.BCRYPT, password_max_length=72)
        )
        assert bcrypt_policy.max_bytes == BCRYPT_MAX_INPUT_BYTES
        # 40 two-byte characters: inside the character limit, outside the byte one.
        with pytest.raises(PasswordPolicyError) as excinfo:
            bcrypt_policy.validate("ü" * 40)
        assert "bytes" in str(excinfo.value.details)

    def test_from_settings_reads_the_operator_configuration(self) -> None:
        policy = PasswordPolicy.from_settings(
            make_settings(password_min_length=16, password_max_length=100)
        )
        assert (policy.min_length, policy.max_length) == (16, 100)

    def test_describe_states_what_is_not_checked(self) -> None:
        """The honest labels matter as much as the positive ones (§151)."""
        described = PasswordPolicy().describe()
        assert described["min_length"] == 12
        assert described["checks_common_passwords"] is True
        assert described["checks_account_identifiers"] is True
        assert described["requires_character_classes"] is False
        assert described["expires_periodically"] is False
        assert described["screened_against_breach_corpus"] is False


class TestFromSettings:
    def test_the_hasher_follows_the_configured_scheme(self) -> None:
        argon2 = PasswordHasher.from_settings(make_settings())
        assert argon2.hash(GOOD_PASSWORD).startswith("$argon2id$")
        bcrypt = PasswordHasher.from_settings(
            make_settings(
                password_hash_scheme=PasswordHashScheme.BCRYPT,
                bcrypt_rounds=11,
                password_max_length=72,
            )
        )
        assert bcrypt.hash(GOOD_PASSWORD).startswith("$2b$11$")

    def test_production_cost_parameters_are_the_documented_ones(self) -> None:
        """The defaults an operator gets without tuning anything (§59)."""
        settings = Settings(_env_files=None, environment=Environment.TEST)
        hasher = PasswordHasher.from_settings(settings)
        digest = hasher.hash(GOOD_PASSWORD)
        assert "m=65536,t=3,p=4" in digest
