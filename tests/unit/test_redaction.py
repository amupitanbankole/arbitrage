"""Secret redaction (§12, §127, §133).

These are among the most important tests in the suite. A leaked exchange API key
is a direct financial loss, and the failure mode is silent: the log looks normal
and the secret is already in a backup, a log aggregator and a support ticket.
"""

from __future__ import annotations

from typing import cast

import pytest

from arb_core.security.redaction import (
    REDACTED,
    is_sensitive_key,
    mask_api_key,
    mask_dsn,
    redact_mapping,
    redact_object,
    redact_text,
)


class TestIsSensitiveKey:
    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "API_KEY",
            "apiKey",
            "api-key",
            "userApiKey",
            "password",
            "PASSWORD",
            "user_password",
            "passwd",
            "pwd",
            "secret",
            "client_secret",
            "api_secret",
            "token",
            "access_token",
            "refresh_token",
            "session_token",
            "authorization",
            "auth_token",
            "private_key",
            "encryption_key",
            "signing_key",
            "jwt",
            "mnemonic",
            "seed",
            "totp",
            "otp",
            "cookie",
            "csrf",
            "signature",
        ],
    )
    def test_credential_shaped_keys_are_detected(self, key: str) -> None:
        assert is_sensitive_key(key) is True

    @pytest.mark.parametrize(
        "key",
        ["symbol", "exchange", "quantity", "price", "status", "user_id", "request_id"],
    )
    def test_ordinary_keys_are_not_flagged(self, key: str) -> None:
        assert is_sensitive_key(key) is False

    @pytest.mark.parametrize(
        "key",
        [
            "idempotency_key",
            "request_id",
            "cache_key",
            "key_prefix",
            "redis_key_prefix",
            "sort_key",
            "partition_key",
            "primary_key",
            "public_key",
            "client_id",
        ],
    )
    def test_allowlisted_keys_survive(self, key: str) -> None:
        """Operational identifiers must stay readable or logs become useless."""
        assert is_sensitive_key(key) is False

    def test_author_is_not_confused_with_authorization(self) -> None:
        """The bare fragment ``auth`` is excluded for exactly this reason."""
        assert is_sensitive_key("author") is False
        assert is_sensitive_key("authorization") is True

    def test_non_string_key_is_handled(self) -> None:
        # JSON objects can carry numeric keys, so the guard is real. The cast
        # documents that a non-str is being passed on purpose rather than
        # suppressing the error at the call site.
        assert is_sensitive_key(cast("str", 1)) is False


class TestMaskApiKey:
    def test_matches_the_admin_display_format(self) -> None:
        """§12 specifies exactly this presentation."""
        assert mask_api_key("vmPuREDnEP8kQkFbXqEz1L2nM3oP4qR5sT6u1234") == ("************1234")

    def test_mask_length_never_discloses_secret_length(self) -> None:
        short = mask_api_key("abcd")
        long = mask_api_key("a" * 200 + "wxyz")
        assert short == "************"
        assert long == "************wxyz"
        # Both leak nothing about the original length beyond the visible suffix.
        assert len(short) == 12

    @pytest.mark.parametrize("visible", [0, -1])
    def test_zero_visible_suffix_reveals_nothing(self, visible: int) -> None:
        assert mask_api_key("supersecret", visible_suffix=visible) == "************"

    def test_empty_and_none(self) -> None:
        assert mask_api_key(None) == ""
        assert mask_api_key("") == ""

    def test_non_string_input(self) -> None:
        assert mask_api_key(123456).endswith("3456")


class TestMaskDsn:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "postgresql+asyncpg://arb:s3cret@db:5432/arbitrage",
                f"postgresql+asyncpg://arb:{REDACTED}@db:5432/arbitrage",
            ),
            ("redis://:pw@cache:6379/0", f"redis://:{REDACTED}@cache:6379/0"),
            ("redis://cache:6379/0", "redis://cache:6379/0"),
            ("", ""),
        ],
    )
    def test_password_component_is_removed(self, url: str, expected: str) -> None:
        assert mask_dsn(url) == expected

    def test_username_and_host_are_preserved(self) -> None:
        """Operators still need to know which database a message refers to."""
        masked = mask_dsn("postgresql://arb:s3cret@db-primary:5432/arbitrage")
        assert "arb" in masked
        assert "db-primary" in masked
        assert "s3cret" not in masked


class TestRedactText:
    def test_bearer_token(self) -> None:
        out = redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig")
        assert "eyJhbGciOiJIUzI1NiJ9" not in out
        assert REDACTED in out

    def test_basic_auth(self) -> None:
        out = redact_text("Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==")
        assert "dXNlcjpwYXNzd29yZA==" not in out

    def test_api_key_header(self) -> None:
        out = redact_text("X-API-Key: abcdef0123456789")
        assert "abcdef0123456789" not in out

    def test_assignment_forms(self) -> None:
        for text in (
            "password=hunter2hunter2",
            "password: 'hunter2hunter2'",
            'api_secret = "abc123abc123"',
            "token=eyJ0eXAiOiJKV1QiLCJhbGci",
        ):
            out = redact_text(text)
            assert "hunter2hunter2" not in out
            assert "abc123abc123" not in out
            assert "eyJ0eXAiOiJKV1QiLCJhbGci" not in out

    def test_embedded_dsn(self) -> None:
        out = redact_text("could not connect to postgresql://arb:s3cret@db:5432/x")
        assert "s3cret" not in out
        assert "db:5432" in out

    def test_ordinary_text_is_untouched(self) -> None:
        text = "Order filled: 0.0025 BTC at 105000.50 USDT on binance"
        assert redact_text(text) == text

    def test_empty_input(self) -> None:
        assert redact_text("") == ""


class TestRedactObject:
    def test_nested_mappings(self) -> None:
        payload = {
            "user": {"email": "a@b.c", "api_secret": "xyz"},
            "orders": [{"symbol": "BTC/USDT", "token": "abc"}],
            "count": 3,
        }
        out = redact_object(payload)
        assert out["user"]["email"] == "a@b.c"
        assert out["user"]["api_secret"] == REDACTED
        assert out["orders"][0]["symbol"] == "BTC/USDT"
        assert out["orders"][0]["token"] == REDACTED
        assert out["count"] == 3

    def test_original_is_not_mutated(self) -> None:
        payload = {"api_key": "secret-value"}
        redact_object(payload)
        assert payload == {"api_key": "secret-value"}

    def test_tuples_and_sets_are_preserved_by_type(self) -> None:
        assert isinstance(redact_object(("a", "b")), tuple)
        assert isinstance(redact_object({"a", "b"}), set)
        assert isinstance(redact_object(frozenset({"a"})), frozenset)

    def test_strings_are_scrubbed(self) -> None:
        out = redact_object("password=hunter2hunter2")
        assert "hunter2hunter2" not in out

    def test_deeply_nested_input_is_bounded(self) -> None:
        """A self-referential or pathological structure must not hang or recurse."""
        deep: dict[str, object] = {}
        current = deep
        for _ in range(50):
            child: dict[str, object] = {"password": "x"}
            current["child"] = child
            current = child
        out = redact_object(deep)
        assert out is not None

    def test_self_referential_structure_terminates(self) -> None:
        payload: dict[str, object] = {"name": "ok"}
        payload["self"] = payload
        # Depth limit stops the recursion; the call must return, not raise.
        assert redact_object(payload) is not None

    def test_arbitrary_objects_are_not_stringified(self) -> None:
        """Coercing an unknown object to text could itself leak an attribute."""

        class HoldsASecret:
            def __init__(self) -> None:
                self.api_key = "should-not-appear"

            def __repr__(self) -> str:
                return f"HoldsASecret(api_key={self.api_key})"

        out = redact_object(HoldsASecret())
        assert isinstance(out, HoldsASecret)

    def test_redact_mapping_returns_a_dict(self) -> None:
        assert redact_mapping({"token": "abc"}) == {"token": REDACTED}
