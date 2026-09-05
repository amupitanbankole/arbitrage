"""Configuration and production fail-closed behaviour (§89, §90, §145).

The production checks are the important ones. A trading platform that boots with
``DEBUG=true``, a committed development secret, an insecure cookie or a SQLite
database is a platform that will lose money or leak credentials — so the process
must refuse to start. These tests assert that refusal, and that **all** problems
are reported at once so an operator fixes the configuration in one pass rather
than discovering it one restart at a time.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from arb_core.config import (
    KNOWN_INSECURE_SECRETS,
    Environment,
    LogFormat,
    Settings,
    find_project_root,
    get_settings,
    reset_settings_cache,
    resolve_env_files,
)
from arb_core.errors import ConfigurationError
from tests.support.config import TEST_PRODUCTION_ENCRYPTION_KEY, production_kwargs


def make_production(**overrides: object) -> Settings:
    """Build a production Settings with the given fields overridden."""
    return Settings(**{**production_kwargs(), **overrides})


class TestDevelopmentDefaults:
    def test_defaults_are_safe(self, settings: Settings) -> None:
        assert settings.environment is Environment.TEST
        assert settings.live_trading_enabled is False
        assert settings.global_kill_switch_enabled is False
        assert settings.feature_flag_live_trading is False
        assert settings.feature_flag_dex_trading is False

    def test_conservative_first_live_limits(self, settings: Settings) -> None:
        """§32: the documented conservative defaults must be the real defaults."""
        fresh = Settings(environment=Environment.DEVELOPMENT)
        assert fresh.default_max_trade_usd == 25
        assert fresh.default_max_daily_loss_usd == 25
        assert fresh.default_max_concurrent_trades == 1
        assert fresh.default_max_exchange_exposure_usd == 100

    def test_monetary_defaults_are_decimal_not_float(self, settings: Settings) -> None:
        """§74 — a float here would propagate into every limit check."""
        from decimal import Decimal

        assert isinstance(settings.default_max_trade_usd, Decimal)
        assert isinstance(settings.default_max_daily_loss_usd, Decimal)

    def test_string_numbers_are_coerced_to_decimal(self) -> None:
        parsed = Settings(environment=Environment.TEST, default_max_trade_usd="12.34")
        from decimal import Decimal

        assert parsed.default_max_trade_usd == Decimal("12.34")

    def test_secrets_are_secretstr(self, settings: Settings) -> None:
        """``repr`` and ``str`` of a SecretStr must not reveal the value."""
        for field in (
            settings.jwt_secret,
            settings.session_secret,
            settings.encryption_key,
            settings.database_url,
            settings.redis_url,
        ):
            assert isinstance(field, SecretStr)
            assert "**********" in str(field)

    def test_settings_repr_leaks_nothing(self, settings: Settings) -> None:
        rendered = repr(settings)
        assert "test_only_insecure_jwt_secret" not in rendered
        assert "9b4jVmYWQwDDmHYJcNY1Izm4O9GVGhbAIF7zv0VR4tM" not in rendered


class TestDerivedValues:
    def test_database_url_is_masked(self) -> None:
        parsed = Settings(
            environment=Environment.TEST,
            database_url="postgresql+asyncpg://arb:sup3rs3cret@db:5432/arbitrage",
        )
        assert "sup3rs3cret" not in parsed.database_url_safe
        assert "[REDACTED]" in parsed.database_url_safe
        # Operators still need to know which host and database.
        assert "db:5432" in parsed.database_url_safe

    def test_redis_url_is_masked(self) -> None:
        parsed = Settings(
            environment=Environment.TEST, redis_url="redis://:cache-secret@redis:6379/0"
        )
        assert "cache-secret" not in parsed.redis_url_safe

    def test_csv_parsing(self) -> None:
        parsed = Settings(
            environment=Environment.TEST,
            cors_origins="https://a.example.com, https://b.example.com ,, https://c.example.com",
            worker_roles="market-data, ,execution",
        )
        assert parsed.cors_origin_list == [
            "https://a.example.com",
            "https://b.example.com",
            "https://c.example.com",
        ]
        assert parsed.worker_role_list == ["market-data", "execution"]

    def test_redis_key_namespacing(self, settings: Settings) -> None:
        assert settings.redis_key("orderbook", "binance", "BTC/USDT") == (
            "arb_test:orderbook:binance:BTC/USDT"
        )
        assert settings.redis_key("") == "arb_test"

    def test_sqlalchemy_kwargs_exclude_pool_options_for_sqlite(self, settings: Settings) -> None:
        """SQLite rejects PostgreSQL pool arguments."""
        kwargs = settings.sqlalchemy_engine_kwargs
        assert "pool_size" not in kwargs
        assert "max_overflow" not in kwargs

    def test_sqlalchemy_kwargs_include_pool_options_for_postgres(self) -> None:
        parsed = Settings(
            environment=Environment.TEST,
            database_url="postgresql+asyncpg://arb:x@db:5432/arbitrage",
            database_pool_size=7,
            database_max_overflow=3,
        )
        kwargs = parsed.sqlalchemy_engine_kwargs
        assert kwargs["pool_size"] == 7
        assert kwargs["max_overflow"] == 3
        assert kwargs["pool_pre_ping"] is True

    def test_fernet_key_is_usable(self, settings: Settings) -> None:
        """§12 — the configured key must actually be able to encrypt."""
        fernet = settings.fernet()
        token = fernet.encrypt(b"exchange-api-secret")
        assert fernet.decrypt(token) == b"exchange-api-secret"

    def test_environment_predicates(self) -> None:
        assert make_production().is_production is True
        assert make_production().is_deployed is True
        # Staging is held to the production standard, so it needs a full valid
        # configuration to construct at all — which is itself the point.
        staging = make_production(environment=Environment.STAGING)
        assert staging.is_deployed is True
        assert staging.is_production is False
        development = Settings(environment=Environment.DEVELOPMENT)
        assert development.is_deployed is False
        assert development.is_test is False


class TestCrossFieldValidation:
    """These apply in every environment, not just production."""

    def test_samesite_none_requires_secure_cookie(self) -> None:
        with pytest.raises(ConfigurationError, match="COOKIE_SECURE"):
            Settings(environment=Environment.TEST, cookie_samesite="none", cookie_secure=False)

    def test_samesite_none_is_allowed_with_secure_cookie(self) -> None:
        parsed = Settings(environment=Environment.TEST, cookie_samesite="none", cookie_secure=True)
        assert parsed.cookie_samesite == "none"

    def test_invalid_samesite_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="COOKIE_SAMESITE"):
            Settings(environment=Environment.TEST, cookie_samesite="sometimes")

    @pytest.mark.parametrize("credentials", [True, False])
    def test_wildcard_cors_origin_is_always_rejected(self, credentials: bool) -> None:
        """A wildcard origin is refused regardless of the credentials flag (§61).

        This API authenticates with a Bearer token, so a wildcard would let any
        website issue cross-origin requests carrying a token obtained elsewhere.
        """
        with pytest.raises(ConfigurationError, match=r"may not be '\*'"):
            Settings(
                environment=Environment.TEST,
                cors_origins="*",
                cors_allow_credentials=credentials,
            )

    def test_explicit_origins_are_accepted(self) -> None:
        parsed = Settings(
            environment=Environment.TEST,
            cors_origins="https://app.example.com,https://admin.example.com",
        )
        assert parsed.cors_origin_list == [
            "https://app.example.com",
            "https://admin.example.com",
        ]

    def test_non_http_origin_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="not a valid http"):
            Settings(environment=Environment.TEST, cors_origins="file:///etc/passwd")

    def test_worker_staleness_must_exceed_heartbeat_interval(self) -> None:
        """Otherwise every worker is reported missing the moment it starts."""
        with pytest.raises(ConfigurationError, match="must exceed"):
            Settings(
                environment=Environment.TEST,
                worker_heartbeat_interval_seconds=30,
                worker_stale_after_seconds=30,
            )

    def test_unsafe_jwt_algorithm_is_rejected(self) -> None:
        """``alg=none`` and friends must not be configurable (§136)."""
        for algorithm in ("none", "None", "HS1", "MD5"):
            with pytest.raises(ValueError, match="not permitted"):
                Settings(environment=Environment.TEST, jwt_algorithm=algorithm)

    def test_sqlite_is_rejected_in_production(self) -> None:
        with pytest.raises(ConfigurationError, match="must use PostgreSQL"):
            make_production(database_url="sqlite+aiosqlite:///./prod.db")

    def test_invalid_encryption_key_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="url-safe base64"):
            Settings(environment=Environment.TEST, encryption_key="not-a-fernet-key")

    def test_fernet_key_must_be_32_bytes(self) -> None:
        import base64

        too_short = base64.urlsafe_b64encode(b"only-16-bytes!!!").decode()
        with pytest.raises(ConfigurationError, match="url-safe base64"):
            Settings(environment=Environment.TEST, encryption_key=too_short)

    def test_out_of_range_numeric_settings_are_rejected(self) -> None:
        with pytest.raises(ValueError):
            Settings(environment=Environment.TEST, api_port=99999)
        with pytest.raises(ValueError):
            Settings(environment=Environment.TEST, database_pool_size=-1)


class TestProductionFailClosed:
    """§145 — a misconfigured trading system must not start."""

    def test_a_valid_production_configuration_is_accepted(self) -> None:
        parsed = make_production()
        assert parsed.environment is Environment.PRODUCTION
        assert parsed.is_production is True

    def test_staging_is_held_to_the_same_standard(self) -> None:
        parsed = make_production(environment=Environment.STAGING)
        assert parsed.is_deployed is True
        with pytest.raises(ConfigurationError):
            make_production(environment=Environment.STAGING, debug=True)

    @pytest.mark.parametrize(
        ("override", "expected_fragment"),
        [
            ({"debug": True}, "DEBUG must be false"),
            ({"log_format": LogFormat.CONSOLE}, "LOG_FORMAT must be 'json'"),
            ({"log_redaction_enabled": False}, "LOG_REDACTION_ENABLED cannot be disabled"),
            ({"cookie_secure": False}, "COOKIE_SECURE must be true"),
            ({"cookie_httponly": False}, "COOKIE_HTTPONLY must be true"),
            ({"trust_proxy_headers": False}, "TRUST_PROXY_HEADERS"),
            ({"rate_limit_enabled": False}, "RATE_LIMIT_ENABLED must be true"),
        ],
    )
    def test_insecure_operational_settings_are_rejected(
        self, override: dict[str, object], expected_fragment: str
    ) -> None:
        with pytest.raises(ConfigurationError, match=expected_fragment):
            make_production(**override)

    @pytest.mark.parametrize(
        "field",
        ["jwt_secret", "session_secret"],
    )
    def test_committed_development_secrets_are_rejected(self, field: str) -> None:
        for known in KNOWN_INSECURE_SECRETS:
            if len(known) < 40:
                continue
            with pytest.raises(ConfigurationError, match="committed development value"):
                make_production(**{field: known})

    @pytest.mark.parametrize("field", ["jwt_secret", "session_secret"])
    def test_short_secrets_are_rejected(self, field: str) -> None:
        with pytest.raises(ConfigurationError, match="at least 64 characters"):
            make_production(**{field: "too-short"})

    @pytest.mark.parametrize("field", ["jwt_secret", "session_secret"])
    def test_placeholder_secrets_are_rejected(self, field: str) -> None:
        with pytest.raises(ConfigurationError, match="placeholder"):
            make_production(**{field: "CHANGE_ME_" + ("z" * 64)})
        with pytest.raises(ConfigurationError, match="placeholder"):
            make_production(**{field: "REPLACE_WITH_" + ("z" * 64)})

    def test_committed_encryption_key_is_rejected(self) -> None:
        """The dev/test keys are public in this repository."""
        for known in ("db4D7xAh6Dn9sk-oUr0U2mQ_uGYIxZmxIKFF53hShKA=",):
            with pytest.raises(ConfigurationError, match="ENCRYPTION_KEY"):
                make_production(encryption_key=known)

    def test_placeholder_encryption_key_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="placeholder"):
            make_production(encryption_key="REPLACE_WITH_GENERATED_FERNET_KEY")

    def test_a_generated_encryption_key_is_accepted(self) -> None:
        """The remediation path must actually work."""
        generated = Fernet.generate_key().decode()
        assert make_production(encryption_key=generated).encryption_key.get_secret_value() == (
            generated
        )

    @pytest.mark.parametrize("field", ["postgres_password", "grafana_admin_password"])
    def test_placeholder_service_passwords_are_rejected(self, field: str) -> None:
        for value in ("", "CHANGE_ME_grafana_password", "REPLACE_WITH_SECRET_MANAGER_VALUE"):
            # The message names the environment variable, not the field.
            with pytest.raises(ConfigurationError, match=field.upper()):
                make_production(**{field: value})

    def test_non_postgresql_database_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="must use PostgreSQL"):
            make_production(database_url="mysql+asyncmy://arb:x@db:3306/arbitrage")

    def test_live_trading_requires_the_feature_flag(self) -> None:
        """Two independent gates must agree before live trading (§31, §48)."""
        with pytest.raises(ConfigurationError, match="FEATURE_FLAG_LIVE_TRADING"):
            make_production(live_trading_enabled=True, feature_flag_live_trading=False)

    def test_live_trading_with_both_gates_is_accepted(self) -> None:
        parsed = make_production(live_trading_enabled=True, feature_flag_live_trading=True)
        assert parsed.live_trading_enabled is True

    def test_all_problems_are_reported_at_once(self) -> None:
        """An operator should not have to restart once per misconfiguration."""
        with pytest.raises(ConfigurationError) as excinfo:
            make_production(
                debug=True,
                cookie_secure=False,
                jwt_secret="short",
                session_secret="short",
                rate_limit_enabled=False,
                database_url="sqlite+aiosqlite:///./x.db",
            )
        message = str(excinfo.value)
        assert "DEBUG must be false" in message
        assert "COOKIE_SECURE must be true" in message
        assert "RATE_LIMIT_ENABLED must be true" in message
        assert "JWT_SECRET" in message
        assert "SESSION_SECRET" in message
        assert "6 configuration problem(s)" in message

    def test_error_message_contains_no_secret_values(self) -> None:
        secret = "a-very-specific-secret-value-that-must-not-appear"
        with pytest.raises(ConfigurationError) as excinfo:
            make_production(jwt_secret=secret)
        assert secret not in str(excinfo.value)


class TestEnvironmentFileResolution:
    def test_project_root_is_found_from_the_package_location(self) -> None:
        root = find_project_root()
        assert (root / "pyproject.toml").is_file()
        assert (root / ".env.example").is_file()

    def test_file_order_is_ascending_priority(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "test")
        files = resolve_env_files()
        assert [path.name for path in files] == [".env.example", ".env.test", ".env"]

    def test_missing_environment_file_is_not_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Production has no committed .env.production; values come from the env."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        files = resolve_env_files()
        assert not (files[1]).exists()  # .env.production is git-ignored

    def test_real_environment_variables_beat_dotenv_files(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§90 — the secret manager must always win over a committed template."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("LOG_LEVEL", "ERROR")
        monkeypatch.setenv("REDIS_KEY_PREFIX", "from_real_env")
        parsed = Settings()
        assert parsed.log_level == "ERROR"
        assert parsed.redis_key_prefix == "from_real_env"


class TestSettingsSingleton:
    def test_get_settings_is_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        reset_settings_cache()
        try:
            first = get_settings()
            second = get_settings()
            assert first is second
        finally:
            reset_settings_cache()

    def test_field_errors_surface_as_configuration_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pydantic field error must reach the operator as a clear failure."""
        reset_settings_cache()
        monkeypatch.setenv("API_PORT", "not-a-number")
        try:
            with pytest.raises(ConfigurationError, match="invalid platform configuration"):
                get_settings()
        finally:
            monkeypatch.delenv("API_PORT", raising=False)
            reset_settings_cache()

    def test_production_validation_runs_through_the_singleton(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Booting production with the committed templates must fail."""
        reset_settings_cache()
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.delenv("JWT_SECRET", raising=False)
        try:
            with pytest.raises(ConfigurationError, match="refusing to start in production"):
                get_settings()
        finally:
            monkeypatch.delenv("ENVIRONMENT", raising=False)
            reset_settings_cache()


class TestEncryptionKeyUsability:
    def test_the_production_test_key_is_a_valid_fernet_key(self) -> None:
        Fernet(TEST_PRODUCTION_ENCRYPTION_KEY.encode())
