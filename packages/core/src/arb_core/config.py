"""Centralised configuration (§89, §90, §91).

A single :class:`Settings` object is the only place environment values are read.
Nothing else in the codebase touches ``os.environ`` directly, which keeps the
surface auditable and makes it impossible for a secret to be picked up
accidentally by an unreviewed ``getenv`` call.

Precedence, lowest to highest:

1. ``.env.example`` — documented, committed, non-secret defaults
2. ``.env.<environment>`` — per-environment overrides
3. ``.env`` — developer-local values (git-ignored)
4. **real environment variables** — Docker, CI and secret managers

Production fail-closed (§145)
------------------------------
A misconfigured trading system must not start. When ``ENVIRONMENT`` is
``production`` or ``staging``, :meth:`Settings.validate_deployed_environment`
raises :class:`~arb_core.errors.ConfigurationError` if debugging is on, any
secret is missing/short/a known development value, cookies are insecure, the
database is not PostgreSQL, or CORS is wildcarded with credentials. This runs at
import-of-settings time, so the container exits non-zero and the orchestrator
surfaces the failure instead of silently trading with a broken configuration.
"""

from __future__ import annotations

import os
from decimal import Decimal
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar, Final
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from arb_core.errors import ConfigurationError
from arb_core.log import get_logger
from arb_core.money import to_decimal
from arb_core.security.redaction import mask_dsn

__all__ = [
    "EmailProvider",
    "Environment",
    "LogFormat",
    "PasswordHashScheme",
    "Settings",
    "get_settings",
    "reset_settings_cache",
]

_logger = get_logger(__name__)

#: Secrets that appear in committed templates. Their presence in a deployed
#: environment means somebody copied a template without substituting real values.
KNOWN_INSECURE_SECRETS: Final[frozenset[str]] = frozenset(
    {
        # .env.example / .env.development
        "db4D7xAh6Dn9sk-oUr0U2mQ_uGYIxZmxIKFF53hShKA=",
        # .env.test
        "9b4jVmYWQwDDmHYJcNY1Izm4O9GVGhbAIF7zv0VR4tM=",
        "dev_only_insecure_jwt_secret_do_not_use_anywhere_else_0123456789abcdef",
        "dev_only_insecure_session_secret_do_not_use_anywhere_else_0123456789abc",
        "dev_only_not_a_secret",
        "test_only_insecure_jwt_secret_do_not_use_anywhere_else_0123456789abcdef",
        "test_only_insecure_session_secret_do_not_use_anywhere_else_012345678",
        "CHANGE_ME_jwt_secret_min_64_chars_long_random_string_aaaaaaaaaaaaaaaaaaaa",
        "CHANGE_ME_session_secret_min_64_chars_long_random_string_aaaaaaaaaaaaaaaa",
        "CHANGE_ME_db_password",
        "CHANGE_ME_grafana_password",
        "CHANGE_ME_smtp_password",
        "CHANGE_ME_telegram_bot_token",
    }
)

_MIN_SECRET_LENGTH: Final[int] = 64
_PLACEHOLDER_PREFIXES: Final[tuple[str, ...]] = ("CHANGE_ME", "REPLACE_WITH", "REPLACE")


class Environment(StrEnum):
    """Deployment environment. Drives every safety default in the platform."""

    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_deployed(self) -> bool:
        """``True`` for environments reachable by real users and real money."""
        return self in {Environment.STAGING, Environment.PRODUCTION}


class LogFormat(StrEnum):
    """Log rendering mode (§127)."""

    JSON = "json"
    CONSOLE = "console"


class EmailProvider(StrEnum):
    """Notification transport for email (§56)."""

    NONE = "none"
    SMTP = "smtp"
    SES = "ses"


class PasswordHashScheme(StrEnum):
    """Password hashing algorithm (§3, §59)."""

    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"


def _split_csv(raw: str) -> list[str]:
    """Split a comma-separated environment value, trimming and dropping blanks."""
    return [item.strip() for item in raw.split(",") if item.strip()]


def find_project_root(start: Path | None = None) -> Path:
    """Locate the monorepo root by walking up from ``start``.

    The root is identified by the presence of both the workspace
    ``pyproject.toml`` and ``.env.example``. Falls back to the current working
    directory, which is correct inside containers where no dotenv files exist.
    """
    current = (start or Path(__file__)).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / ".env.example").is_file():
            return candidate
    return Path.cwd()


def resolve_env_files(root: Path | None = None) -> tuple[Path, ...]:
    """Return the dotenv files to load, in ascending priority order."""
    base = root or find_project_root()
    environment = (os.getenv("ENVIRONMENT") or "development").strip().lower() or "development"
    return (
        base / ".env.example",
        base / f".env.{environment}",
        base / ".env",
    )


class _MultiFileDotEnvSource(PydanticBaseSettingsSource):
    """Dotenv source that honours the ordered file list from :func:`resolve_env_files`.

    ``pydantic-settings`` already knows how to merge several dotenv files (later
    files win), so this is a thin wrapper whose only job is to compute that
    ordered list at construction time. Missing files are skipped rather than
    raising, so the same ``Settings`` class works unchanged inside a container
    that receives configuration purely from real environment variables.
    """

    def __init__(self, settings_cls: type[BaseSettings], env_files: tuple[Path, ...]) -> None:
        existing = tuple(path for path in env_files if path.is_file())
        self._delegate: DotEnvSettingsSource | None = (
            DotEnvSettingsSource(settings_cls, env_file=existing, case_sensitive=False)
            if existing
            else None
        )

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        if self._delegate is None:
            return None, field_name, False
        return self._delegate.get_field_value(field, field_name)

    def __call__(self) -> dict[str, Any]:
        if self._delegate is None:
            return {}
        return self._delegate()


class Settings(BaseSettings):
    """Platform configuration.

    Field names map 1:1 to the uppercase environment variables documented in
    ``.env.example``.
    """

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_file=None,  # handled by settings_customise_sources
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
        frozen=False,
    )

    # --- 1. Application -----------------------------------------------------
    environment: Environment = Environment.DEVELOPMENT
    service_name: str = "arbitrage-platform"
    app_version: str = "0.1.0"
    debug: bool = False

    # --- 2. Logging (§66, §127) ---------------------------------------------
    log_format: LogFormat = LogFormat.JSON
    log_level: str = "INFO"
    log_redaction_enabled: bool = True

    # --- 3. HTTP ------------------------------------------------------------
    # Binding all interfaces is required inside a container: the port is
    # published by the orchestrator, and 127.0.0.1 would make the service
    # unreachable from outside its own network namespace. The API port is
    # deliberately NOT published in the production compose file (§124), so
    # this is not an exposure — nginx fronts it.
    api_host: str = "0.0.0.0"  # noqa: S104 - see above
    api_port: int = Field(default=8000, ge=1, le=65535)
    trust_proxy_headers: bool = False
    #: Comma-separated list of proxy addresses whose ``X-Forwarded-For`` header is
    #: trusted. ``*`` trusts any peer, which is only acceptable because the API
    #: port is not published to the host in production (§124) — nginx is the only
    #: reachable client. Set this to the reverse-proxy address if the API is ever
    #: exposed directly, otherwise client IP (and therefore audit and rate-limit
    #: data) is spoofable.
    forwarded_allow_ips: str = "*"
    api_base_url: str = "http://localhost:8000"
    frontend_url: str = "http://localhost:3000"
    internal_api_url: str = "http://api:8000"
    cors_origins: str = "http://localhost:3000"
    cors_allow_credentials: bool = True

    # --- 4. PostgreSQL (§64) -------------------------------------------------
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://arbitrage:dev_only_not_a_secret@localhost:5432/arbitrage"
    )
    database_migration_url: SecretStr = SecretStr(
        "postgresql+psycopg://arbitrage:dev_only_not_a_secret@localhost:5432/arbitrage"
    )
    database_pool_size: int = Field(default=10, ge=0, le=500)
    database_max_overflow: int = Field(default=20, ge=0, le=500)
    database_pool_timeout_seconds: int = Field(default=30, ge=1, le=600)
    database_pool_recycle_seconds: int = Field(default=1800, ge=30, le=86400)
    database_echo: bool = False

    # --- 5. Redis (§64) ------------------------------------------------------
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")
    redis_max_connections: int = Field(default=50, ge=1, le=5000)
    redis_key_prefix: str = "arb"
    redis_socket_timeout_seconds: float = Field(default=5.0, gt=0, le=300)
    redis_health_check_interval_seconds: int = Field(default=30, ge=0, le=3600)

    # --- 6. Authentication (§59, §60) ----------------------------------------
    jwt_secret: SecretStr = SecretStr(
        "dev_only_insecure_jwt_secret_do_not_use_anywhere_else_0123456789abcdef"
    )
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_ttl_days: int = Field(default=30, ge=1, le=365)
    session_ttl_hours: int = Field(default=12, ge=1, le=720)
    session_idle_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    session_secret: SecretStr = SecretStr(
        "dev_only_insecure_session_secret_do_not_use_anywhere_else_0123456789abc"
    )

    # --- 7. Password hashing (§59) -------------------------------------------
    password_hash_scheme: PasswordHashScheme = PasswordHashScheme.ARGON2ID
    argon2_time_cost: int = Field(default=3, ge=1, le=32)
    argon2_memory_cost_kib: int = Field(default=65536, ge=8192, le=2097152)
    argon2_parallelism: int = Field(default=4, ge=1, le=64)
    password_min_length: int = Field(default=12, ge=8, le=256)

    # --- 8. Credential encryption (§12) --------------------------------------
    encryption_key: SecretStr = SecretStr("db4D7xAh6Dn9sk-oUr0U2mQ_uGYIxZmxIKFF53hShKA=")
    encryption_context: str = "arbitrage-platform"
    #: Development-only escape hatch allowing template placeholders to pass
    #: validation. It is ignored in staging/production regardless of its value.
    allow_placeholder_secrets: bool = Field(
        default=False, validation_alias="ARB_ALLOW_PLACEHOLDER_SECRETS"
    )

    # --- 9. Cookies / CSRF (§61) ---------------------------------------------
    cookie_secure: bool = False
    cookie_httponly: bool = True
    cookie_samesite: str = "lax"
    cookie_domain: str = ""

    # --- 10. Rate limiting (§61) ---------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_default: str = "120/minute"
    rate_limit_auth: str = "10/minute"
    rate_limit_admin: str = "60/minute"

    # --- 11. Trading safety (§31, §32) ---------------------------------------
    live_trading_enabled: bool = False
    global_kill_switch_enabled: bool = False
    default_max_trade_usd: Decimal = Decimal("25")
    default_max_daily_loss_usd: Decimal = Decimal("25")
    default_max_concurrent_trades: int = Field(default=1, ge=0, le=1000)
    default_max_exchange_exposure_usd: Decimal = Decimal("100")
    market_data_max_age_ms: int = Field(default=2000, ge=1, le=600000)
    opportunity_ttl_seconds: int = Field(default=5, ge=1, le=3600)

    # --- 12. Notifications (§56) ---------------------------------------------
    email_provider: EmailProvider = EmailProvider.NONE
    email_from_address: str = "no-reply@example.com"
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_starttls: bool = True
    telegram_bot_token: SecretStr = SecretStr("")
    telegram_default_chat_id: str = ""

    # --- 13. Observability (§54, §112) ---------------------------------------
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    metrics_auth_token: SecretStr = SecretStr("")
    prometheus_url: str = "http://localhost:9090"
    grafana_url: str = "http://localhost:3001"

    # --- 14. Workers (§55) ----------------------------------------------------
    worker_roles: str = "foundation"
    worker_heartbeat_interval_seconds: int = Field(default=15, ge=1, le=3600)
    worker_stale_after_seconds: int = Field(default=60, ge=5, le=86400)
    worker_concurrency: int = Field(default=4, ge=1, le=512)

    # --- 15. Feature-flag bootstrap defaults (§58) ----------------------------
    #
    # One attribute per key in FEATURE_FLAG_DEFAULTS, and nothing else. These
    # only seed the ``feature_flags`` table on first start; the database row
    # wins afterwards (§110), so an operator's decision survives a redeploy.
    feature_flag_paper_trading: bool = True
    feature_flag_live_trading: bool = False
    feature_flag_backtesting: bool = False
    #: Non-default strategies such as futures/spot basis (§19).
    feature_flag_advanced_strategies: bool = False
    feature_flag_dex_trading: bool = False
    feature_flag_rebalancing: bool = False
    #: Hedging and multi-leg recovery automation (§28).
    feature_flag_advanced_execution: bool = False

    # --- 16. Frontend ---------------------------------------------------------
    next_public_api_base_url: str = "http://localhost:8000"
    next_public_app_name: str = "Arbitrage Platform"
    next_public_demo_mode: bool = False

    # --- 17. Monitoring stack (docker-compose only) ---------------------------
    postgres_db: str = "arbitrage"
    postgres_user: str = "arbitrage"
    postgres_password: SecretStr = SecretStr("dev_only_not_a_secret")
    grafana_admin_user: str = "admin"
    grafana_admin_password: SecretStr = SecretStr("CHANGE_ME_grafana_password")

    # ------------------------------------------------------------------
    # Source customisation
    # ------------------------------------------------------------------
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order sources so real environment variables always win (§90)."""
        del dotenv_settings  # replaced by the multi-file source below
        return (
            init_settings,
            env_settings,
            _MultiFileDotEnvSource(settings_cls, resolve_env_files()),
            file_secret_settings,
        )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------
    @field_validator("cookie_samesite")
    @classmethod
    def _validate_samesite(cls, value: str) -> str:
        normalised = value.strip().lower()
        allowed = {"lax", "strict", "none"}
        if normalised not in allowed:
            msg = f"COOKIE_SAMESITE must be one of {sorted(allowed)}, got {value!r}"
            raise ValueError(msg)
        return normalised

    @field_validator("jwt_algorithm")
    @classmethod
    def _validate_jwt_algorithm(cls, value: str) -> str:
        # "none" and asymmetric-key-confusion algorithms are rejected outright.
        allowed = {"HS256", "HS384", "HS512", "RS256", "ES256", "EdDSA"}
        if value not in allowed:
            msg = f"JWT_ALGORITHM {value!r} is not permitted; allowed: {sorted(allowed)}"
            raise ValueError(msg)
        return value

    @field_validator(
        "default_max_trade_usd",
        "default_max_daily_loss_usd",
        "default_max_exchange_exposure_usd",
        mode="before",
    )
    @classmethod
    def _coerce_decimal(cls, value: Any) -> Decimal:
        """Accept string/number input but keep ``Decimal`` internally (§74)."""
        if isinstance(value, Decimal):
            return value
        return to_decimal(value, strict=False)

    @model_validator(mode="after")
    def _validate_consistency(self) -> Settings:
        """Cross-field invariants that apply in every environment."""
        if self.cookie_samesite == "none" and not self.cookie_secure:
            msg = "COOKIE_SAMESITE=none requires COOKIE_SECURE=true"
            raise ConfigurationError(msg)

        origins = self.cors_origin_list
        # A wildcard origin is rejected unconditionally, not only when
        # credentials are enabled. This API authenticates with a Bearer token
        # (§59), and a wildcard lets any website on the internet issue
        # cross-origin requests carrying a token it obtained elsewhere (an XSS on
        # a third-party page, a leaked browser extension). Listing explicit
        # origins costs nothing and removes the whole class of problem (§61).
        if "*" in origins:
            msg = (
                "CORS_ORIGINS may not be '*'. List the explicit browser origins "
                "that may call this API."
            )
            raise ConfigurationError(msg)
        for origin in origins:
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                msg = f"CORS_ORIGINS entry {origin!r} is not a valid http(s) origin"
                raise ConfigurationError(msg)

        if self.worker_stale_after_seconds <= self.worker_heartbeat_interval_seconds:
            msg = (
                "WORKER_STALE_AFTER_SECONDS must exceed WORKER_HEARTBEAT_INTERVAL_SECONDS "
                "or every worker will be reported missing"
            )
            raise ConfigurationError(msg)

        # Encryption key must be usable before anything tries to store a secret.
        self._validate_encryption_key()

        if self.environment.is_deployed:
            self.validate_deployed_environment()
        return self

    def _validate_encryption_key(self) -> None:
        """Ensure ``ENCRYPTION_KEY`` is a usable Fernet key (§12)."""
        key = self.encryption_key.get_secret_value()
        if key.startswith(_PLACEHOLDER_PREFIXES):
            if not (self.allow_placeholder_secrets and not self.environment.is_deployed):
                msg = "ENCRYPTION_KEY is still a template placeholder"
                raise ConfigurationError(msg)
            return
        try:
            Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            msg = (
                "ENCRYPTION_KEY must be a url-safe base64-encoded 32-byte key. "
                "Generate one with: python -c "
                '"from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"'
            )
            raise ConfigurationError(msg) from exc

    def validate_deployed_environment(self) -> None:
        """Fail closed when a staging/production configuration is unsafe (§145).

        Raises :class:`~arb_core.errors.ConfigurationError` listing every problem
        found, so an operator fixes the whole configuration in one pass instead
        of discovering issues one restart at a time.
        """
        problems: list[str] = []

        if self.debug:
            problems.append("DEBUG must be false")
        if self.log_format is not LogFormat.JSON:
            problems.append("LOG_FORMAT must be 'json' for machine-parseable logs")
        if not self.log_redaction_enabled:
            problems.append("LOG_REDACTION_ENABLED cannot be disabled")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE must be true")
        if not self.cookie_httponly:
            problems.append("COOKIE_HTTPONLY must be true")
        if not self.trust_proxy_headers:
            problems.append("TRUST_PROXY_HEADERS should be true behind nginx")
        if not self.rate_limit_enabled:
            problems.append("RATE_LIMIT_ENABLED must be true")

        # SQLite is acceptable in development and test only (§64). Checked here
        # rather than in the cross-field validator so it is reported together
        # with every other problem in a single pass.
        scheme = urlparse(self.database_url.get_secret_value()).scheme
        if not scheme.startswith("postgresql"):
            problems.append(
                f"DATABASE_URL must use PostgreSQL in staging/production, got scheme {scheme!r}"
            )

        for name, value in (
            ("JWT_SECRET", self.jwt_secret.get_secret_value()),
            ("SESSION_SECRET", self.session_secret.get_secret_value()),
        ):
            if value in KNOWN_INSECURE_SECRETS:
                problems.append(f"{name} is a committed development value")
            elif value.startswith(_PLACEHOLDER_PREFIXES):
                problems.append(f"{name} is still a template placeholder")
            elif len(value) < _MIN_SECRET_LENGTH:
                problems.append(f"{name} must be at least {_MIN_SECRET_LENGTH} characters")

        encryption_key = self.encryption_key.get_secret_value()
        if encryption_key in KNOWN_INSECURE_SECRETS:
            problems.append("ENCRYPTION_KEY is a committed development value")

        for name, secret in (
            ("POSTGRES_PASSWORD", self.postgres_password),
            ("GRAFANA_ADMIN_PASSWORD", self.grafana_admin_password),
        ):
            value = secret.get_secret_value()
            if (
                not value
                or value in KNOWN_INSECURE_SECRETS
                or value.startswith(_PLACEHOLDER_PREFIXES)
            ):
                problems.append(
                    f"{name} is missing, a placeholder, or a committed development value"
                )

        if self.live_trading_enabled and not self.feature_flag_live_trading:
            problems.append("LIVE_TRADING_ENABLED is true but FEATURE_FLAG_LIVE_TRADING is false")

        if problems:
            detail = "; ".join(problems)
            msg = (
                f"refusing to start in {self.environment.value}: "
                f"{len(problems)} configuration problem(s): {detail}"
            )
            raise ConfigurationError(msg)

    # ------------------------------------------------------------------
    # Derived values
    # ------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        """``True`` only for ``ENVIRONMENT=production``."""
        return self.environment is Environment.PRODUCTION

    @property
    def is_deployed(self) -> bool:
        """``True`` for staging and production."""
        return self.environment.is_deployed

    @property
    def is_test(self) -> bool:
        """``True`` for the automated test-suite environment."""
        return self.environment is Environment.TEST

    @property
    def cors_origin_list(self) -> list[str]:
        """Parsed ``CORS_ORIGINS`` list."""
        return _split_csv(self.cors_origins)

    @property
    def worker_role_list(self) -> list[str]:
        """Parsed ``WORKER_ROLES`` list."""
        return _split_csv(self.worker_roles)

    @property
    def database_url_safe(self) -> str:
        """``DATABASE_URL`` with the password masked — safe to log (§127)."""
        return mask_dsn(self.database_url.get_secret_value())

    @property
    def redis_url_safe(self) -> str:
        """``REDIS_URL`` with any password masked — safe to log."""
        return mask_dsn(self.redis_url.get_secret_value())

    @property
    def sqlalchemy_engine_kwargs(self) -> dict[str, Any]:
        """Connection-pool arguments for the async SQLAlchemy engine (§81)."""
        kwargs: dict[str, Any] = {
            "echo": self.database_echo,
            "future": True,
        }
        # SQLite (development/test only) does not support pool sizing the same
        # way and rejects asyncpg-specific arguments.
        if self.database_url.get_secret_value().startswith("sqlite"):
            return kwargs
        kwargs.update(
            {
                "pool_size": self.database_pool_size,
                "max_overflow": self.database_max_overflow,
                "pool_timeout": self.database_pool_timeout_seconds,
                "pool_recycle": self.database_pool_recycle_seconds,
                "pool_pre_ping": True,
            }
        )
        return kwargs

    @property
    def redis_connection_kwargs(self) -> dict[str, Any]:
        """Connection arguments for the async Redis client."""
        return {
            "max_connections": self.redis_max_connections,
            "socket_timeout": self.redis_socket_timeout_seconds,
            "socket_connect_timeout": self.redis_socket_timeout_seconds,
            "health_check_interval": self.redis_health_check_interval_seconds,
            "retry_on_timeout": True,
            "decode_responses": False,
        }

    def fernet(self) -> Fernet:
        """Return a Fernet instance for credential envelope encryption (§12)."""
        return Fernet(self.encryption_key.get_secret_value().encode())

    def redis_key(self, *parts: str) -> str:
        """Build a namespaced Redis key so environments can share a server."""
        joined = ":".join(part.strip(":") for part in parts if part)
        return f"{self.redis_key_prefix}:{joined}" if joined else self.redis_key_prefix


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings` singleton.

    Cached because constructing it parses dotenv files; a per-request cost would
    be wasteful and would make configuration appear to change at runtime.
    """
    try:
        settings = Settings()
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        )
        msg = f"invalid platform configuration: {details}"
        raise ConfigurationError(msg) from exc
    except ConfigurationError:
        # Cross-field and deployed-environment checks raise this directly so the
        # operator sees the precise problem rather than a pydantic wrapper.
        raise

    _logger.info(
        "configuration loaded",
        extra={
            "environment": settings.environment.value,
            "service": settings.service_name,
            "database": settings.database_url_safe,
            "redis": settings.redis_url_safe,
            "live_trading_enabled": settings.live_trading_enabled,
            "global_kill_switch_enabled": settings.global_kill_switch_enabled,
        },
    )
    return settings


def reset_settings_cache() -> None:
    """Drop the cached settings. Test-only; production config is immutable."""
    get_settings.cache_clear()
