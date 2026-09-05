"""Shared, deterministic test configuration values.

Lives outside ``conftest.py`` on purpose: pytest imports conftest itself, so a
test module doing ``from tests.conftest import ...`` can end up with the module
loaded twice under different names. Keeping plain helpers here avoids that
entirely.

Every value in this module is derived from a public string and committed to the
repository. **None of them are secrets** (§89, §142). They are also all present in
``arb_core.config.KNOWN_INSECURE_SECRETS`` where relevant, so production startup
validation rejects them — which is exactly what makes them safe to commit.
"""

from __future__ import annotations

from typing import Any

from arb_core.config import Environment

__all__ = [
    "TEST_ENCRYPTION_KEY",
    "TEST_JWT_SECRET",
    "TEST_PRODUCTION_ENCRYPTION_KEY",
    "TEST_SESSION_SECRET",
    "override",
    "production_kwargs",
]

TEST_ENCRYPTION_KEY = "9b4jVmYWQwDDmHYJcNY1Izm4O9GVGhbAIF7zv0VR4tM="
TEST_JWT_SECRET = "test_only_insecure_jwt_secret_do_not_use_anywhere_else_0123456789abcdef"
TEST_SESSION_SECRET = "test_only_insecure_session_secret_do_not_use_anywhere_else_012345678"
#: A structurally valid Fernet key that is NOT one of the committed development
#: values, so production-startup validation accepts it.
TEST_PRODUCTION_ENCRYPTION_KEY = "gwJkzppyb-OX5v7mGKJIUFt3DSu102YbslIAaAtUMdI="


def production_kwargs() -> dict[str, Any]:
    """A configuration that satisfies every production startup check.

    Built as constructor arguments rather than ``model_copy(update=...)``:
    ``model_copy`` bypasses validation, so using it here would make the fixture
    unable to prove that the configuration it returns is actually accepted.
    """
    return {
        "environment": Environment.PRODUCTION,
        "debug": False,
        "log_format": "json",
        "log_redaction_enabled": True,
        "cookie_secure": True,
        "cookie_httponly": True,
        "cookie_samesite": "lax",
        "trust_proxy_headers": True,
        "rate_limit_enabled": True,
        "cors_origins": "https://app.example.com",
        "cors_allow_credentials": True,
        "database_url": "postgresql+asyncpg://arb:a-real-db-password@postgres:5432/arbitrage",
        "database_migration_url": "postgresql+psycopg://arb:a-real-db-password@postgres:5432/arbitrage",
        "redis_url": "redis://redis:6379/0",
        "jwt_secret": "production-jwt-secret-" + ("x" * 64),
        "session_secret": "production-session-secret-" + ("y" * 64),
        # A structurally valid key that is not a committed development value.
        "encryption_key": TEST_PRODUCTION_ENCRYPTION_KEY,
        "postgres_password": "a-real-production-db-password",
        "grafana_admin_password": "a-real-production-grafana-password",
        "worker_heartbeat_interval_seconds": 15,
        "worker_stale_after_seconds": 60,
    }


def override(base: Any, **changes: Any) -> Any:
    """Return a new validated ``Settings`` with ``changes`` applied.

    Reconstructs through the constructor rather than using
    ``model_copy(update=...)``, which bypasses validation entirely. A test that
    flips ``live_trading_enabled`` must still pass every consistency check, or it
    proves nothing about what production would accept.
    """
    from arb_core.config import Settings

    current = base.model_dump()
    current.update(changes)
    return Settings(**current)
