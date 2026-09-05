"""Feature-flag evaluation (§58, §110).

The database row is authoritative. ``Settings.feature_flag_*`` values are
bootstrap defaults used for two things only: seeding the table on first start,
and deciding what to do when the flag cannot be read.

That second use is a safety decision, and it is **fail-closed**: if the database
or cache is unreachable, the value falls back to the committed default, which is
``False`` for every capability that can lose money. A transient dependency
outage must never result in live trading being treated as enabled (§25, §145).

Flags are cached in Redis for a short window. The cache stores the flag *row*,
not the evaluation result, because rollout percentage and allow-lists are
per-user: caching the boolean would either leak one user's evaluation to another
or require a cache key per user, which is unbounded cardinality in Redis.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from arb_core.errors import ErrorCode, FeatureDisabledError
from arb_core.log import get_logger
from arb_core.redis.client import RedisClient, decode
from arb_persistence.models.feature_flags import FEATURE_FLAG_DEFAULTS, FeatureFlag
from arb_persistence.repositories.feature_flags import FeatureFlagRepository

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from arb_core.config import Settings

__all__ = ["FeatureFlagService"]

_logger = get_logger(__name__)

_CACHE_TTL_SECONDS: Final[int] = 30
_MAX_CACHE_TTL_SECONDS: Final[int] = 300

#: Maps a flag key to the Settings attribute holding its bootstrap default.
#:
#: Every key of :data:`FEATURE_FLAG_DEFAULTS` must appear here exactly once and
#: point at its *own* attribute; a test asserts this. Reusing one attribute for
#: two keys silently couples unrelated capabilities.
_BOOTSTRAP_ATTRIBUTES: Final[dict[str, str]] = {
    "paper_trading": "feature_flag_paper_trading",
    "live_trading": "feature_flag_live_trading",
    "backtesting": "feature_flag_backtesting",
    "advanced_strategies": "feature_flag_advanced_strategies",
    "dex_trading": "feature_flag_dex_trading",
    "rebalancing": "feature_flag_rebalancing",
    "advanced_execution": "feature_flag_advanced_execution",
}


class FeatureFlagService:
    """Reads and evaluates feature flags."""

    def __init__(
        self,
        *,
        settings: Settings,
        session: AsyncSession | None = None,
        redis: RedisClient | None = None,
    ) -> None:
        self._settings = settings
        self._session = session
        self._redis = redis
        self._repository = FeatureFlagRepository(session) if session is not None else None

    # --- public API ------------------------------------------------------
    def bootstrap_default(self, key: str) -> bool:
        """Committed default for ``key``. Unknown keys default to disabled."""
        attribute = _BOOTSTRAP_ATTRIBUTES.get(key)
        if attribute is None:
            return False
        return bool(getattr(self._settings, attribute, False))

    async def is_enabled(
        self,
        key: str,
        *,
        plan: str | None = None,
        user_id: UUID | None = None,
    ) -> bool:
        """Evaluate ``key`` for one caller, failing closed on any error."""
        cached = await self._read_cache(key)
        if cached is not None:
            return self._evaluate(cached, plan=plan, user_id=user_id)

        flag = await self._load(key)
        if flag is None:
            # Unknown or unreadable flag: the committed default is the only safe
            # answer, and it is False for anything that can lose money.
            fallback = self.bootstrap_default(key)
            _logger.warning(
                "feature flag unavailable; falling back to committed default",
                extra={"flag": key, "fallback": fallback, "fail_closed": not fallback},
            )
            return fallback

        await self._write_cache(key, flag)
        return flag.is_enabled_for(plan=plan, user_id=user_id)

    async def require_enabled(
        self,
        key: str,
        *,
        plan: str | None = None,
        user_id: UUID | None = None,
        message: str | None = None,
    ) -> None:
        """Raise :class:`FeatureDisabledError` unless ``key`` is enabled (§58).

        Server-side enforcement. A flag that only hides a control in the UI is
        not a control (§43).
        """
        if not await self.is_enabled(key, plan=plan, user_id=user_id):
            raise FeatureDisabledError(
                message or f"the '{key}' capability is not enabled",
                code=ErrorCode.FEATURE_DISABLED,
                details={"flag": key},
            )

    async def list_flags(self) -> list[dict[str, Any]]:
        """Administrative view of every flag. Contains no secrets."""
        if self._repository is None:
            return [
                {"key": key, "enabled": enabled, "description": description}
                for key, (enabled, description) in sorted(FEATURE_FLAG_DEFAULTS.items())
            ]
        flags = await self._repository.list_all()
        return [flag.safe_snapshot() for flag in flags]

    async def ensure_seeded(self) -> int:
        """Insert any flag defined in code but missing from the database.

        Idempotent, and it never overwrites an existing value: an administrator's
        decision must survive a redeploy (§91).
        """
        if self._repository is None:
            return 0
        return await self._repository.ensure_defaults(FEATURE_FLAG_DEFAULTS)

    # --- internals -------------------------------------------------------
    async def _load(self, key: str) -> FeatureFlag | None:
        if self._repository is None:
            return None
        try:
            return await self._repository.get_by_key(key)
        except Exception:  # fail closed, never propagate
            _logger.exception("failed to read feature flag", extra={"flag": key})
            return None

    def _cache_key(self, key: str) -> str:
        if self._redis is None:
            return ""
        return self._redis.key("feature_flag", key)

    async def _read_cache(self, key: str) -> dict[str, Any] | None:
        if self._redis is None:
            return None
        try:
            raw = await self._redis.raw.get(self._cache_key(key))
        except Exception:  # noqa: BLE001 - cache is an optimisation, not a dependency
            _logger.warning("feature flag cache read failed", extra={"flag": key})
            return None
        if raw is None:
            return None
        try:
            decoded = decode(raw)
            payload = json.loads(decoded) if isinstance(decoded, str) else None
        except (ValueError, TypeError):
            _logger.warning("discarding malformed feature flag cache entry", extra={"flag": key})
            return None
        return payload if isinstance(payload, dict) else None

    async def _write_cache(self, key: str, flag: FeatureFlag) -> None:
        if self._redis is None:
            return
        payload = {
            "key": flag.key,
            "enabled": flag.enabled,
            "rollout_percentage": flag.rollout_percentage,
            "allowed_plans": flag.allowed_plans,
            "allowed_user_ids": flag.allowed_user_ids,
        }
        try:
            await self._redis.raw.set(
                self._cache_key(key),
                json.dumps(payload),
                ex=min(_CACHE_TTL_SECONDS, _MAX_CACHE_TTL_SECONDS),
            )
        except Exception:  # noqa: BLE001 - cache write failure is not fatal
            _logger.warning("feature flag cache write failed", extra={"flag": key})

    @staticmethod
    def _evaluate(
        payload: dict[str, Any],
        *,
        plan: str | None,
        user_id: UUID | None,
    ) -> bool:
        """Evaluate a cached flag payload with the same rules as the model.

        Mirrors :meth:`arb_persistence.models.feature_flags.FeatureFlag.is_enabled_for`
        step for step: master switch, plan allow-list, user allow-list, rollout.
        The ordering is a security property, and two implementations of one rule
        will drift — so a test compares them across every combination rather
        than trusting this docstring.
        """
        if not payload.get("enabled", False):
            return False

        allowed_plans = payload.get("allowed_plans")
        if allowed_plans is not None and plan not in allowed_plans:
            return False

        allowed_users = payload.get("allowed_user_ids")
        if allowed_users is not None and user_id is not None and str(user_id) in allowed_users:
            # Additive fast-path: admitted whatever the rollout says.
            return True

        rollout = int(payload.get("rollout_percentage") or 0)
        if rollout >= 100:
            return True
        if rollout <= 0 or user_id is None:
            return False
        return user_id.int % 100 < rollout
