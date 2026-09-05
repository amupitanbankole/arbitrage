"""Feature-flag persistence (§58, §110).

:func:`FeatureFlagRepository.ensure_defaults` is idempotent: it inserts only
flags that do not already exist. Re-running it after a deployment can therefore
introduce newly-added flags without ever reverting a value an administrator
changed (§91).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from arb_persistence.models.feature_flags import FeatureFlag
from arb_persistence.repositories.base import Repository

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["FeatureFlagRepository"]


class FeatureFlagRepository(Repository[FeatureFlag]):
    """Read and mutate feature flags."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, FeatureFlag)

    async def get_by_key(self, key: str) -> FeatureFlag | None:
        """Fetch one flag by its stable key."""
        statement = select(FeatureFlag).where(FeatureFlag.key == key)
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def list_all(self) -> Sequence[FeatureFlag]:
        """Every flag, ordered by key for stable admin rendering."""
        statement = select(FeatureFlag).order_by(FeatureFlag.key)
        result = await self._session.execute(statement)
        return list(result.scalars().all())

    async def ensure_defaults(self, defaults: Mapping[str, tuple[bool, str]]) -> int:
        """Seed missing flags. Returns how many rows were inserted."""
        existing = {flag.key for flag in await self.list_all()}
        missing = {key: value for key, value in defaults.items() if key not in existing}
        if not missing:
            return 0

        self.add_all(
            [
                FeatureFlag(
                    key=key,
                    description=description,
                    enabled=enabled,
                    # Rollout starts at 100% only when the flag is enabled; an
                    # enabled-with-0% flag means "allow-list only", which is the
                    # safe reading of a freshly introduced capability.
                    rollout_percentage=100 if enabled else 0,
                )
                for key, (enabled, description) in missing.items()
            ]
        )
        await self.flush()
        return len(missing)

    async def set_state(
        self,
        key: str,
        *,
        enabled: bool | None = None,
        rollout_percentage: int | None = None,
        allowed_plans: list[str] | None = None,
        updated_by: UUID | None = None,
    ) -> FeatureFlag:
        """Apply a partial update to one flag.

        Only the supplied arguments change. A partial-update signature prevents
        the common administrative bug of sending a full object built from a stale
        read and silently reverting somebody else's change.
        """
        flag = await self.get_by_key(key)
        if flag is None:
            msg = f"unknown feature flag: {key}"
            raise KeyError(msg)

        updates: dict[str, Any] = {}
        if enabled is not None:
            updates["enabled"] = enabled
            # Enabling without specifying a rollout defaults to everybody;
            # disabling always forces the rollout to zero so a later re-enable
            # cannot resume a wide rollout unintentionally.
            if rollout_percentage is None:
                updates["rollout_percentage"] = 100 if enabled else 0
        if rollout_percentage is not None:
            updates["rollout_percentage"] = rollout_percentage
        if allowed_plans is not None:
            updates["allowed_plans"] = allowed_plans
        if updated_by is not None:
            updates["updated_by"] = updated_by

        for field, value in updates.items():
            setattr(flag, field, value)
        await self.flush()
        return flag
