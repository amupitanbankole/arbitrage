"""Database-driven feature flags (§58, §110).

Flags are rows, not constants. Hard-coding ``if settings.live_trading`` across
the codebase would mean a behaviour change requires a deployment, and would make
it impossible to enable a capability for one plan or a percentage of users —
which is exactly how live trading must be rolled out (§135).

Precedence is explicit: the **database row wins**. ``Settings.feature_flag_*``
values are bootstrap defaults used only to seed the table on first start, so a
container restart can never silently re-enable something an administrator turned
off (§91).

Enforcement is server-side only. A flag that merely hides a button in the UI is
not a control (§43).
"""

from __future__ import annotations

import uuid
from typing import Any, Final

from sqlalchemy import Boolean, CheckConstraint, SmallInteger, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from arb_core.db import GUID, Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin

__all__ = ["FEATURE_FLAG_DEFAULTS", "FeatureFlag"]

_FLAG_KEY_MAX_LENGTH: Final[int] = 64

#: Bootstrap values seeded into ``feature_flags`` on first migration run.
#:
#: Everything that can lose money is off by default (§31, §110). ``dex_trading``
#: and ``rebalancing`` stay off until their phases ship (§20, §36);
#: ``backtesting`` and ``advanced_strategies`` are enabled only once the engines
#: exist (§37).
FEATURE_FLAG_DEFAULTS: Final[dict[str, tuple[bool, str]]] = {
    "paper_trading": (True, "Simulated execution using live market data (§30)"),
    "live_trading": (False, "Real order submission; requires explicit per-bot activation (§31)"),
    "backtesting": (False, "Historical simulation of strategies (§37)"),
    "advanced_strategies": (False, "Futures/spot basis and other non-default strategies (§19)"),
    "dex_trading": (False, "On-chain execution via wallet adapters (§20)"),
    "rebalancing": (False, "Cross-exchange inventory rebalancing recommendations (§36)"),
    "advanced_execution": (False, "Hedging and multi-leg recovery automation (§28)"),
}


class FeatureFlag(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single server-side capability gate."""

    __tablename__ = "feature_flags"
    __table_args__ = (
        CheckConstraint(
            "rollout_percentage >= 0 AND rollout_percentage <= 100",
            name="rollout_percentage_within_range",
        ),
    )

    #: Stable identifier matched in code, e.g. ``live_trading``.
    #: `unique=True` implies an index for key lookups on every supported
    #: dialect, so a separate `index=True` would create a redundant one.
    key: Mapped[str] = mapped_column(String(_FLAG_KEY_MAX_LENGTH), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Master switch. When false the flag is off for everyone regardless of
    #: rollout percentage or allow-lists.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Graduated rollout: 0 = nobody, 100 = everybody. Deterministic per user so
    #: a user does not flip between states across requests (§135).
    rollout_percentage: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)

    #: Optional subscription-plan allow-list (§57). ``None`` means "any plan".
    allowed_plans: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)

    #: Optional per-user allow-list: an **additive** fast-path admitting named
    #: users regardless of ``rollout_percentage``. This is what makes "internal
    #: testers at 0%, then widen the rollout" work — the listed users keep access
    #: as the percentage climbs, and everyone else follows the rollout.
    allowed_user_ids: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)

    #: Administrator who last changed the flag. Correlates with ``audit_logs``
    #: (§53, §91) — every flag change must also produce an audit entry.
    updated_by: Mapped[uuid.UUID | None] = mapped_column(GUID, nullable=True)

    def is_enabled_for(
        self,
        *,
        plan: str | None = None,
        user_id: uuid.UUID | None = None,
    ) -> bool:
        """Evaluate this flag for one caller.

        The evaluation order is a security property (§57, §58):

        1. **Master switch** — a disabled flag is off for everyone, so no
           rollout percentage or allow-list can grant it.
        2. **Plan allow-list** — a commercial gate. Being in the rollout bucket,
           or being individually allow-listed, cannot bypass it.
        3. **User allow-list** — an additive fast-path for named testers.
        4. **Percentage rollout** — deterministic per user, and an anonymous
           caller cannot be bucketed so is not admitted below 100%.
        """
        if not self.enabled:
            return False

        if self.allowed_plans is not None and plan not in self.allowed_plans:
            return False

        if (
            self.allowed_user_ids is not None
            and user_id is not None
            and str(user_id) in self.allowed_user_ids
        ):
            # Explicitly allow-listed: admitted whatever the rollout says.
            return True

        if self.rollout_percentage >= 100:
            return True
        if self.rollout_percentage <= 0:
            # Enabled at 0% with nobody allow-listed means "nobody yet".
            return False
        if user_id is None:
            # An anonymous caller cannot be bucketed deterministically, so it is
            # not admitted to a partial rollout.
            return False

        # Stable bucketing on the identifier's own entropy: the same user always
        # lands in the same bucket, and no hash of a secret is involved.
        bucket = user_id.int % 100
        return bucket < self.rollout_percentage

    def safe_snapshot(self) -> dict[str, Any]:
        """Administrative view of the flag. Contains no secrets by construction."""
        return {
            "key": self.key,
            "description": self.description,
            "enabled": self.enabled,
            "rollout_percentage": self.rollout_percentage,
            "allowed_plans": self.allowed_plans,
            "allowed_user_ids": self.allowed_user_ids,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
