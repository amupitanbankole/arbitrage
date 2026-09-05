"""ORM models.

Importing this package registers every model on ``arb_core.db.Base.metadata``,
which is what Alembic's ``target_metadata`` reads. A model that is not imported
here is invisible to autogenerate and will silently never be migrated — so new
models must always be added to the imports and to ``__all__``.

Phase 1 scope
-------------
Only platform-infrastructure tables exist so far. The domain tables listed in §10
(authentication, exchanges, markets, strategies, arbitrage, orders, balances,
P&L, risk, bots, notifications, SaaS) are added by the phase that needs them,
each with its own migration (§9, §141). The current status of every table is
tracked in ``docs/STATUS.md``.
"""

from __future__ import annotations

from arb_core.db import Base
from arb_persistence.models.audit import AuditLog
from arb_persistence.models.enums import ActorType, AuditResult, WorkerStatus, enum_column
from arb_persistence.models.feature_flags import FEATURE_FLAG_DEFAULTS, FeatureFlag
from arb_persistence.models.observability import SystemHealthSnapshot, WorkerHeartbeat

__all__ = [
    "FEATURE_FLAG_DEFAULTS",
    "ActorType",
    "AuditLog",
    "AuditResult",
    "Base",
    "FeatureFlag",
    "SystemHealthSnapshot",
    "WorkerHeartbeat",
    "WorkerStatus",
    "enum_column",
]
