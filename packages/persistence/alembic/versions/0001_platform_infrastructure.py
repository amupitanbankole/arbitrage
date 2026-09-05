"""platform infrastructure: audit log, feature flags, worker heartbeats, system health

Phase 1 foundation (§9, §10, §53, §55, §58, §141).

Scope
-----
This migration creates the cross-cutting infrastructure tables only. The domain
tables listed in §10 — authentication, exchanges, markets, strategies,
arbitrage, orders, balances, P&L, risk, bots, notifications and SaaS — are
introduced by the phase that needs them, each in its own migration, so that a
revision always maps to one reviewable change.

Portability
-----------
Every column type is dialect-portable: ``Uuid`` renders as native ``UUID`` on
PostgreSQL and ``CHAR(32)`` elsewhere, ``DateTime(timezone=True)`` as
``TIMESTAMP WITH TIME ZONE``, and the JSON variant as ``JSONB`` on PostgreSQL
only. The identical migration therefore applies to production PostgreSQL and to
the SQLite database used by the hermetic test-suite (§142), which is what allows
CI to verify upgrade -> downgrade -> upgrade on every pull request (§141).

Enum columns are written with their member values inlined rather than imported
from the application. A migration must describe the schema as it was at the time
it was written; importing a live enum class would silently change the DDL of an
already-applied migration whenever a member is added.

Append-only audit log
---------------------
On PostgreSQL this migration installs a trigger rejecting ``UPDATE`` and
``DELETE`` against ``audit_logs``, enforcing §53 at the database layer rather
than relying on application discipline. The documented archival procedure
(disable replication triggers, archive, delete) is in ``docs/OPERATIONS.md``.

Revision ID: 0001
Revises:
Create Date: 2026-09-05

"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Portable type factories. A fresh instance per column: SQLAlchemy type objects
# carry per-column state once bound, so sharing one instance is unsafe.
# ---------------------------------------------------------------------------
def _uuid() -> sa.Uuid:
    return sa.Uuid()


def _utc() -> sa.DateTime:
    return sa.DateTime(timezone=True)


def _json() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def _enum(*values: str, name: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, validate_strings=True, length=64)


# Frozen copy of arb_persistence.models.feature_flags.FEATURE_FLAG_DEFAULTS at
# the time this migration was written (§31, §58, §110). Anything that can lose
# money is seeded disabled.
_SEED_FLAGS: tuple[tuple[str, bool, str], ...] = (
    ("paper_trading", True, "Simulated execution using live market data (§30)"),
    (
        "live_trading",
        False,
        "Real order submission; requires explicit per-bot activation (§31)",
    ),
    ("backtesting", False, "Historical simulation of strategies (§37)"),
    (
        "advanced_strategies",
        False,
        "Futures/spot basis and other non-default strategies (§19)",
    ),
    ("dex_trading", False, "On-chain execution via wallet adapters (§20)"),
    (
        "rebalancing",
        False,
        "Cross-exchange inventory rebalancing recommendations (§36)",
    ),
    ("advanced_execution", False, "Hedging and multi-leg recovery automation (§28)"),
)

_AUDIT_IMMUTABILITY_FUNCTION = "audit_logs_prevent_mutation"


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    # --- feature_flags (§58, §110) ---------------------------------------
    op.create_table(
        "feature_flags",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("rollout_percentage", sa.SmallInteger(), nullable=False),
        sa.Column("allowed_plans", _json(), nullable=True),
        sa.Column("allowed_user_ids", _json(), nullable=True),
        sa.Column("updated_by", _uuid(), nullable=True),
        sa.Column("created_at", _utc(), nullable=False),
        sa.Column("updated_at", _utc(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_feature_flags"),
        sa.UniqueConstraint("key", name="uq_feature_flags_key"),
        sa.CheckConstraint(
            "rollout_percentage >= 0 AND rollout_percentage <= 100",
            name="ck_feature_flags_rollout_percentage_within_range",
        ),
    )
    op.create_index(
        "ix_feature_flags_created_at", "feature_flags", ["created_at"], unique=False
    )
    op.create_index(
        "ix_feature_flags_updated_at", "feature_flags", ["updated_at"], unique=False
    )

    _seed_feature_flags()

    # --- audit_logs (§53) --------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("occurred_at", _utc(), nullable=False),
        sa.Column("actor_id", _uuid(), nullable=True),
        sa.Column(
            "actor_type",
            _enum("USER", "ADMIN", "SYSTEM", "WORKER", "ANONYMOUS", name="actor_type"),
            nullable=False,
        ),
        sa.Column("actor_role", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("old_value_safe", _json(), nullable=True),
        sa.Column("new_value_safe", _json(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "result",
            _enum("SUCCESS", "FAILURE", "DENIED", name="audit_result"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
    )
    op.create_index(
        "ix_audit_logs_actor_id_occurred_at",
        "audit_logs",
        ["actor_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_logs_resource_type_resource_id",
        "audit_logs",
        ["resource_type", "resource_id"],
        unique=False,
    )
    op.create_index(
        "ix_audit_logs_action_occurred_at",
        "audit_logs",
        ["action", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_logs_occurred_at", "audit_logs", ["occurred_at"], unique=False
    )

    _install_audit_immutability_trigger()

    # --- worker_heartbeats (§55) -------------------------------------------
    op.create_table(
        "worker_heartbeats",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("identity", sa.String(length=255), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            _enum(
                "STARTING",
                "RUNNING",
                "DEGRADED",
                "STOPPING",
                "STOPPED",
                "FAILED",
                name="worker_status",
            ),
            nullable=False,
        ),
        sa.Column("started_at", _utc(), nullable=True),
        sa.Column("last_heartbeat_at", _utc(), nullable=False),
        sa.Column("jobs_processed", sa.BigInteger(), nullable=False),
        sa.Column("jobs_failed", sa.BigInteger(), nullable=False),
        sa.Column("details", _json(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_worker_heartbeats"),
    )
    op.create_index(
        "ix_worker_heartbeats_role_last_heartbeat_at",
        "worker_heartbeats",
        ["role", "last_heartbeat_at"],
        unique=False,
    )
    op.create_index(
        "ix_worker_heartbeats_last_heartbeat_at",
        "worker_heartbeats",
        ["last_heartbeat_at"],
        unique=False,
    )

    # --- system_health_snapshots (§10, §111) -------------------------------
    op.create_table(
        "system_health_snapshots",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("environment", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            _enum(
                "HEALTHY",
                "DEGRADED",
                "UNAVAILABLE",
                "DISABLED",
                name="health_state",
            ),
            nullable=False,
        ),
        sa.Column("components", _json(), nullable=False),
        sa.Column("observed_at", _utc(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_system_health_snapshots"),
    )
    op.create_index(
        "ix_system_health_snapshots_service_observed_at",
        "system_health_snapshots",
        ["service", "observed_at"],
        unique=False,
    )
    op.create_index(
        "ix_system_health_snapshots_observed_at",
        "system_health_snapshots",
        ["observed_at"],
        unique=False,
    )


def downgrade() -> None:
    _drop_audit_immutability_trigger()

    op.drop_index(
        "ix_system_health_snapshots_observed_at", table_name="system_health_snapshots"
    )
    op.drop_index(
        "ix_system_health_snapshots_service_observed_at",
        table_name="system_health_snapshots",
    )
    op.drop_table("system_health_snapshots")

    op.drop_index(
        "ix_worker_heartbeats_last_heartbeat_at", table_name="worker_heartbeats"
    )
    op.drop_index(
        "ix_worker_heartbeats_role_last_heartbeat_at", table_name="worker_heartbeats"
    )
    op.drop_table("worker_heartbeats")

    op.drop_index("ix_audit_logs_occurred_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action_occurred_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_resource_type_resource_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_actor_id_occurred_at", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_feature_flags_updated_at", table_name="feature_flags")
    op.drop_index("ix_feature_flags_created_at", table_name="feature_flags")
    op.drop_table("feature_flags")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _seed_feature_flags() -> None:
    """Insert the bootstrap flags.

    ``id``, ``created_at`` and ``updated_at`` are supplied explicitly because
    their defaults are Python-side (see arb_core.db.base) and a bulk insert does
    not invoke them. Identifiers use stdlib UUID here so the migration stays
    free of application imports; ordering of seven seed rows is irrelevant.
    """
    now = datetime.now(UTC)
    flags_table = sa.table(
        "feature_flags",
        sa.column("id", sa.Uuid()),
        sa.column("key", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("enabled", sa.Boolean()),
        sa.column("rollout_percentage", sa.SmallInteger()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        flags_table,
        [
            {
                "id": uuid.uuid4(),
                "key": key,
                "description": description,
                "enabled": enabled,
                # Enabled flags roll out to everyone; disabled flags stay at 0%
                # so enabling them later is a deliberate, separate action (§91).
                "rollout_percentage": 100 if enabled else 0,
                "created_at": now,
                "updated_at": now,
            }
            for key, enabled, description in _SEED_FLAGS
        ],
    )


def _install_audit_immutability_trigger() -> None:
    """Reject UPDATE/DELETE on audit_logs (PostgreSQL only).

    SQLite has no equivalent procedural trigger language available portably, so
    in the test-suite the append-only property is enforced by the absence of any
    mutation path in AuditRepository plus the security test-suite. Production
    gets the stronger, database-level guarantee.
    """
    if not _is_postgresql():
        return

    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {_AUDIT_IMMUTABILITY_FUNCTION}()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            RAISE EXCEPTION
                'audit_logs is append-only: % is forbidden (§53). '
                'Use the documented archival procedure in docs/OPERATIONS.md.',
                TG_OP;
            RETURN NULL;
        END;
        $function$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_prevent_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_prevent_mutation();
        """
    )


def _drop_audit_immutability_trigger() -> None:
    """Remove the immutability trigger before dropping the table."""
    if not _is_postgresql():
        return

    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_delete ON audit_logs;")
    op.execute(f"DROP FUNCTION IF EXISTS {_AUDIT_IMMUTABILITY_FUNCTION}();")
