"""Alembic migrations (§9, §141).

Every schema change goes through Alembic — never ``create_all`` — so these tests
drive Alembic's own command API against a throwaway database. The assertions that
matter most are the ones a passing ``create_all`` suite would hide:

* **Schema parity.** The migrated schema must contain exactly the columns the
  models declare. ``create_all`` derives the schema *from* the models, so it can
  never detect a migration that forgot a column; this test can.
* **Round-trip.** ``upgrade → downgrade → upgrade`` must work, because a
  migration that cannot be reversed cannot be rolled back during an incident.
* **Seed safety.** The flags written by the migration must leave every
  money-losing capability disabled (§31, §110).

All tests here are **synchronous**. ``alembic/env.py`` runs migrations through
``asyncio.run()``, which raises ``RuntimeError`` if an event loop is already
running, so an ``async def`` test would fail for a reason unrelated to migrations.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from itertools import pairwise
from typing import TYPE_CHECKING, Any

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from arb_persistence.models import Base
from arb_persistence.models.feature_flags import FEATURE_FLAG_DEFAULTS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Engine, Inspector

# The tables this phase's migration owns. ``alembic_version`` is Alembic's own
# bookkeeping table and is excluded from parity checks.
_PLATFORM_TABLES = frozenset(
    {"feature_flags", "audit_logs", "worker_heartbeats", "system_health_snapshots"}
)

#: Added by revision 0002 (§10, §59-§60).
_AUTH_TABLES = frozenset({"users", "user_sessions", "auth_tokens", "mfa_recovery_codes"})

#: The current head, and the revisions that lead to it newest-first.
#:
#: Asserting an exact value rather than "there is exactly one head" is deliberate:
#: it makes adding a migration a change somebody has to make consciously, in a diff
#: a reviewer reads. What it must not become is a place where a new revision is
#: accommodated by weakening the check, so these two constants are the only thing to
#: update — the assertions around them stay as strict as they are.
HEAD_REVISION = "0003"
REVISION_ORDER = ["0003", "0002", "0001"]


def _url(cfg: Any) -> str:
    url: str = cfg.get_main_option("sqlalchemy.url")
    return url


@contextmanager
def _engine(cfg: Any) -> Iterator[Engine]:
    """A sync engine over the migration database, disposed on exit.

    Disposal matters: an undisposed engine leaks a connection, and the suite runs
    with ``-W error``, so a ResourceWarning at GC time would fail an unrelated
    test.
    """
    engine = create_engine(_url(cfg), future=True)
    try:
        yield engine
    finally:
        engine.dispose()


@contextmanager
def _reflection(cfg: Any) -> Iterator[Inspector]:
    """An inspector that stays usable for the whole ``with`` block.

    ``inspect(connection)`` is bound to that connection, so returning it from a
    closed ``with`` yields an object whose every method raises
    ``ResourceClosedError``. Inspecting the *engine* opens connections lazily and
    stays valid as long as the engine lives.
    """
    with _engine(cfg) as engine:
        yield inspect(engine)


def _table_names(cfg: Any) -> set[str]:
    with _reflection(cfg) as inspector:
        return set(inspector.get_table_names())


def _current_version(cfg: Any) -> str | None:
    """Read ``alembic_version`` directly rather than trusting Alembic's cache."""
    with _engine(cfg) as engine, engine.connect() as connection:
        exists = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        ).fetchone()
        if exists is None:
            return None
        row = connection.execute(text("SELECT version_num FROM alembic_version")).fetchone()
        return str(row[0]) if row else None


def _flag_rows(cfg: Any) -> list[dict[str, Any]]:
    with _engine(cfg) as engine, engine.connect() as connection:
        rows = connection.execute(
            text("SELECT key, enabled, rollout_percentage, description FROM feature_flags")
        ).fetchall()
    return [dict(row._mapping) for row in rows]


class TestUpgrade:
    def test_upgrade_head_creates_every_platform_table(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        assert _table_names(alembic_cfg) >= _PLATFORM_TABLES
        assert _current_version(alembic_cfg) == HEAD_REVISION

    def test_upgrade_is_idempotent(self, alembic_cfg: Any) -> None:
        """Re-running ``upgrade head`` on a migrated database must be a no-op.

        Deployments restart containers and re-run migrations routinely; a second
        application that raises would make every redeploy an incident.
        """
        command.upgrade(alembic_cfg, "head")
        command.upgrade(alembic_cfg, "head")
        assert _current_version(alembic_cfg) == HEAD_REVISION
        assert len(_flag_rows(alembic_cfg)) == len(FEATURE_FLAG_DEFAULTS)

    def test_indexes_are_created(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _reflection(alembic_cfg) as inspector:
            audit_indexes = {index["name"] for index in inspector.get_indexes("audit_logs")}
        # §45/§50/§131: the three dominant admin queries must be indexed.
        assert "ix_audit_logs_actor_id_occurred_at" in audit_indexes
        assert "ix_audit_logs_resource_type_resource_id" in audit_indexes
        assert "ix_audit_logs_action_occurred_at" in audit_indexes
        assert "ix_audit_logs_occurred_at" in audit_indexes

    def test_check_constraint_is_enforced(self, alembic_cfg: Any) -> None:
        """A rollout percentage above 100 must be impossible to store."""
        command.upgrade(alembic_cfg, "head")
        now = datetime.now(UTC)
        with (
            _engine(alembic_cfg) as engine,
            engine.begin() as connection,
            pytest.raises(IntegrityError),
        ):
            connection.execute(
                text(
                    "INSERT INTO feature_flags (id, key, description, enabled, "
                    "rollout_percentage, created_at, updated_at) "
                    "VALUES (:id, :key, '', 1, 250, :now, :now)"
                ),
                {"id": str(uuid.uuid4()).replace("-", ""), "key": "bad", "now": now},
            )

    def test_unique_key_constraint_is_enforced(self, alembic_cfg: Any) -> None:
        """Two rows for one flag would make evaluation order-dependent."""
        command.upgrade(alembic_cfg, "head")
        now = datetime.now(UTC)
        with (
            _engine(alembic_cfg) as engine,
            engine.begin() as connection,
            pytest.raises(IntegrityError),
        ):
            connection.execute(
                text(
                    "INSERT INTO feature_flags (id, key, description, enabled, "
                    "rollout_percentage, created_at, updated_at) "
                    "VALUES (:id, 'live_trading', '', 0, 0, :now, :now)"
                ),
                {"id": str(uuid.uuid4()).replace("-", ""), "now": now},
            )


class TestSeedData:
    def test_every_declared_flag_is_seeded(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        rows = _flag_rows(alembic_cfg)
        assert {row["key"] for row in rows} == set(FEATURE_FLAG_DEFAULTS)

    def test_nothing_that_can_lose_money_is_seeded_enabled(self, alembic_cfg: Any) -> None:
        """§31, §110 — verified against what the migration actually writes.

        The migration carries a frozen copy of the defaults (correct, since a
        migration must not import live application state), so this test is what
        stops that copy from drifting into something unsafe.
        """
        command.upgrade(alembic_cfg, "head")
        rows = {row["key"]: row for row in _flag_rows(alembic_cfg)}
        for key in (
            "live_trading",
            "dex_trading",
            "rebalancing",
            "advanced_execution",
            "advanced_strategies",
            "backtesting",
        ):
            assert rows[key]["enabled"] in (False, 0), f"{key} must be seeded disabled"

    def test_paper_trading_is_the_only_enabled_seed(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        enabled = {row["key"] for row in _flag_rows(alembic_cfg) if row["enabled"]}
        assert enabled == {"paper_trading"}

    def test_rollout_matches_the_enabled_state(self, alembic_cfg: Any) -> None:
        """Enabled rolls out to everyone; disabled stays at 0% (§91).

        A disabled flag at 100% would become live for every user the moment an
        administrator flips ``enabled`` without reviewing the rollout — so the
        two must be set together, deliberately.
        """
        command.upgrade(alembic_cfg, "head")
        for row in _flag_rows(alembic_cfg):
            expected = 100 if row["enabled"] else 0
            assert row["rollout_percentage"] == expected, row["key"]

    def test_seeded_defaults_match_the_live_constants(self, alembic_cfg: Any) -> None:
        """Detect drift between the frozen migration copy and the model."""
        command.upgrade(alembic_cfg, "head")
        rows = {row["key"]: row for row in _flag_rows(alembic_cfg)}
        for key, (enabled, description) in FEATURE_FLAG_DEFAULTS.items():
            assert bool(rows[key]["enabled"]) is enabled, key
            assert rows[key]["description"] == description, key


class TestDowngrade:
    def test_downgrade_base_removes_every_table(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        command.downgrade(alembic_cfg, "base")
        remaining = _table_names(alembic_cfg)
        assert not (_PLATFORM_TABLES & remaining)
        assert not (_AUTH_TABLES & remaining)
        assert _current_version(alembic_cfg) is None

    def test_full_round_trip(self, alembic_cfg: Any) -> None:
        """§141 — CI verifies upgrade → downgrade → upgrade on every PR."""
        command.upgrade(alembic_cfg, "head")
        command.downgrade(alembic_cfg, "base")
        command.upgrade(alembic_cfg, "head")

        assert _current_version(alembic_cfg) == HEAD_REVISION
        assert _table_names(alembic_cfg) >= set(_PLATFORM_TABLES | _AUTH_TABLES)
        assert {row["key"] for row in _flag_rows(alembic_cfg)} == set(FEATURE_FLAG_DEFAULTS)

    def test_downgrade_without_upgrade_is_a_no_op(self, alembic_cfg: Any) -> None:
        command.downgrade(alembic_cfg, "base")
        assert _current_version(alembic_cfg) is None


class TestSchemaParity:
    def test_models_and_migration_declare_the_same_tables(self, alembic_cfg: Any) -> None:
        """The strongest check here: ``create_all`` can never detect this drift."""
        command.upgrade(alembic_cfg, "head")
        migrated = _table_names(alembic_cfg) - {"alembic_version"}
        assert migrated == set(Base.metadata.tables)

    def test_every_model_column_exists_in_the_migrated_schema(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _reflection(alembic_cfg) as inspector:
            for table_name, table in Base.metadata.tables.items():
                migrated_columns = {column["name"] for column in inspector.get_columns(table_name)}
                model_columns = {column.name for column in table.columns}
                assert migrated_columns == model_columns, (
                    f"{table_name}: missing={model_columns - migrated_columns} "
                    f"unexpected={migrated_columns - model_columns}"
                )

    def test_nullability_matches(self, alembic_cfg: Any) -> None:
        """A column nullable in the database but not in the model is a bug that
        only surfaces when real data arrives."""
        command.upgrade(alembic_cfg, "head")
        with _reflection(alembic_cfg) as inspector:
            for table_name, table in Base.metadata.tables.items():
                migrated = {
                    c["name"]: bool(c["nullable"]) for c in inspector.get_columns(table_name)
                }
                for column in table.columns:
                    assert migrated[column.name] == bool(column.nullable), (
                        f"{table_name}.{column.name}: model nullable={column.nullable} "
                        f"database nullable={migrated[column.name]}"
                    )

    def test_primary_keys_match(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _reflection(alembic_cfg) as inspector:
            for table_name, table in Base.metadata.tables.items():
                assert set(inspector.get_pk_constraint(table_name)["constrained_columns"]) == {
                    column.name for column in table.primary_key.columns
                }, table_name


class TestRevisionGraph:
    def test_there_is_exactly_one_head(self, alembic_cfg: Any) -> None:
        """Branching heads make ``upgrade head`` ambiguous and deployments fail."""
        script = ScriptDirectory.from_config(alembic_cfg)
        heads = script.get_heads()
        assert len(heads) == 1
        assert heads[0] == HEAD_REVISION

    def test_history_is_linear_from_base(self, alembic_cfg: Any) -> None:
        script = ScriptDirectory.from_config(alembic_cfg)
        revisions = list(script.walk_revisions())
        # walk_revisions() yields newest first.
        assert [revision.revision for revision in revisions] == REVISION_ORDER
        assert revisions[-1].down_revision is None
        # Contiguity: every revision names the one immediately before it as its
        # parent. Checking the whole chain rather than one hard-coded parent means a
        # branch or a skipped revision number fails here, and adding a migration does
        # not require anybody to remember to edit this assertion.
        for child, parent in pairwise(revisions):
            assert child.down_revision == parent.revision

    def test_every_revision_has_a_downgrade(self, alembic_cfg: Any) -> None:
        """An irreversible migration cannot be rolled back during an incident."""
        script = ScriptDirectory.from_config(alembic_cfg)
        for revision in script.walk_revisions():
            module = revision.module
            assert callable(getattr(module, "downgrade", None)), revision.revision


class TestOfflineSql:
    def test_offline_mode_emits_ddl_without_connecting(
        self, alembic_cfg: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``--sql`` mode lets an operator review DDL before a deploy (§141)."""
        command.upgrade(alembic_cfg, "head", sql=True)
        emitted = capsys.readouterr().out
        assert "CREATE TABLE feature_flags" in emitted
        assert "CREATE TABLE audit_logs" in emitted
        # No database was touched.
        assert _current_version(alembic_cfg) is None

    def test_offline_sql_does_not_leak_credentials(
        self, alembic_cfg: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        alembic_cfg.set_main_option(
            "sqlalchemy.url", "postgresql+psycopg://arb:Sup3rSecret@db:5432/arb"
        )
        command.upgrade(alembic_cfg, "head", sql=True)
        emitted = capsys.readouterr().out
        assert "Sup3rSecret" not in emitted

    def test_offline_sql_is_dialect_correct_for_postgres(
        self, alembic_cfg: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The PostgreSQL-only audit immutability trigger must appear in PG DDL."""
        alembic_cfg.set_main_option("sqlalchemy.url", "postgresql+psycopg://arb@db:5432/arb")
        command.upgrade(alembic_cfg, "head", sql=True)
        emitted = capsys.readouterr().out
        assert "audit_logs_prevent_mutation" in emitted
        assert re.search(r"CREATE\s+(OR REPLACE\s+)?FUNCTION", emitted, re.IGNORECASE)

    def test_sqlite_ddl_omits_the_postgres_trigger(
        self, alembic_cfg: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The migration is dialect-aware, not merely dialect-tolerant."""
        command.upgrade(alembic_cfg, "head", sql=True)
        emitted = capsys.readouterr().out
        assert "audit_logs_prevent_mutation" not in emitted


@pytest.mark.postgres
class TestAuditImmutabilityOnPostgres:
    """§53 enforced by the database rather than by application discipline.

    The SQLite migration cannot install this trigger — SQLite has no procedural
    trigger language portable enough to express it — so the guarantee is only
    verifiable against a real server. CI provides one (§142).

    Cleanup is by ``downgrade base``, which drops the tables outright. Row-level
    triggers do not fire on ``DROP TABLE``, so this is not blocked by the very
    protection being tested. Deliberately leaving the row behind would be
    acceptable in an audit log, but dropping it keeps repeated CI runs clean.
    """

    @staticmethod
    def _psycopg_url() -> str:
        return os.environ["TEST_POSTGRES_URL"].replace(
            "postgresql+asyncpg://", "postgresql+psycopg://", 1
        )

    def test_update_and_delete_are_rejected(self, alembic_cfg: Any) -> None:
        import uuid
        from datetime import UTC, datetime

        url = self._psycopg_url()
        alembic_cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(alembic_cfg, "head")

        row_id = uuid.uuid4()
        marker_action = f"TEST_IMMUTABILITY_{uuid.uuid4().hex[:8]}"
        engine = create_engine(url, future=True)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO audit_logs (id, occurred_at, actor_type, action, "
                        "resource_type, result) "
                        "VALUES (:id, :now, 'SYSTEM', :action, 'feature_flag', 'SUCCESS')"
                    ),
                    {"id": row_id, "now": datetime.now(UTC), "action": marker_action},
                )

            with engine.begin() as connection, pytest.raises(Exception, match="append-only"):
                connection.execute(
                    text("UPDATE audit_logs SET action = 'TAMPERED' WHERE id = :id"),
                    {"id": row_id},
                )

            with engine.begin() as connection, pytest.raises(Exception, match="append-only"):
                connection.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": row_id})

            with engine.connect() as connection:
                action = connection.execute(
                    text("SELECT action FROM audit_logs WHERE id = :id"), {"id": row_id}
                ).scalar_one()
            assert action == marker_action, "the tampering attempt must not have landed"
        finally:
            engine.dispose()
            command.downgrade(alembic_cfg, "base")


# ---------------------------------------------------------------------------
# Revision 0002: authentication (§10, §59-§60)
#
# Schema parity above proves the columns exist and are nullable as declared. It
# cannot prove a constraint actually rejects anything, and for these tables the
# constraints *are* the security property: a unique index that does not hold lets
# two accounts share one password-reset flow, and a CHECK that does not hold lets a
# mixed-case email defeat that index.
# ---------------------------------------------------------------------------
def _hex_id() -> str:
    return str(uuid.uuid4()).replace("-", "")


def _insert_user(
    connection: Any,
    *,
    email: str = "user@example.com",
    role: str = "TRADER",
    status: str = "ACTIVE",
    failed_login_count: int = 0,
) -> str:
    """Insert the minimum a ``users`` row needs. Raw SQL bypasses ORM defaults, so
    every NOT NULL column is supplied explicitly."""
    user_id = _hex_id()
    now = datetime.now(UTC)
    connection.execute(
        text(
            "INSERT INTO users (id, email, password_hash, role, status, "
            "failed_login_count, mfa_enabled, must_change_password, created_at, updated_at) "
            "VALUES (:id, :email, '$argon2id$stub', :role, :status, "
            ":failures, 0, 0, :now, :now)"
        ),
        {
            "id": user_id,
            "email": email,
            "role": role,
            "status": status,
            "failures": failed_login_count,
            "now": now,
        },
    )
    return user_id


def _insert_session(
    connection: Any, user_id: str, *, token: str = "a" * 64, parent_session_id: str | None = None
) -> str:
    session_id = _hex_id()
    now = datetime.now(UTC)
    connection.execute(
        text(
            "INSERT INTO user_sessions (id, user_id, family_id, parent_session_id, "
            "refresh_token_hash, status, expires_at, last_seen_at, created_at, updated_at) "
            "VALUES (:id, :user_id, :family_id, :parent, :token, 'ACTIVE', "
            ":expires, :now, :now, :now)"
        ),
        {
            "id": session_id,
            "user_id": user_id,
            "family_id": _hex_id(),
            "parent": parent_session_id,
            "token": token,
            "expires": now,
            "now": now,
        },
    )
    return session_id


class TestAuthenticationUpgrade:
    def test_the_auth_tables_are_created(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        assert _table_names(alembic_cfg) >= _AUTH_TABLES

    def test_downgrade_to_0001_removes_only_the_auth_tables(self, alembic_cfg: Any) -> None:
        """§141 — a phase must be reversible without taking the platform with it."""
        command.upgrade(alembic_cfg, "head")
        command.downgrade(alembic_cfg, "0001")
        remaining = _table_names(alembic_cfg)
        assert not (_AUTH_TABLES & remaining)
        assert remaining >= _PLATFORM_TABLES
        assert _current_version(alembic_cfg) == "0001"
        # And it re-applies cleanly.
        command.upgrade(alembic_cfg, "head")
        assert _table_names(alembic_cfg) >= _AUTH_TABLES

    def test_the_indexes_the_auth_queries_depend_on_exist(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _reflection(alembic_cfg) as inspector:
            sessions = {index["name"] for index in inspector.get_indexes("user_sessions")}
            tokens = {index["name"] for index in inspector.get_indexes("auth_tokens")}
            users = {index["name"] for index in inspector.get_indexes("users")}
        # "this user's signed-in devices" and "revoke the whole token family" (§60, §68).
        assert "ix_user_sessions_user_id_status" in sessions
        assert "ix_user_sessions_family_id" in sessions
        # Retention sweeps for expired sessions and tokens.
        assert "ix_user_sessions_expires_at" in sessions
        assert "ix_auth_tokens_expires_at" in tokens
        # "invalidate outstanding reset tokens before issuing a new one" (§59).
        assert "ix_auth_tokens_user_id_purpose" in tokens
        # Administrator account listing filters by status (§45).
        assert "ix_users_status_created_at" in users


class TestAuthenticationConstraints:
    def test_a_mixed_case_email_cannot_be_stored(self, alembic_cfg: Any) -> None:
        """Without this, ``John@x.com`` and ``john@x.com`` are two accounts sharing
        one password-reset flow — and the unique index cannot see it."""
        command.upgrade(alembic_cfg, "head")
        with (
            _engine(alembic_cfg) as engine,
            engine.begin() as connection,
            pytest.raises(IntegrityError),
        ):
            _insert_user(connection, email="MixedCase@Example.com")

    def test_a_lowercase_email_is_accepted(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            user_id = _insert_user(connection, email="mixedcase@example.com")
        assert user_id

    def test_two_accounts_cannot_share_an_email(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            _insert_user(connection, email="dupe@example.com")
            with pytest.raises(IntegrityError):
                _insert_user(connection, email="dupe@example.com")

    def test_a_negative_failure_count_cannot_be_stored(self, alembic_cfg: Any) -> None:
        """The counter drives lockout; a negative value would make the threshold
        comparison meaningless."""
        command.upgrade(alembic_cfg, "head")
        with (
            _engine(alembic_cfg) as engine,
            engine.begin() as connection,
            pytest.raises(IntegrityError),
        ):
            _insert_user(connection, failed_login_count=-1)

    def test_two_sessions_cannot_share_a_refresh_token_digest(self, alembic_cfg: Any) -> None:
        """The digest is how a presented token finds its session. Two rows with one
        digest would make that lookup ambiguous — which session gets revoked?"""
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            user_id = _insert_user(connection)
            _insert_session(connection, user_id, token="b" * 64)
            with pytest.raises(IntegrityError):
                _insert_session(connection, user_id, token="b" * 64)

    def test_a_session_cannot_be_its_own_parent(self, alembic_cfg: Any) -> None:
        """Rotation lineage is walked to revoke a family; a self-parent makes that
        walk a cycle."""
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            user_id = _insert_user(connection)
            session_id = _hex_id()
            now = datetime.now(UTC)
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO user_sessions (id, user_id, family_id, "
                        "parent_session_id, refresh_token_hash, status, expires_at, "
                        "last_seen_at, created_at, updated_at) VALUES (:id, :user_id, "
                        ":family_id, :id, :token, 'ACTIVE', :now, :now, :now, :now)"
                    ),
                    {
                        "id": session_id,
                        "user_id": user_id,
                        "family_id": _hex_id(),
                        "token": "c" * 64,
                        "now": now,
                    },
                )

    def test_a_recovery_code_is_unique_within_an_account(self, alembic_cfg: Any) -> None:
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            user_id = _insert_user(connection)
            now = datetime.now(UTC)
            statement = text(
                "INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) "
                "VALUES (:id, :user_id, :code_hash, :now)"
            )
            params = {"id": _hex_id(), "user_id": user_id, "code_hash": "d" * 64, "now": now}
            connection.execute(statement, params)
            with pytest.raises(IntegrityError):
                connection.execute(statement, {**params, "id": _hex_id()})

    def test_deleting_a_user_removes_their_sessions_and_tokens(self, alembic_cfg: Any) -> None:
        """ON DELETE CASCADE: an erased account must not leave live credentials
        behind. SQLite enforces foreign keys only when the pragma is set, so it is
        enabled for this connection; PostgreSQL enforces them always."""
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys = ON"))
            user_id = _insert_user(connection)
            _insert_session(connection, user_id, token="e" * 64)
            now = datetime.now(UTC)
            connection.execute(
                text(
                    "INSERT INTO auth_tokens (id, user_id, purpose, token_hash, "
                    "expires_at, created_at) VALUES (:id, :user_id, 'PASSWORD_RESET', "
                    ":token_hash, :now, :now)"
                ),
                {"id": _hex_id(), "user_id": user_id, "token_hash": "f" * 64, "now": now},
            )
            connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
            remaining_sessions = connection.execute(
                text("SELECT COUNT(*) FROM user_sessions WHERE user_id = :id"), {"id": user_id}
            ).scalar_one()
            remaining_tokens = connection.execute(
                text("SELECT COUNT(*) FROM auth_tokens WHERE user_id = :id"), {"id": user_id}
            ).scalar_one()
        assert remaining_sessions == 0
        assert remaining_tokens == 0

    def test_an_orphan_session_cannot_be_created(self, alembic_cfg: Any) -> None:
        """A session with no user would be an unowned credential."""
        command.upgrade(alembic_cfg, "head")
        with (
            _engine(alembic_cfg) as engine,
            engine.begin() as connection,
            pytest.raises(IntegrityError),
        ):
            connection.execute(text("PRAGMA foreign_keys = ON"))
            _insert_session(connection, _hex_id(), token="0" * 64)


# ---------------------------------------------------------------------------
# Revision 0003: the TOTP replay guard (§59)
#
# RFC 6238 §5.2 forbids accepting a time-based code a second time. Enforcing that
# needs the step of the most recently accepted code, stored where it survives a
# cache flush and a restart — hence a column on ``users`` rather than a Redis key,
# and hence a test that the column is really there and really nullable.
# ---------------------------------------------------------------------------
def _user_columns(cfg: Any) -> set[str]:
    with _reflection(cfg) as inspector:
        return {str(column["name"]) for column in inspector.get_columns("users")}


class TestTotpReplayGuard:
    def test_the_column_arrives_with_this_revision_and_leaves_with_it(
        self, alembic_cfg: Any
    ) -> None:
        """0003 owns exactly one column, in both directions."""
        command.upgrade(alembic_cfg, "0002")
        assert "totp_last_used_step" not in _user_columns(alembic_cfg)

        command.upgrade(alembic_cfg, "head")
        assert "totp_last_used_step" in _user_columns(alembic_cfg)

        command.downgrade(alembic_cfg, "0002")
        assert "totp_last_used_step" not in _user_columns(alembic_cfg)

    def test_a_fresh_account_has_accepted_no_step(self, alembic_cfg: Any) -> None:
        """NULL means "no code has been accepted yet".

        That is why the column can be added to a table with rows in it and needs no
        backfill: the absence of a recorded step is a true statement about a new
        account, not a missing value.
        """
        command.upgrade(alembic_cfg, "head")
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            user_id = _insert_user(connection)
            stored = connection.execute(
                text("SELECT totp_last_used_step FROM users WHERE id = :id"), {"id": user_id}
            ).scalar_one()
        assert stored is None

    def test_an_accepted_step_survives_a_round_trip(self, alembic_cfg: Any) -> None:
        """The column is wide enough for a step counter, now and later.

        A step is ``unix_seconds // period``: about 59 million today at the default
        30-second period, and past the range of a 32-bit signed integer for any
        period of a second or less. Value chosen well past both.
        """
        command.upgrade(alembic_cfg, "head")
        step = 2**40
        with _engine(alembic_cfg) as engine, engine.begin() as connection:
            user_id = _insert_user(connection)
            connection.execute(
                text("UPDATE users SET totp_last_used_step = :step WHERE id = :id"),
                {"id": user_id, "step": step},
            )
            stored = connection.execute(
                text("SELECT totp_last_used_step FROM users WHERE id = :id"), {"id": user_id}
            ).scalar_one()
        assert stored == step


@pytest.mark.postgres
class TestTotpReplayGuardOnPostgres:
    """The non-negativity CHECK, verified where a constraint can actually be added.

    SQLite has no ``ALTER TABLE ... ADD CONSTRAINT``, so revision 0003 installs the
    CHECK only on PostgreSQL — the sole supported production database (§10) — and
    this is the test that proves it landed. CI provides a real server (§142).
    """

    def test_a_negative_step_is_rejected(self, alembic_cfg: Any) -> None:
        url = os.environ["TEST_POSTGRES_URL"].replace(
            "postgresql+asyncpg://", "postgresql+psycopg://", 1
        )
        alembic_cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(alembic_cfg, "head")

        engine = create_engine(url)
        try:
            with engine.begin() as connection:
                user_id = _insert_user(connection)
            with engine.begin() as connection, pytest.raises(IntegrityError):
                connection.execute(
                    text("UPDATE users SET totp_last_used_step = -1 WHERE id = :id"),
                    {"id": user_id},
                )
        finally:
            engine.dispose()
            command.downgrade(alembic_cfg, "base")
