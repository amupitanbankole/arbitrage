"""Append-only audit log (§53, §83, §130, §131, §133).

Three properties carry the weight here:

* **Redaction happens unconditionally at the write boundary.** ``old_value`` /
  ``new_value`` / ``reason`` pass through :mod:`arb_core.security.redaction`
  inside ``AuditService.record``; a caller cannot opt out. An audit table is the
  one place a secret is guaranteed to be copied, read by administrators, and
  retained for years — so a leak here is worse than a leak in a log line.
* **Append-only is structural, not conventional.** There is no ``updated_at``,
  no soft-delete column, and no mutation method on the repository. On PostgreSQL
  a trigger enforces it at the database layer (covered in ``test_migrations``).
* **Denied actions are recorded too.** A burst of denials is the signature of
  privilege probing (§130), which only works if failures are audited.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest
from sqlalchemy import select

from arb_api.services.audit_service import AuditActor, AuditService
from arb_core.clock import utc_now
from arb_core.context import context_scope
from arb_core.pagination import PaginationParams
from arb_core.security.redaction import REDACTED
from arb_persistence.models.audit import AuditLog
from arb_persistence.models.enums import ActorType, AuditResult
from arb_persistence.repositories.audit import AuditRepository

if TYPE_CHECKING:
    from sqlalchemy import Table

    from arb_core.db.session import Database

#: Keys whose *entire* value must become ``[REDACTED]``, because the key name
#: itself marks the value as a credential.
SENSITIVE_FIELDS = {
    "password": "Sup3rSecretPassword",
    "api_secret": "exchange-api-secret-value-0123456789",
    "api_key": "AKIAIOSFODNN7EXAMPLE",
    "token": "bearer-token-value-abcdef",
    "encryption_key": "Zm9vYmFyYmF6cXV1eC1lbmNyeXB0aW9uLWtleQ==",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----",
}

#: A DSN is not a credential by key name, so its value is *masked* rather than
#: replaced: the password goes, the host and database stay. That is deliberate —
#: "which database?" is a question an operator genuinely needs answered, and the
#: part that must not survive is the password.
DATABASE_URL_KEY = "database_url"
DATABASE_URL_PASSWORD = "Sup3rSecret"
DATABASE_URL_VALUE = f"postgresql+asyncpg://arb:{DATABASE_URL_PASSWORD}@db:5432/arb"

#: Every secret that must not appear anywhere in a stored audit row.
SECRETS = {**SENSITIVE_FIELDS, DATABASE_URL_KEY: DATABASE_URL_VALUE}


async def _all_rows(database: Database) -> list[AuditLog]:
    async with database.session() as session:
        result = await session.execute(select(AuditLog).order_by(AuditLog.occurred_at))
        return list(result.scalars().all())


class TestRecord:
    async def test_writes_a_complete_entry(self, database: Database) -> None:
        actor_id = uuid.uuid4()
        async with database.unit_of_work() as session:
            entry = await AuditService(session).record(
                action="ADMIN_TRIGGERED_GLOBAL_KILL_SWITCH",
                resource_type="platform",
                resource_id="global",
                actor=AuditActor(
                    actor_type=ActorType.USER,
                    actor_id=actor_id,
                    role="admin",
                    ip_address="203.0.113.7",
                    user_agent="pytest",
                ),
                old_value={"global_kill_switch_enabled": False},
                new_value={"global_kill_switch_enabled": True},
                reason="runaway bot",
                request_id="req-123",
            )
            entry_id = entry.id

        rows = await _all_rows(database)
        assert len(rows) == 1
        stored = rows[0]
        assert stored.id == entry_id
        assert stored.action == "ADMIN_TRIGGERED_GLOBAL_KILL_SWITCH"
        assert stored.resource_type == "platform"
        assert stored.resource_id == "global"
        assert stored.actor_id == actor_id
        assert stored.actor_type is ActorType.USER
        assert stored.actor_role == "admin"
        assert stored.ip_address == "203.0.113.7"
        assert stored.result is AuditResult.SUCCESS
        assert stored.request_id == "req-123"
        assert stored.new_value_safe == {"global_kill_switch_enabled": True}

    async def test_flushes_but_does_not_commit(self, database: Database) -> None:
        """§63 — the caller owns the transaction boundary.

        An audit entry written by a service that then fails must roll back with
        the action it describes; recording a change that never happened is worse
        than recording nothing.
        """
        async with database.session() as session:
            entry = await AuditService(session).record(action="UNCOMMITTED", resource_type="test")
            assert entry.id is not None  # flushed: the identifier is populated
            await session.rollback()

        assert await _all_rows(database) == []

    async def test_defaults_to_a_system_actor(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await AuditService(session).record(action="WORKER_STARTED", resource_type="worker")

        stored = (await _all_rows(database))[0]
        assert stored.actor_type is ActorType.SYSTEM
        assert stored.actor_id is None
        assert stored.actor_role == "system"

    async def test_actor_factory_for_system_actions(self) -> None:
        actor = AuditActor.system(role="scheduler")
        assert actor.actor_type is ActorType.SYSTEM
        assert actor.actor_id is None
        assert actor.role == "scheduler"

    @pytest.mark.parametrize("action", ["", "   ", "\t\n"])
    async def test_blank_action_is_rejected(self, database: Database, action: str) -> None:
        """Actions are matched exactly in the admin UI; a blank one is unfindable."""
        with pytest.raises(ValueError, match="non-empty stable verb"):
            async with database.unit_of_work() as session:
                await AuditService(session).record(action=action, resource_type="test")

    @pytest.mark.parametrize("resource_type", ["", "   "])
    async def test_blank_resource_type_is_rejected(
        self, database: Database, resource_type: str
    ) -> None:
        with pytest.raises(ValueError, match="resource_type must be non-empty"):
            async with database.unit_of_work() as session:
                await AuditService(session).record(action="X", resource_type=resource_type)

    async def test_action_and_resource_type_are_trimmed(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="  ADMIN_CHANGED_FLAG  ", resource_type="  feature_flag  "
            )
        stored = (await _all_rows(database))[0]
        assert stored.action == "ADMIN_CHANGED_FLAG"
        assert stored.resource_type == "feature_flag"

    async def test_resource_id_is_stringified(self, database: Database) -> None:
        """Callers pass UUIDs and ints; the column is text and must stay queryable."""
        identifier = uuid.uuid4()
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="A", resource_type="bot", resource_id=identifier
            )
            await AuditService(session).record(action="B", resource_type="bot", resource_id=7)
        rows = await _all_rows(database)
        assert rows[0].resource_id == str(identifier)
        assert rows[1].resource_id == "7"

    async def test_occurred_at_is_aware_utc(self, database: Database) -> None:
        """§75 — audit timelines are compared against ``utc_now()``."""
        before = utc_now()
        async with database.unit_of_work() as session:
            await AuditService(session).record(action="A", resource_type="test")
        stored = (await _all_rows(database))[0]
        assert stored.occurred_at.tzinfo is not None
        assert before <= stored.occurred_at <= utc_now() + timedelta(seconds=1)

    async def test_request_id_falls_back_to_the_ambient_context(self, database: Database) -> None:
        """§66 — an audit entry must correlate with the logs of its request."""
        with context_scope(request_id="ambient-request-id"):
            async with database.unit_of_work() as session:
                await AuditService(session).record(action="A", resource_type="test")
        assert (await _all_rows(database))[0].request_id == "ambient-request-id"

    async def test_explicit_request_id_wins_over_the_context(self, database: Database) -> None:
        with context_scope(request_id="ambient"):
            async with database.unit_of_work() as session:
                await AuditService(session).record(
                    action="A", resource_type="test", request_id="explicit"
                )
        assert (await _all_rows(database))[0].request_id == "explicit"

    async def test_denied_actions_are_recorded(self, database: Database) -> None:
        """§130 — a burst of denials is the signature of privilege probing."""
        async with database.unit_of_work() as session:
            entry = await AuditService(session).record_denied(
                action="ADMIN_ATTEMPTED_ROLE_CHANGE",
                resource_type="user",
                resource_id="u-1",
                actor=AuditActor(actor_type=ActorType.USER, actor_id=uuid.uuid4(), role="viewer"),
                reason="insufficient permission",
            )
        assert entry.result is AuditResult.DENIED
        assert (await _all_rows(database))[0].result is AuditResult.DENIED


class TestRedaction:
    async def test_value_payloads_are_redacted(self, database: Database) -> None:
        """The single most important assertion in this module (§133)."""
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="ADMIN_STORED_EXCHANGE_CREDENTIALS",
                resource_type="exchange_credential",
                old_value=dict(SECRETS),
                new_value=dict(SECRETS),
            )

        stored = (await _all_rows(database))[0]
        for payload in (stored.old_value_safe, stored.new_value_safe):
            assert payload is not None
            serialised = str(payload)
            # No secret survives, under any key.
            for name, secret in SECRETS.items():
                assert secret not in serialised, f"{name} survived into the audit log"
            # Credential-named keys are replaced wholesale.
            for name in SENSITIVE_FIELDS:
                assert payload[name] == REDACTED, name
            # A DSN keeps its shape but loses its password.
            assert DATABASE_URL_PASSWORD not in payload[DATABASE_URL_KEY]
            assert REDACTED in payload[DATABASE_URL_KEY]
            assert "db:5432/arb" in payload[DATABASE_URL_KEY]

    async def test_redaction_is_not_optional(self, database: Database) -> None:
        """There is no parameter that turns it off, by design."""
        signature = inspect.signature(AuditService.record)
        assert not any(
            "redact" in name.lower() or "safe" in name.lower() for name in signature.parameters
        )

    async def test_reason_is_redacted(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="A",
                resource_type="test",
                reason="rotating because api_secret=exchange-api-secret-value-0123456789",
            )
        stored = (await _all_rows(database))[0]
        assert stored.reason is not None
        assert "exchange-api-secret-value-0123456789" not in stored.reason

    async def test_nested_payloads_are_redacted(self, database: Database) -> None:
        """Credentials arrive nested inside exchange configuration objects."""
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="ADMIN_UPDATED_EXCHANGE",
                resource_type="exchange",
                new_value={
                    "exchange": "binance",
                    "credentials": {
                        "api_key": "AKIAIOSFODNN7EXAMPLE",
                        "api_secret": "exchange-api-secret-value-0123456789",
                    },
                    "list": [{"password": "Sup3rSecretPassword"}],
                },
            )
        serialised = str((await _all_rows(database))[0].new_value_safe)
        for secret in SECRETS.values():
            assert secret not in serialised

    async def test_non_sensitive_fields_survive(self, database: Database) -> None:
        """Redaction that destroyed everything would make the audit log useless."""
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="ADMIN_CHANGED_FLAG",
                resource_type="feature_flag",
                resource_id="live_trading",
                old_value={"enabled": False, "rollout_percentage": 0},
                new_value={"enabled": True, "rollout_percentage": 100},
            )
        stored = (await _all_rows(database))[0]
        assert stored.old_value_safe == {"enabled": False, "rollout_percentage": 0}
        assert stored.new_value_safe == {"enabled": True, "rollout_percentage": 100}

    async def test_none_payloads_stay_none(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await AuditService(session).record(action="A", resource_type="test")
        stored = (await _all_rows(database))[0]
        assert stored.old_value_safe is None
        assert stored.new_value_safe is None

    async def test_long_user_agent_is_truncated_not_rejected(self, database: Database) -> None:
        """A bookkeeping failure must not lose the audit entry itself."""
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="A",
                resource_type="test",
                actor=AuditActor(actor_type=ActorType.USER, user_agent="x" * 4096),
            )
        stored = (await _all_rows(database))[0]
        assert stored.user_agent is not None
        assert len(stored.user_agent) <= 512

    async def test_repr_carries_no_payload(self, database: Database) -> None:
        """A repr that reaches a log line must not be able to carry secrets."""
        async with database.unit_of_work() as session:
            entry = await AuditService(session).record(
                action="ADMIN_STORED_EXCHANGE_CREDENTIALS",
                resource_type="exchange_credential",
                new_value=dict(SECRETS),
            )
        rendered = repr(entry)
        assert "ADMIN_STORED_EXCHANGE_CREDENTIALS" in rendered
        for secret in SECRETS.values():
            assert secret not in rendered


class TestAppendOnly:
    async def test_no_update_or_soft_delete_columns(self) -> None:
        """§83 — there is structurally nothing to update."""
        columns = set(AuditLog.__table__.c.keys())
        assert "updated_at" not in columns
        assert "deleted_at" not in columns

    def test_repository_exposes_no_mutation_methods(self) -> None:
        """The guarantee must not depend on callers behaving."""
        forbidden = {"delete", "delete_by_id", "update", "remove", "set_state", "soft_delete"}
        present = {
            name for name, _ in inspect.getmembers(AuditRepository, predicate=inspect.isfunction)
        }
        assert not (forbidden & present), sorted(forbidden & present)

    def test_repository_offers_only_add_and_read(self) -> None:
        public = {
            name
            for name, member in inspect.getmembers(AuditRepository)
            if not name.startswith("_") and callable(member)
        }
        assert public <= {
            "add",
            "add_all",
            "flush",
            "get_by_id",
            "count",
            "paginate",
            "latest_for_resource",
            "search",
            "count_denied_since",
        }, sorted(public)


class TestQueries:
    async def _seed_history(self, database: Database) -> None:
        admin = uuid.UUID("01890b1e-0000-7000-8000-0000000000aa")
        viewer = uuid.UUID("01890b1e-0000-7000-8000-0000000000bb")
        async with database.unit_of_work() as session:
            service = AuditService(session)
            for _ in range(5):
                await service.record(
                    action="BOT_STARTED",
                    resource_type="bot",
                    resource_id="bot-1",
                    actor=AuditActor(actor_type=ActorType.USER, actor_id=admin, role="admin"),
                )
            await service.record(
                action="ADMIN_CHANGED_FLAG",
                resource_type="feature_flag",
                resource_id="live_trading",
                actor=AuditActor(actor_type=ActorType.USER, actor_id=admin, role="admin"),
            )
            await service.record_denied(
                action="ADMIN_ATTEMPTED_ROLE_CHANGE",
                resource_type="user",
                resource_id="u-1",
                actor=AuditActor(actor_type=ActorType.USER, actor_id=viewer, role="viewer"),
            )

    async def test_latest_for_resource_is_newest_first(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            history = await AuditRepository(session).latest_for_resource("bot", "bot-1")
        assert len(history) == 5
        stamps = [entry.occurred_at for entry in history]
        assert stamps == sorted(stamps, reverse=True)

    async def test_latest_for_resource_respects_the_limit(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            history = await AuditRepository(session).latest_for_resource("bot", "bot-1", limit=2)
        assert len(history) == 2

    async def test_latest_for_resource_ignores_other_objects(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            history = await AuditRepository(session).latest_for_resource(
                "feature_flag", "live_trading"
            )
        assert len(history) == 1
        assert history[0].action == "ADMIN_CHANGED_FLAG"

    async def test_search_filters_by_action(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            result = await AuditRepository(session).search(
                PaginationParams(page=1, page_size=50), action="BOT_STARTED"
            )
        assert result.total == 5
        assert all(entry.action == "BOT_STARTED" for entry in result.items)

    async def test_search_filters_by_actor(self, database: Database) -> None:
        await self._seed_history(database)
        viewer = uuid.UUID("01890b1e-0000-7000-8000-0000000000bb")
        async with database.session() as session:
            result = await AuditRepository(session).search(
                PaginationParams(page=1, page_size=50), actor_id=viewer
            )
        assert result.total == 1
        assert result.items[0].actor_role == "viewer"

    async def test_search_filters_by_result(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            denied = await AuditRepository(session).search(
                PaginationParams(page=1, page_size=50), result=AuditResult.DENIED
            )
            succeeded = await AuditRepository(session).search(
                PaginationParams(page=1, page_size=50), result=AuditResult.SUCCESS
            )
        assert denied.total == 1
        assert succeeded.total == 6

    async def test_search_paginates(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            repository = AuditRepository(session)
            first = await repository.search(PaginationParams(page=1, page_size=3))
            second = await repository.search(PaginationParams(page=2, page_size=3))
        assert first.total == 7
        assert len(first.items) == 3
        assert len(second.items) == 3
        assert first.has_more is True
        assert {e.id for e in first.items}.isdisjoint({e.id for e in second.items})

    async def test_search_filters_by_time_window(self, database: Database) -> None:
        await self._seed_history(database)
        future = utc_now() + timedelta(hours=1)
        past = utc_now() - timedelta(hours=1)
        async with database.session() as session:
            repository = AuditRepository(session)
            inside = await repository.search(
                PaginationParams(page=1, page_size=50), occurred_from=past, occurred_to=future
            )
            outside = await repository.search(
                PaginationParams(page=1, page_size=50), occurred_from=future
            )
        assert inside.total == 7
        assert outside.total == 0

    async def test_count_denied_since(self, database: Database) -> None:
        """Feeds abnormal-activity detection (§130)."""
        await self._seed_history(database)
        async with database.session() as session:
            repository = AuditRepository(session)
            assert await repository.count_denied_since(utc_now() - timedelta(minutes=5)) == 1
            assert await repository.count_denied_since(utc_now() + timedelta(minutes=5)) == 0

    async def test_unfiltered_search_returns_everything(self, database: Database) -> None:
        await self._seed_history(database)
        async with database.session() as session:
            result = await AuditRepository(session).search(PaginationParams(page=1, page_size=50))
        assert result.total == 7


class TestSchemaShape:
    @pytest.mark.parametrize(
        ("column", "expected"),
        [
            ("action", 128),
            ("resource_type", 64),
            ("resource_id", 128),
            ("actor_role", 64),
            ("ip_address", 64),
            ("user_agent", 512),
            ("request_id", 64),
        ],
    )
    def test_text_columns_are_bounded(self, column: str, expected: int) -> None:
        """Unbounded text in an append-only table is an unbounded disk cost."""
        length = getattr(AuditLog.__table__.c[column].type, "length", None)
        assert length == expected, column

    def test_the_four_admin_indexes_exist(self) -> None:
        """§45, §50, §131 — each dominant query must have an index."""
        # ``__table__`` is declared on the abstract FromClause; this model's is a
        # Table, which is what actually owns the index collection.
        table = cast("Table", AuditLog.__table__)
        names = {index.name for index in table.indexes}
        assert {
            "ix_audit_logs_actor_id_occurred_at",
            "ix_audit_logs_resource_type_resource_id",
            "ix_audit_logs_action_occurred_at",
            "ix_audit_logs_occurred_at",
        } <= names

    def test_value_columns_are_named_safe(self) -> None:
        """The suffix is a permanent reminder at every call site (§53)."""
        columns = set(AuditLog.__table__.c.keys())
        assert "old_value_safe" in columns
        assert "new_value_safe" in columns
        assert "old_value" not in columns
        assert "new_value" not in columns
