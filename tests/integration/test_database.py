"""Database engine, portable types and transaction semantics (§9, §63, §74, §75, §81).

These run against SQLite by default and against real PostgreSQL when
``TEST_POSTGRES_URL`` is set. The point of that duplication is §74: a decimal
test that only ever runs on SQLite proves nothing about the system that will
actually hold customer money, and ``arb_core.db.sql_types`` exists precisely so
the same assertion is meaningful on both.

Phase 1 has no money-bearing tables yet, so the decimal/datetime fidelity tests
use a probe model declared against the same conventions. When ``orders`` and
``balances`` arrive, the guarantees below apply to them unchanged.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, cast
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import MetaData, String, Uuid, select
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool

from arb_api.services.audit_service import AuditActor, AuditService
from arb_api.services.feature_flag_service import _BOOTSTRAP_ATTRIBUTES
from arb_core.clock import utc_now
from arb_core.config import Settings
from arb_core.db.base import NAMING_CONVENTION, Base
from arb_core.db.session import Database, build_engine_kwargs, describe_url, is_sqlite_url
from arb_core.db.sql_types import JSONType, MoneyDecimal, PreciseDecimal, UTCDateTime
from arb_core.health import HealthState
from arb_core.identifiers import uuid7
from arb_core.pagination import PaginationParams
from arb_persistence.models.audit import AuditLog
from arb_persistence.models.enums import ActorType, AuditResult, WorkerStatus
from arb_persistence.models.feature_flags import FEATURE_FLAG_DEFAULTS, FeatureFlag
from arb_persistence.models.observability import WorkerHeartbeat
from arb_persistence.repositories.base import PaginatedResult
from arb_persistence.repositories.feature_flags import FeatureFlagRepository

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import Dialect
    from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Probe model
# ---------------------------------------------------------------------------


class ProbeBase(DeclarativeBase):
    """Deliberately separate from the platform ``Base``.

    Sharing metadata would leak a test-only table into migrations and into
    ``create_all`` for every other test.
    """

    metadata: ClassVar[MetaData] = MetaData(naming_convention=NAMING_CONVENTION)
    # Copied, not re-declared: this asserts the platform map is the thing that
    # makes a bare ``Mapped[Decimal]`` safe (§74).
    type_annotation_map: ClassVar[dict[Any, Any]] = Base.type_annotation_map


class TypeProbe(ProbeBase):
    """One row per type behaviour under test."""

    __tablename__ = "type_probe"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    # No explicit column type: the annotation map must supply an exact one.
    amount: Mapped[Decimal]
    moment: Mapped[datetime]
    label: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)


class _SqliteDialectStub:
    """A dialect whose only relevant property is ``name == 'sqlite'``."""

    name = "sqlite"

    def type_descriptor(self, obj: Any) -> Any:
        return obj


#: ``process_bind_param``/``process_result_value`` receive a ``Dialect`` only so
#: dialect-specific types can adapt their SQL; the paths under test read just
#: ``name``. The stand-in is cast once here so every call site stays readable.
_DIALECT = cast("Dialect", _SqliteDialectStub())


@pytest.fixture
async def probe_table(database: Database) -> AsyncIterator[None]:
    """Create the probe table on the shared test engine, then drop it."""
    async with database.engine.begin() as connection:
        await connection.run_sync(ProbeBase.metadata.create_all)
    try:
        yield
    finally:
        async with database.engine.begin() as connection:
            await connection.run_sync(ProbeBase.metadata.drop_all)


async def _store_and_read(database: Database, **values: Any) -> Any:
    """Insert one probe row and read a single column back."""
    column = values.pop("read")
    async with database.unit_of_work() as session:
        session.add(TypeProbe(**values))
    async with database.session() as session:
        return (await session.execute(select(column))).scalars().all()


class TestTypeAnnotationMap:
    def test_decimal_maps_to_an_exact_type(self) -> None:
        """A bare ``Mapped[Decimal]`` must never become a float column."""
        assert isinstance(TypeProbe.__table__.c.amount.type, PreciseDecimal)

    def test_datetime_maps_to_utc_aware(self) -> None:
        assert isinstance(TypeProbe.__table__.c.moment.type, UTCDateTime)

    def test_uuid_maps_to_portable_guid(self) -> None:
        assert isinstance(TypeProbe.__table__.c.id.type, Uuid)

    def test_naming_convention_is_shared(self) -> None:
        """Autogenerated migrations must name constraints identically (§9)."""
        assert ProbeBase.metadata.naming_convention == Base.metadata.naming_convention
        assert set(NAMING_CONVENTION) == {"ix", "uq", "ck", "fk", "pk", "ix_partial"}


class TestDecimalFidelity:
    async def test_the_classic_float_trap_is_not_present(
        self, database: Database, probe_table: None
    ) -> None:
        """0.1 + 0.2 == 0.3 exactly. On a float column this fails."""
        stored = await _store_and_read(
            database,
            amount=Decimal("0.1") + Decimal("0.2"),
            moment=utc_now(),
            read=TypeProbe.amount,
        )
        assert stored == [Decimal("0.3")]
        assert all(isinstance(value, Decimal) for value in stored)

    async def test_full_precision_survives_the_round_trip(
        self, database: Database, probe_table: None
    ) -> None:
        """18 decimal places is the declared precision; nothing may be rounded."""
        value = Decimal("1234567890.123456789012345678")
        stored = await _store_and_read(
            database, amount=value, moment=utc_now(), read=TypeProbe.amount
        )
        assert stored == [value]

    async def test_negative_values_and_zero(self, database: Database, probe_table: None) -> None:
        """Losses are as important as gains; the sign must survive."""
        values = [Decimal("0"), Decimal("-0.000000000000000001"), Decimal("-99999.99")]
        async with database.unit_of_work() as session:
            for value in values:
                session.add(TypeProbe(amount=value, moment=utc_now()))

        async with database.session() as session:
            stored = (await session.execute(select(TypeProbe.amount))).scalars().all()

        assert sorted(stored) == sorted(values)

    async def test_summation_has_no_drift(self, database: Database, probe_table: None) -> None:
        """The failure mode §74 exists to prevent: accumulated rounding error."""
        async with database.unit_of_work() as session:
            for _ in range(100):
                session.add(TypeProbe(amount=Decimal("0.07"), moment=utc_now()))

        async with database.session() as session:
            rows = (await session.execute(select(TypeProbe.amount))).scalars().all()

        assert sum(rows, Decimal("0")) == Decimal("7.00")

    @pytest.mark.parametrize("bad", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
    def test_non_finite_values_are_rejected_on_write(self, bad: Decimal) -> None:
        """NaN and Infinity must never reach storage as a balance."""
        with pytest.raises(ValueError, match="non-finite"):
            MoneyDecimal.process_bind_param(bad, _DIALECT)

    def test_none_binds_to_none(self) -> None:
        assert MoneyDecimal.process_bind_param(None, _DIALECT) is None

    def test_nulls_come_back_as_none(self) -> None:
        assert MoneyDecimal.process_result_value(None, _DIALECT) is None

    def test_sqlite_stores_the_exact_literal_not_a_float(self) -> None:
        """The regression that a float column would cause, made explicit."""
        bound = PreciseDecimal(38, 18).process_bind_param(Decimal("0.30000000000000004"), _DIALECT)
        assert bound == "0.30000000000000004"
        assert float(bound) != Decimal("0.3")


class TestDateTimeFidelity:
    async def test_aware_utc_round_trips_unchanged(
        self, database: Database, probe_table: None
    ) -> None:
        moment = datetime(2026, 9, 5, 12, 30, 45, 123456, tzinfo=UTC)
        stored = await _store_and_read(
            database, amount=Decimal("1"), moment=moment, read=TypeProbe.moment
        )
        assert stored == [moment]
        assert stored[0].tzinfo is not None, "§75 — naive datetimes must not escape"

    async def test_non_utc_offset_is_normalised_to_utc(
        self, database: Database, probe_table: None
    ) -> None:
        """Lagos is UTC+1. Instants must compare correctly regardless of origin."""
        local = datetime(2026, 9, 5, 13, 0, 0, tzinfo=ZoneInfo("Africa/Lagos"))
        stored = await _store_and_read(
            database, amount=Decimal("1"), moment=local, read=TypeProbe.moment
        )
        assert stored[0].utcoffset() == timedelta(0)
        assert stored[0] == datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)

    async def test_naive_datetime_is_rejected_on_write(
        self, database: Database, probe_table: None
    ) -> None:
        """A naive value is ambiguous; the database refuses to guess.

        SQLAlchemy wraps type-level failures in ``StatementError``. The wrapped
        cause must still be *our* §75 message, because that is what an operator
        sees in the log when a future model forgets a timezone.
        """
        with pytest.raises(StatementError) as excinfo:
            async with database.unit_of_work() as session:
                session.add(
                    TypeProbe(
                        amount=Decimal("1"),
                        # Naive on purpose: this is the value that must be rejected.
                        moment=datetime(2026, 9, 5, 12, 0, 0),  # noqa: DTZ001
                    )
                )

        cause = excinfo.value.orig
        assert isinstance(cause, ValueError)
        assert "timezone-aware UTC" in str(cause)

    async def test_timestamp_mixin_defaults_are_populated(self, database: Database) -> None:
        """Platform models get created_at/updated_at without being asked (§9)."""
        async with database.unit_of_work() as session:
            flag = FeatureFlag(key="probe_ts", description="", enabled=False)
            session.add(flag)
            await session.flush()
            assert flag.created_at.tzinfo is not None
            assert flag.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_change(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            flag = FeatureFlag(key="probe_ts2", description="before", enabled=False)
            session.add(flag)
            await session.flush()
            first = flag.updated_at

            created = flag.created_at
            flag.description = "after"
            await session.flush()

            # onupdate fired (>= rather than > : two flushes can share a
            # microsecond), and it left created_at alone.
            assert flag.description == "after"
            assert flag.updated_at >= first
            assert flag.created_at == created


class TestIdentifiers:
    async def test_primary_keys_are_uuid7_and_time_ordered(self, database: Database) -> None:
        """§82 — insert-heavy tables stay append-mostly instead of scattering."""
        generated = [uuid7() for _ in range(50)]
        async with database.unit_of_work() as session:
            for index, identifier in enumerate(generated):
                session.add(
                    WorkerHeartbeat(
                        id=identifier,
                        role="foundation",
                        identity=f"worker-{index}",
                        host="test-host",
                        environment="test",
                        status=WorkerStatus.RUNNING,
                        last_heartbeat_at=utc_now(),
                    )
                )

        async with database.session() as session:
            stored = (await session.execute(select(WorkerHeartbeat.id))).scalars().all()

        assert len(stored) == 50
        assert sorted(stored) == sorted(generated)
        assert all(value.version == 7 for value in stored)

    async def test_primary_keys_are_generated_when_omitted(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            flag = FeatureFlag(key="auto_id", description="", enabled=False)
            session.add(flag)
            await session.flush()
            assert flag.id.version == 7


class TestJsonColumn:
    async def test_nested_payload_round_trips(self, database: Database, probe_table: None) -> None:
        payload = {"nested": {"list": [1, 2, 3]}, "flag": True, "nothing": None}
        stored = await _store_and_read(
            database,
            amount=Decimal("1"),
            moment=utc_now(),
            payload=payload,
            read=TypeProbe.payload,
        )
        assert stored == [payload]

    async def test_null_payload_round_trips(self, database: Database, probe_table: None) -> None:
        stored = await _store_and_read(
            database, amount=Decimal("1"), moment=utc_now(), read=TypeProbe.payload
        )
        assert stored == [None]


class TestTransactionSemantics:
    async def test_unit_of_work_commits_on_success(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            session.add(FeatureFlag(key="committed", description="", enabled=False))

        async with database.session() as reader:
            assert await FeatureFlagRepository(reader).get_by_key("committed") is not None

    async def test_unit_of_work_rolls_back_on_exception(self, database: Database) -> None:
        """§63 — a failed write must leave no partial state behind."""
        with pytest.raises(RuntimeError, match="boom"):
            async with database.unit_of_work() as session:
                session.add(FeatureFlag(key="rolled_back", description="", enabled=False))
                await session.flush()
                raise RuntimeError("boom")

        async with database.session() as reader:
            assert await FeatureFlagRepository(reader).get_by_key("rolled_back") is None

    async def test_unit_of_work_rolls_back_on_cancellation(self, database: Database) -> None:
        """A cancelled task must not leave a half-applied financial write."""
        with pytest.raises(asyncio.CancelledError):
            async with database.unit_of_work() as session:
                session.add(FeatureFlag(key="cancelled", description="", enabled=False))
                await session.flush()
                raise asyncio.CancelledError

        async with database.session() as reader:
            assert await FeatureFlagRepository(reader).get_by_key("cancelled") is None

    async def test_plain_session_does_not_commit(self, database: Database) -> None:
        """Read paths must not open a write transaction (§81)."""
        async with database.session() as session:
            session.add(FeatureFlag(key="never_committed", description="", enabled=False))
            await session.flush()

        async with database.session() as reader:
            assert await FeatureFlagRepository(reader).get_by_key("never_committed") is None

    async def test_session_factory_is_stable(self, database: Database) -> None:
        """One factory per process; per-request factories leak connections."""
        assert database.session_factory() is database.session_factory()


class TestHealthProbe:
    async def test_healthy(self, database: Database) -> None:
        check = await database.probe()
        assert check.name == "database"
        assert check.state is HealthState.HEALTHY
        # latency_ms is None only when a probe never completed; a HEALTHY check
        # must carry a real measurement, so that is asserted before comparing.
        assert check.latency_ms is not None
        assert check.latency_ms >= 0
        assert check.detail is None

    async def test_degraded_on_slow_probe(self, database: Database) -> None:
        """-1 rather than 0: an in-memory probe can legitimately take 0ms."""
        check = await database.probe(degraded_after_ms=-1)
        assert check.state is HealthState.DEGRADED
        assert check.detail is not None

    async def test_unavailable_when_the_database_cannot_be_reached(self) -> None:
        """§111 — the probe reports the outage; it must not raise into the handler."""
        broken = Database.create("postgresql+asyncpg://arbuser:pw@127.0.0.1:1/arbitrage")
        try:
            check = await broken.probe()
        finally:
            await broken.dispose()
        assert check.state is HealthState.UNAVAILABLE
        assert check.detail is not None
        assert check.detail.startswith("probe failed: ")

    async def test_probe_never_leaks_credentials(self) -> None:
        """§133 — driver messages routinely embed the DSN, which has the password."""
        broken = Database.create("postgresql+asyncpg://arbuser:Sup3rSecret@127.0.0.1:1/arbitrage")
        try:
            check = await broken.probe()
        finally:
            await broken.dispose()

        assert check.state is HealthState.UNAVAILABLE
        assert "Sup3rSecret" not in (check.detail or "")
        assert "Sup3rSecret" not in broken.url_safe

    def test_unwritable_sqlite_path_fails_fast(self, tmp_path: Any) -> None:
        """A misconfigured path errors at construction, not at the first query.

        This is deliberate: §111 keeps *outages* from killing startup, but a
        path that can never work should not be discovered mid-request.
        """
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        with pytest.raises(OSError):
            Database.create(f"sqlite+aiosqlite:///{blocker}/nested.db")


class TestEngineConstruction:
    def test_memory_sqlite_uses_a_shared_static_pool(self) -> None:
        """Each new connection would otherwise see an empty database."""
        kwargs = build_engine_kwargs("sqlite+aiosqlite:///:memory:")
        assert kwargs["poolclass"] is StaticPool
        assert kwargs["connect_args"]["check_same_thread"] is False
        assert "pool_size" not in kwargs

    def test_file_sqlite_omits_postgres_pool_arguments(self) -> None:
        kwargs = build_engine_kwargs("sqlite+aiosqlite:///./tmpfiles/x.db")
        assert "pool_size" not in kwargs
        assert "pool_pre_ping" not in kwargs

    def test_postgres_gets_a_bounded_pre_pinging_pool(self) -> None:
        """§81 — dropped connections must be replaced, not surfaced as failures."""
        kwargs = build_engine_kwargs(
            "postgresql+asyncpg://u:p@h:5432/db",
            pool_size=7,
            max_overflow=3,
            pool_timeout=11,
            pool_recycle=99,
        )
        assert kwargs["pool_size"] == 7
        assert kwargs["max_overflow"] == 3
        assert kwargs["pool_timeout"] == 11
        assert kwargs["pool_recycle"] == 99
        assert kwargs["pool_pre_ping"] is True
        assert "poolclass" not in kwargs

    def test_url_classification(self) -> None:
        assert is_sqlite_url("sqlite+aiosqlite:///:memory:")
        assert is_sqlite_url("sqlite:///:memory:")
        assert not is_sqlite_url("postgresql+asyncpg://u:p@h/db")

    def test_describe_url_excludes_the_password(self) -> None:
        described = describe_url("postgresql+asyncpg://u:secret@db-host:5432/arbitrage")
        assert described == {
            "scheme": "postgresql+asyncpg",
            "host": "db-host",
            "port": 5432,
            "database": "arbitrage",
            "sqlite": False,
        }
        assert "secret" not in str(described)

    def test_from_settings_applies_configuration(self, settings: Settings) -> None:
        db = Database.from_settings(settings)
        assert db.dialect_name == "sqlite"
        # No credentials to mask in the test DSN, so the URL is reported as-is.
        assert db.url_safe == settings.database_url.get_secret_value()

    def test_from_settings_masks_a_password_bearing_url(self, settings: Settings) -> None:
        overridden = Settings(
            **{
                **settings.model_dump(exclude={"database_url"}),
                "database_url": "postgresql+asyncpg://arb:Sup3rSecret@db:5432/arb",
            }
        )
        db = Database.from_settings(overridden)
        assert "Sup3rSecret" not in db.url_safe
        assert "Sup3rSecret" not in str(db.engine.url)
        assert db.url_safe == "postgresql+asyncpg://arb:[REDACTED]@db:5432/arb"
        # PostgreSQL-only pool arguments were applied, SQLite-only ones were not.
        assert db.engine.pool.__class__.__name__ == "AsyncAdaptedQueuePool"
        assert db.engine.pool._pre_ping is True

    def test_from_settings_works_on_sqlite(self, settings: Settings) -> None:
        """Regression guard for a real startup-blocking defect.

        ``from_settings`` used to forward ``pool_size``/``max_overflow``/
        ``pool_timeout`` to ``create_async_engine`` unconditionally. PostgreSQL
        accepts them; SQLite raises ``TypeError``. Since development and the
        whole test-suite run on SQLite, the API could not start at all outside
        production — the worst possible way for the bug to present itself.
        """
        db = Database.from_settings(settings)
        assert db.dialect_name == "sqlite"
        assert db.engine.pool.__class__.__name__ == "StaticPool"

    def test_sqlite_parent_directory_is_created(self, tmp_path: Any) -> None:
        """A fresh checkout must not fail with 'unable to open database file'."""
        db = Database.create(f"sqlite+aiosqlite:///{tmp_path}/nested/dir/test.db")
        assert (tmp_path / "nested" / "dir").is_dir()
        assert db.dialect_name == "sqlite"


class TestRepositoryPagination:
    async def _seed(self, session: AsyncSession, count: int, *, prefix: str = "flag") -> None:
        repository = FeatureFlagRepository(session)
        repository.add_all(
            [
                FeatureFlag(key=f"{prefix}_{index:02d}", description="", enabled=False)
                for index in range(count)
            ]
        )
        await repository.flush()

    async def test_paginate_returns_the_page_and_the_total(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await self._seed(session, 25)

        async with database.session() as session:
            result = await FeatureFlagRepository(session).paginate(
                PaginationParams(page=2, page_size=10), order_by=(FeatureFlag.key,)
            )

        assert isinstance(result, PaginatedResult)
        assert result.total == 25
        assert len(result.items) == 10
        assert result.items[0].key == "flag_10"
        assert result.has_more is True

    async def test_last_page_reports_no_more(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await self._seed(session, 3)

        async with database.session() as session:
            result = await FeatureFlagRepository(session).paginate(
                PaginationParams(page=1, page_size=10)
            )
        assert result.total == 3
        assert result.has_more is False

    async def test_page_beyond_the_end_is_empty(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await self._seed(session, 3)

        async with database.session() as session:
            result = await FeatureFlagRepository(session).paginate(
                PaginationParams(page=99, page_size=10)
            )
        assert result.items == []
        assert result.total == 3
        assert result.has_more is False

    async def test_criteria_narrow_both_the_count_and_the_page(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            FeatureFlagRepository(session).add_all(
                [
                    FeatureFlag(key="on_1", description="", enabled=True),
                    FeatureFlag(key="on_2", description="", enabled=True),
                    FeatureFlag(key="off_1", description="", enabled=False),
                ]
            )

        async with database.session() as session:
            result = await FeatureFlagRepository(session).paginate(
                PaginationParams(page=1, page_size=10),
                criteria=(FeatureFlag.enabled.is_(True),),
            )
        assert result.total == 2
        assert {flag.key for flag in result.items} == {"on_1", "on_2"}


class TestEnumPersistence:
    async def test_enums_round_trip_as_their_members(self, database: Database) -> None:
        async with database.unit_of_work() as session:
            await AuditService(session).record(
                action="TEST_ENUM_ROUND_TRIP",
                resource_type="feature_flag",
                resource_id="live_trading",
                actor=AuditActor.system(),
                result=AuditResult.SUCCESS,
            )

        async with database.session() as reader:
            row = (await reader.execute(select(AuditLog))).scalar_one()

        assert row.actor_type is ActorType.SYSTEM
        assert row.result is AuditResult.SUCCESS

    async def test_invalid_enum_value_is_rejected(self, database: Database) -> None:
        """``validate_strings=True`` makes the database the last line of defence."""
        with pytest.raises(StatementError) as excinfo:
            async with database.unit_of_work() as session:
                session.add(
                    WorkerHeartbeat(
                        role="foundation",
                        identity="bad-status",
                        host="h",
                        environment="test",
                        status="NOT_A_STATUS",
                        last_heartbeat_at=utc_now(),
                    )
                )
                await session.flush()

        assert isinstance(excinfo.value.orig, LookupError)
        assert "NOT_A_STATUS" in str(excinfo.value.orig)


class TestSchemaIntegrity:
    def test_every_declared_flag_has_its_own_bootstrap_attribute(self) -> None:
        """Regression guard for a real defect: two keys shared one attribute.

        Coupling ``advanced_strategies`` (§19) to ``advanced_execution`` (§28)
        meant a config change to one silently seeded the other.
        """
        assert set(_BOOTSTRAP_ATTRIBUTES) == set(FEATURE_FLAG_DEFAULTS)
        attributes = list(_BOOTSTRAP_ATTRIBUTES.values())
        assert len(set(attributes)) == len(attributes), "each key needs its own attribute"
        for attribute in attributes:
            assert attribute in Settings.model_fields, f"{attribute} is not a Settings field"

    def test_nothing_that_can_lose_money_is_enabled_by_default(self) -> None:
        """§31, §110 — the committed defaults are the last line of defence."""
        for key in ("live_trading", "dex_trading", "advanced_execution"):
            enabled, _ = FEATURE_FLAG_DEFAULTS[key]
            assert enabled is False, key

    def test_paper_trading_is_the_only_enabled_default(self) -> None:
        enabled = {key for key, (value, _) in FEATURE_FLAG_DEFAULTS.items() if value}
        assert enabled == {"paper_trading"}

    def test_audit_log_has_no_update_or_delete_affordances(self) -> None:
        """§83 — append-only means there is nothing to update."""
        assert "updated_at" not in AuditLog.__table__.c
        assert "deleted_at" not in AuditLog.__table__.c

    def test_financial_models_never_soft_delete(self) -> None:
        """§83 forbids casually removing financial history."""
        from arb_core.db.base import SoftDeleteMixin

        for model in (AuditLog, FeatureFlag, WorkerHeartbeat):
            assert not issubclass(model, SoftDeleteMixin), model.__name__


@pytest.mark.postgres
class TestAgainstRealPostgres:
    """Exercised in CI where a real server is available (§142)."""

    async def test_native_types_are_exact(self) -> None:
        db = Database.create(os.environ["TEST_POSTGRES_URL"])
        try:
            async with db.engine.begin() as connection:
                await connection.run_sync(ProbeBase.metadata.create_all)
            try:
                stored = await _store_and_read(
                    db,
                    amount=Decimal("0.1") + Decimal("0.2"),
                    moment=utc_now(),
                    read=TypeProbe.amount,
                )
                assert stored == [Decimal("0.3")]
                assert db.dialect_name == "postgresql"
            finally:
                async with db.engine.begin() as connection:
                    await connection.run_sync(ProbeBase.metadata.drop_all)
        finally:
            await db.dispose()
