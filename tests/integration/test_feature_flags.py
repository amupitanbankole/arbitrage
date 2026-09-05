"""Feature flags: precedence, rollout and fail-closed evaluation (§57, §58, §91, §110).

The property that matters most is **precedence**: the database row wins over the
configuration default, so a container restart can never silently re-enable a
capability an administrator turned off. Second is **fail closed**: when the flag
cannot be read, the answer must be the committed default — which is ``False`` for
everything that can lose money.

Evaluation order is also a security property, not a detail. The master switch and
the allow-lists are checked *before* the percentage rollout, so landing inside a
rollout bucket can never bypass a plan restriction or a disabled flag.
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

import pytest

from arb_api.services.feature_flag_service import FeatureFlagService
from arb_core.db.session import Database
from arb_core.errors import AppError, ErrorCode
from arb_persistence.models.feature_flags import FEATURE_FLAG_DEFAULTS, FeatureFlag
from arb_persistence.repositories.feature_flags import FeatureFlagRepository
from tests.support.apps import UNREACHABLE_DATABASE_URL
from tests.support.config import override

if TYPE_CHECKING:
    from arb_core.config import Settings
    from arb_core.redis.client import RedisClient

LIVE = "live_trading"
PAPER = "paper_trading"


async def _seed(
    database: Database,
    key: str,
    *,
    enabled: bool,
    rollout_percentage: int = 100,
    allowed_plans: list[str] | None = None,
    allowed_user_ids: list[str] | None = None,
) -> None:
    async with database.unit_of_work() as session:
        session.add(
            FeatureFlag(
                key=key,
                description="seeded by test",
                enabled=enabled,
                rollout_percentage=rollout_percentage,
                allowed_plans=allowed_plans,
                allowed_user_ids=allowed_user_ids,
            )
        )


def _service(
    settings: Settings,
    session: Any = None,
    redis: RedisClient | None = None,
) -> FeatureFlagService:
    return FeatureFlagService(settings=settings, session=session, redis=redis)


class TestSeeding:
    async def test_seeds_every_declared_flag(self, settings: Settings, database: Database) -> None:
        async with database.unit_of_work() as session:
            inserted = await _service(settings, session=session).ensure_seeded()
        assert inserted == len(FEATURE_FLAG_DEFAULTS)

    async def test_seeding_is_idempotent(self, settings: Settings, database: Database) -> None:
        """Replicas restart constantly; seeding must not duplicate or fail."""
        async with database.unit_of_work() as session:
            first = await _service(settings, session=session).ensure_seeded()
        async with database.unit_of_work() as session:
            second = await _service(settings, session=session).ensure_seeded()
        assert first == len(FEATURE_FLAG_DEFAULTS)
        assert second == 0

        async with database.session() as session:
            flags = await FeatureFlagRepository(session).list_all()
        assert len(flags) == len(FEATURE_FLAG_DEFAULTS)

    async def test_seeding_never_overwrites_an_operators_decision(
        self, settings: Settings, database: Database
    ) -> None:
        """§91 — the whole point of database-driven flags."""
        await _seed(database, LIVE, enabled=False, rollout_percentage=0)
        escalated = override(settings, live_trading_enabled=True, feature_flag_live_trading=True)
        async with database.unit_of_work() as session:
            inserted = await _service(escalated, session=session).ensure_seeded()

        assert inserted == len(FEATURE_FLAG_DEFAULTS) - 1, "live_trading already existed"
        async with database.session() as session:
            flag = await FeatureFlagRepository(session).get_by_key(LIVE)
        assert flag is not None
        assert flag.enabled is False, "a restart must not re-enable what was disabled"

    async def test_seeded_rollout_matches_enabled_state(
        self, settings: Settings, database: Database
    ) -> None:
        async with database.unit_of_work() as session:
            await _service(settings, session=session).ensure_seeded()
        async with database.session() as session:
            for flag in await FeatureFlagRepository(session).list_all():
                assert flag.rollout_percentage == (100 if flag.enabled else 0), flag.key

    async def test_seeding_without_a_session_is_a_no_op(self, settings: Settings) -> None:
        assert await _service(settings).ensure_seeded() == 0


class TestPrecedence:
    async def test_database_row_wins_over_the_bootstrap_default(
        self, settings: Settings, database: Database
    ) -> None:
        """``feature_flag_paper_trading`` defaults True; the row says False."""
        assert settings.feature_flag_paper_trading is True
        await _seed(database, PAPER, enabled=False, rollout_percentage=0)
        async with database.session() as session:
            assert await _service(settings, session=session).is_enabled(PAPER) is False

    async def test_database_row_can_enable_what_config_left_disabled(
        self, settings: Settings, database: Database
    ) -> None:
        assert settings.feature_flag_live_trading is False
        await _seed(database, LIVE, enabled=True, rollout_percentage=100)
        async with database.session() as session:
            assert await _service(settings, session=session).is_enabled(LIVE) is True

    async def test_unknown_flag_falls_back_to_the_committed_default(
        self, settings: Settings, database: Database, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Failing closed means the *committed* default, not an arbitrary False."""
        import logging

        async with database.session() as session:
            service = _service(settings, session=session)
            with caplog.at_level(logging.WARNING):
                assert await service.is_enabled(PAPER) is True
                assert await service.is_enabled(LIVE) is False
                assert await service.is_enabled("not_a_real_flag") is False

        assert any("falling back to committed default" in r.message for r in caplog.records)

    async def test_unreadable_database_fails_closed(self, settings: Settings) -> None:
        """§58 — an outage must never be read as 'everything is allowed'."""
        broken = Database.create(UNREACHABLE_DATABASE_URL)
        try:
            async with broken.session() as session:
                service = _service(settings, session=session)
                assert await service.is_enabled(LIVE) is False
                assert await service.is_enabled(PAPER) is True
        finally:
            await broken.dispose()

    async def test_bootstrap_default_for_an_unknown_key_is_false(self, settings: Settings) -> None:
        assert _service(settings).bootstrap_default("invented_capability") is False


class TestRequireEnabled:
    async def test_raises_when_disabled(self, settings: Settings, database: Database) -> None:
        await _seed(database, LIVE, enabled=False)
        async with database.session() as session:
            service = _service(settings, session=session)
            with pytest.raises(AppError) as excinfo:
                await service.require_enabled(LIVE)
        error = excinfo.value
        assert error.code is ErrorCode.FEATURE_DISABLED
        assert error.details == {"flag": LIVE}
        assert LIVE in str(error)

    async def test_passes_when_enabled(self, settings: Settings, database: Database) -> None:
        await _seed(database, PAPER, enabled=True)
        async with database.session() as session:
            await _service(settings, session=session).require_enabled(PAPER)

    async def test_custom_message_is_used(self, settings: Settings, database: Database) -> None:
        await _seed(database, LIVE, enabled=False)
        async with database.session() as session:
            with pytest.raises(Exception, match="live trading is not available on your plan"):
                await _service(settings, session=session).require_enabled(
                    LIVE, message="live trading is not available on your plan"
                )


class TestRolloutAndAllowLists:
    async def test_disabled_flag_is_off_even_at_full_rollout(
        self, settings: Settings, database: Database, some_user_id: uuid.UUID
    ) -> None:
        """Ordering is a security property: the master switch is checked first."""
        await _seed(database, LIVE, enabled=False, rollout_percentage=100)
        async with database.session() as session:
            assert (
                await _service(settings, session=session).is_enabled(LIVE, user_id=some_user_id)
                is False
            )

    async def test_enabled_at_zero_rollout_is_allow_list_only(
        self, settings: Settings, database: Database, some_user_id: uuid.UUID
    ) -> None:
        await _seed(database, LIVE, enabled=True, rollout_percentage=0)
        async with database.session() as session:
            service = _service(settings, session=session)
            assert await service.is_enabled(LIVE, user_id=some_user_id) is False
            assert await service.is_enabled(LIVE) is False

    async def test_full_rollout_reaches_everyone(
        self, settings: Settings, database: Database
    ) -> None:
        await _seed(database, PAPER, enabled=True, rollout_percentage=100)
        async with database.session() as session:
            service = _service(settings, session=session)
            assert await service.is_enabled(PAPER) is True
            assert await service.is_enabled(PAPER, user_id=uuid.uuid4()) is True

    async def test_partial_rollout_is_deterministic_per_user(
        self, settings: Settings, database: Database
    ) -> None:
        """§135 — a user must not flip between states across requests."""
        user = uuid.uuid4()
        await _seed(database, LIVE, enabled=True, rollout_percentage=50)
        async with database.session() as session:
            service = _service(settings, session=session)
            results = {await service.is_enabled(LIVE, user_id=user) for _ in range(20)}
        assert len(results) == 1

    async def test_partial_rollout_splits_a_population(
        self, settings: Settings, database: Database
    ) -> None:
        """A 50% rollout that admits nobody (or everybody) is not a rollout."""
        await _seed(database, LIVE, enabled=True, rollout_percentage=50)
        users = [uuid.uuid4() for _ in range(200)]
        async with database.session() as session:
            service = _service(settings, session=session)
            admitted = [await service.is_enabled(LIVE, user_id=user) for user in users]
        assert 0.3 < (sum(admitted) / len(admitted)) < 0.7

    async def test_partial_rollout_needs_a_user_identity(
        self, settings: Settings, database: Database
    ) -> None:
        """An anonymous caller cannot be bucketed, so it is not admitted."""
        await _seed(database, LIVE, enabled=True, rollout_percentage=50)
        async with database.session() as session:
            assert await _service(settings, session=session).is_enabled(LIVE) is False

    async def test_plan_allow_list_restricts_access(
        self, settings: Settings, database: Database, some_user_id: uuid.UUID
    ) -> None:
        await _seed(
            database,
            LIVE,
            enabled=True,
            rollout_percentage=100,
            allowed_plans=["pro", "enterprise"],
        )
        async with database.session() as session:
            service = _service(settings, session=session)
            assert await service.is_enabled(LIVE, plan="pro", user_id=some_user_id) is True
            assert await service.is_enabled(LIVE, plan="free", user_id=some_user_id) is False
            assert await service.is_enabled(LIVE, user_id=some_user_id) is False

    async def test_plan_restriction_survives_a_favourable_rollout_bucket(
        self, settings: Settings, database: Database
    ) -> None:
        """§57 — landing in the bucket must not bypass the plan gate."""
        user = uuid.UUID(int=1)  # bucket 1: inside any rollout >= 2%
        await _seed(
            database, LIVE, enabled=True, rollout_percentage=100, allowed_plans=["enterprise"]
        )
        async with database.session() as session:
            service = _service(settings, session=session)
            assert await service.is_enabled(LIVE, plan="free", user_id=user) is False
            assert await service.is_enabled(LIVE, plan="enterprise", user_id=user) is True

    async def test_user_allow_list_restricts_access(
        self, settings: Settings, database: Database
    ) -> None:
        insider = uuid.uuid4()
        await _seed(
            database,
            LIVE,
            enabled=True,
            rollout_percentage=0,
            allowed_user_ids=[str(insider)],
        )
        async with database.session() as session:
            service = _service(settings, session=session)
            assert await service.is_enabled(LIVE, user_id=insider) is True
            assert await service.is_enabled(LIVE, user_id=uuid.uuid4()) is False

    async def test_both_allow_lists_must_pass(self, settings: Settings, database: Database) -> None:
        """At 0% rollout the allow-lists are the only way in, so this isolates
        their conjunction from the percentage gate."""
        insider = uuid.uuid4()
        await _seed(
            database,
            LIVE,
            enabled=True,
            rollout_percentage=0,
            allowed_plans=["pro"],
            allowed_user_ids=[str(insider)],
        )
        async with database.session() as session:
            service = _service(settings, session=session)
            assert await service.is_enabled(LIVE, plan="pro", user_id=insider) is True
            assert await service.is_enabled(LIVE, plan="free", user_id=insider) is False
            assert await service.is_enabled(LIVE, plan="pro", user_id=uuid.uuid4()) is False

    async def test_allow_list_is_additive_as_the_rollout_widens(
        self, settings: Settings, database: Database
    ) -> None:
        """The documented lifecycle: internal testers at 0%, then widen.

        Listed users must keep access at every step, and unlisted users must
        start gaining it as the percentage rises — which is what "before a
        broader rollout" means. A purely exclusive allow-list would make raising
        the percentage pointless.
        """
        insider = uuid.uuid4()
        outsider = uuid.UUID(int=99)  # bucket 99: only admitted at 100%
        for rollout in (0, 10, 50, 100):
            key = f"additive_{rollout}"
            await _seed(
                database,
                key,
                enabled=True,
                rollout_percentage=rollout,
                allowed_user_ids=[str(insider)],
            )
            async with database.session() as session:
                service = _service(settings, session=session)
                assert await service.is_enabled(key, user_id=insider) is True, rollout
                expected = rollout >= 100
                assert await service.is_enabled(key, user_id=outsider) is expected, rollout

    async def test_anonymous_caller_never_gets_an_allow_listed_capability(
        self, settings: Settings, database: Database
    ) -> None:
        """No identity means no bucket and no allow-list match."""
        await _seed(
            database,
            LIVE,
            enabled=True,
            rollout_percentage=0,
            allowed_user_ids=[str(uuid.uuid4())],
        )
        async with database.session() as session:
            assert await _service(settings, session=session).is_enabled(LIVE) is False


class TestRedisCache:
    async def test_a_read_populates_the_cache(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        await _seed(database, PAPER, enabled=True)
        async with database.session() as session:
            service = _service(settings, session=session, redis=redis_client)
            assert await service.is_enabled(PAPER) is True

        key = redis_client.key("feature_flag", PAPER)
        cached = await redis_client.raw.get(key)
        assert cached is not None
        payload = json.loads(cached)
        assert payload["key"] == PAPER
        assert payload["enabled"] is True
        assert await redis_client.raw.ttl(key) > 0

    async def test_the_cache_is_used_without_touching_the_database(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """A stale cache is the documented trade-off; the TTL bounds it."""
        await _seed(database, PAPER, enabled=True)
        key = redis_client.key("feature_flag", PAPER)
        await redis_client.raw.set(
            key, json.dumps({"key": PAPER, "enabled": False, "rollout_percentage": 100})
        )
        async with database.session() as session:
            service = _service(settings, session=session, redis=redis_client)
            assert await service.is_enabled(PAPER) is False

    async def test_a_malformed_cache_entry_is_discarded(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        """A corrupt cache must fall through to the database, not to a guess."""
        await _seed(database, PAPER, enabled=True)
        await redis_client.raw.set(redis_client.key("feature_flag", PAPER), "{not json")
        async with database.session() as session:
            service = _service(settings, session=session, redis=redis_client)
            assert await service.is_enabled(PAPER) is True

    async def test_a_non_object_cache_entry_is_discarded(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        await _seed(database, PAPER, enabled=True)
        await redis_client.raw.set(redis_client.key("feature_flag", PAPER), "[1, 2, 3]")
        async with database.session() as session:
            service = _service(settings, session=session, redis=redis_client)
            assert await service.is_enabled(PAPER) is True

    async def test_a_dead_cache_does_not_break_evaluation(
        self, settings: Settings, database: Database
    ) -> None:
        """The cache is an optimisation, never a dependency."""
        from tests.support.apps import unreachable_redis

        await _seed(database, PAPER, enabled=True)
        broken = unreachable_redis()
        try:
            async with database.session() as session:
                service = _service(settings, session=session, redis=broken)
                assert await service.is_enabled(PAPER) is True
        finally:
            await broken.aclose()

    async def test_the_cache_never_stores_secrets(
        self, settings: Settings, database: Database, redis_client: RedisClient
    ) -> None:
        await _seed(database, PAPER, enabled=True)
        async with database.session() as session:
            await _service(settings, session=session, redis=redis_client).is_enabled(PAPER)
        cached = (await redis_client.raw.get(redis_client.key("feature_flag", PAPER))) or b""
        text = cached.decode() if isinstance(cached, bytes) else str(cached)
        assert settings.jwt_secret.get_secret_value() not in text
        assert set(json.loads(text)) == {
            "key",
            "enabled",
            "rollout_percentage",
            "allowed_plans",
            "allowed_user_ids",
        }


class TestCachedAndModelEvaluationAgree:
    """The service mirrors the model's rules for cached payloads.

    Two implementations of one rule will drift, so every combination is compared
    rather than trusting the comment that says they match.
    """

    @pytest.mark.parametrize("enabled", [True, False])
    @pytest.mark.parametrize("rollout", [0, 1, 50, 99, 100])
    @pytest.mark.parametrize("plans", [None, ["pro"]])
    @pytest.mark.parametrize("plan", [None, "pro", "free"])
    @pytest.mark.parametrize("listed", [None, True, False])
    @pytest.mark.parametrize("anonymous", [False, True])
    async def test_matrix_agrees(
        self,
        enabled: bool,
        rollout: int,
        plans: list[str] | None,
        plan: str | None,
        listed: bool | None,
        anonymous: bool,
    ) -> None:
        # ``listed`` selects whether the caller is on the user allow-list; None
        # means there is no allow-list at all. Bucket 42 is inside rollouts >42.
        listed_user = uuid.UUID(int=42)
        unlisted_user = uuid.UUID(int=43)
        allow_list = None if listed is None else [str(listed_user if listed else uuid.UUID(int=1))]
        user: uuid.UUID | None
        if anonymous:
            user = None
        elif listed is False:
            user = unlisted_user
        else:
            user = listed_user

        flag = FeatureFlag(
            key="matrix",
            description="",
            enabled=enabled,
            rollout_percentage=rollout,
            allowed_plans=plans,
            allowed_user_ids=allow_list,
        )
        payload = {
            "key": flag.key,
            "enabled": flag.enabled,
            "rollout_percentage": flag.rollout_percentage,
            "allowed_plans": flag.allowed_plans,
            "allowed_user_ids": flag.allowed_user_ids,
        }
        assert FeatureFlagService._evaluate(payload, plan=plan, user_id=user) == (
            flag.is_enabled_for(plan=plan, user_id=user)
        ), f"rollout={rollout} plans={plans} plan={plan} listed={listed} anon={anonymous}"


class TestAdministrativeViews:
    async def test_list_flags_returns_snapshots(
        self, settings: Settings, database: Database
    ) -> None:
        await _seed(database, PAPER, enabled=True)
        async with database.session() as session:
            flags = await _service(settings, session=session).list_flags()
        assert len(flags) == 1
        assert flags[0]["key"] == PAPER
        assert set(flags[0]) == {
            "key",
            "description",
            "enabled",
            "rollout_percentage",
            "allowed_plans",
            "allowed_user_ids",
            "updated_at",
        }

    async def test_list_flags_without_a_session_uses_the_committed_defaults(
        self, settings: Settings
    ) -> None:
        """The endpoint must still answer before the database is migrated."""
        flags = await _service(settings).list_flags()
        assert {flag["key"] for flag in flags} == set(FEATURE_FLAG_DEFAULTS)

    async def test_set_state_applies_a_partial_update(
        self, settings: Settings, database: Database
    ) -> None:
        await _seed(database, LIVE, enabled=False, rollout_percentage=0)
        async with database.unit_of_work() as session:
            updated = await FeatureFlagRepository(session).set_state(
                LIVE, enabled=True, updated_by=uuid.uuid4()
            )
            assert updated.enabled is True
            assert updated.rollout_percentage == 100

    async def test_disabling_forces_the_rollout_to_zero(
        self, settings: Settings, database: Database
    ) -> None:
        """A later re-enable must not silently resume a wide rollout."""
        await _seed(database, LIVE, enabled=True, rollout_percentage=100)
        async with database.unit_of_work() as session:
            updated = await FeatureFlagRepository(session).set_state(LIVE, enabled=False)
        assert updated.enabled is False
        assert updated.rollout_percentage == 0

    async def test_set_state_on_an_unknown_flag_raises(
        self, settings: Settings, database: Database
    ) -> None:
        async with database.unit_of_work() as session:
            with pytest.raises(KeyError, match="unknown feature flag"):
                await FeatureFlagRepository(session).set_state("invented", enabled=True)

    async def test_rollout_percentage_is_bounded_at_the_database(
        self, settings: Settings, database: Database
    ) -> None:
        """A 250% rollout would be a nonsense state; the CHECK constraint refuses it."""
        from sqlalchemy.exc import IntegrityError

        with pytest.raises(IntegrityError):
            async with database.unit_of_work() as session:
                session.add(
                    FeatureFlag(
                        key="bad_rollout", description="", enabled=True, rollout_percentage=250
                    )
                )
