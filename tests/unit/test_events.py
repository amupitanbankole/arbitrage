"""Internal event bus (§99).

Idempotency is the property under test. Redis pub/sub, worker restarts and
at-least-once queue semantics all redeliver messages; if a duplicate
``OrderFilled`` event double-counts P&L or re-triggers a hedge, the platform
produces wrong financial records with no error anywhere.
"""

from __future__ import annotations

import asyncio

import pytest

from arb_core.events import Event, EventBus, EventType, InProcessEventBus


class TestEventContract:
    def test_has_a_generated_id_and_utc_timestamp(self) -> None:
        event = Event(event_type=EventType.ORDER_FILLED, source="test")
        assert event.event_id
        assert event.occurred_at.tzinfo is not None

    def test_ids_are_unique(self) -> None:
        ids = {Event(event_type=EventType.ORDER_CREATED, source="t").event_id for _ in range(500)}
        assert len(ids) == 500

    def test_is_immutable(self) -> None:
        """A handler must not be able to mutate what a later handler sees."""
        event = Event(event_type=EventType.TRADE_APPROVED, source="t")
        with pytest.raises(ValueError):
            event.source = "mutated"  # type: ignore[misc]

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValueError):
            Event(event_type=EventType.ORDER_CREATED, source="t", unexpected=1)  # type: ignore[call-arg]

    def test_dedupe_key_prefers_the_business_key(self) -> None:
        event = Event(event_type=EventType.ORDER_FILLED, source="t", idempotency_key="order-1")
        assert event.dedupe_key() == "order-1"
        without = Event(event_type=EventType.ORDER_FILLED, source="t")
        assert without.dedupe_key() == without.event_id

    def test_payload_defaults_to_an_empty_mapping(self) -> None:
        assert Event(event_type=EventType.BOT_CREATED, source="t").payload == {}


class TestEventTypeVocabulary:
    """§98 requires auditable state transitions with stable names."""

    @pytest.mark.parametrize(
        ("member", "value"),
        [
            (EventType.MARKET_DATA_UPDATED, "MarketDataUpdated"),
            (EventType.OPPORTUNITY_DETECTED, "OpportunityDetected"),
            (EventType.RISK_VALIDATED, "RiskValidated"),
            (EventType.TRADE_APPROVED, "TradeApproved"),
            (EventType.ORDER_SUBMITTED, "OrderSubmitted"),
            (EventType.ORDER_FILLED, "OrderFilled"),
            (EventType.PNL_UPDATED, "PnlUpdated"),
            (EventType.NOTIFICATION_SENT, "NotificationSent"),
            (EventType.KILL_SWITCH_TRIGGERED, "KillSwitchTriggered"),
            (EventType.CIRCUIT_BREAKER_TRIGGERED, "CircuitBreakerTriggered"),
            (EventType.LEG_FAILURE_DETECTED, "LegFailureDetected"),
            (EventType.RECONCILIATION_FAILED, "ReconciliationFailed"),
        ],
    )
    def test_documented_events_exist_with_stable_names(self, member: EventType, value: str) -> None:
        """These strings are persisted and matched by alerting rules."""
        assert member.value == value

    def test_values_are_unique(self) -> None:
        values = [member.value for member in EventType]
        assert len(values) == len(set(values))


class TestPublication:
    async def test_handler_receives_the_event(self) -> None:
        bus = InProcessEventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe(EventType.ORDER_FILLED, handler)
        event = Event(event_type=EventType.ORDER_FILLED, source="test")
        await bus.publish(event)
        assert received == [event]

    async def test_unsubscribed_types_are_ignored(self) -> None:
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.ORDER_FILLED, handler)
        await bus.publish(Event(event_type=EventType.ORDER_REJECTED, source="t"))
        assert calls == 0

    async def test_multiple_handlers_all_run_in_order(self) -> None:
        bus = InProcessEventBus()
        order: list[str] = []

        async def first(event: Event) -> None:
            order.append("first")

        async def second(event: Event) -> None:
            order.append("second")

        bus.subscribe(EventType.BOT_STARTED, first)
        bus.subscribe(EventType.BOT_STARTED, second)
        await bus.publish(Event(event_type=EventType.BOT_STARTED, source="t"))
        assert order == ["first", "second"]

    async def test_wildcard_subscriber_sees_everything(self) -> None:
        bus = InProcessEventBus()
        seen: list[str] = []

        async def sink(event: Event) -> None:
            seen.append(event.event_type.value)

        bus.subscribe_all(sink)
        await bus.publish(Event(event_type=EventType.TRADE_COMPLETED, source="t"))
        await bus.publish(Event(event_type=EventType.RISK_REJECTED, source="t"))
        assert seen == ["TradeCompleted", "RiskRejected"]


class TestIdempotency:
    async def test_same_event_object_published_twice_runs_once(self) -> None:
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.ORDER_FILLED, handler)
        event = Event(event_type=EventType.ORDER_FILLED, source="t")
        await bus.publish(event)
        await bus.publish(event)
        assert calls == 1

    async def test_same_business_key_from_different_emissions_runs_once(self) -> None:
        """The realistic duplicate: two distinct event objects, one real-world fact."""
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.ORDER_FILLED, handler)
        for _ in range(5):
            await bus.publish(
                Event(
                    event_type=EventType.ORDER_FILLED,
                    source="execution-worker",
                    idempotency_key="exchange-order-id-42",
                )
            )
        assert calls == 1

    async def test_distinct_business_keys_all_run(self) -> None:
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.ORDER_FILLED, handler)
        for index in range(5):
            await bus.publish(
                Event(
                    event_type=EventType.ORDER_FILLED,
                    source="t",
                    idempotency_key=f"order-{index}",
                )
            )
        assert calls == 5

    async def test_seen_window_is_bounded(self) -> None:
        """De-duplication must not grow without limit on a long-running worker."""
        bus = InProcessEventBus(max_seen=100)
        for index in range(500):
            await bus.publish(
                Event(event_type=EventType.MARKET_DATA_UPDATED, source="t", payload={"i": index})
            )
        # Reaching into _seen is the point: the bound is the behaviour under test.
        assert len(bus._seen) <= 100

    async def test_evicted_keys_can_be_reprocessed(self) -> None:
        """Documented trade-off: the bus is a first line of defence only.

        Handlers that mutate financial state must remain idempotent at the
        database level, because the de-duplication window is finite.
        """
        bus = InProcessEventBus(max_seen=2)
        target_calls = 0

        async def handler(event: Event) -> None:
            nonlocal target_calls
            if event.idempotency_key == "k1":
                target_calls += 1

        bus.subscribe(EventType.MARKET_DATA_UPDATED, handler)
        await bus.publish(
            Event(event_type=EventType.MARKET_DATA_UPDATED, source="t", idempotency_key="k1")
        )
        # Three further keys evict "k1" from a window of two.
        for index in range(3):
            await bus.publish(
                Event(
                    event_type=EventType.MARKET_DATA_UPDATED,
                    source="t",
                    idempotency_key=f"other-{index}",
                )
            )
        await bus.publish(
            Event(event_type=EventType.MARKET_DATA_UPDATED, source="t", idempotency_key="k1")
        )
        # Delivered twice: once before eviction, once after. This is why handlers
        # must also be idempotent in the database.
        assert target_calls == 2

    async def test_duplicate_inside_the_window_is_suppressed(self) -> None:
        """The same key repeated while still in the window runs once."""
        bus = InProcessEventBus(max_seen=10)
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.MARKET_DATA_UPDATED, handler)
        for _ in range(3):
            await bus.publish(
                Event(event_type=EventType.MARKET_DATA_UPDATED, source="t", idempotency_key="k1")
            )
        assert calls == 1


class TestFailureIsolation:
    async def test_a_failing_handler_does_not_block_others(self) -> None:
        """One bad subscriber must not stop the pipeline (§99)."""
        bus = InProcessEventBus()
        reached = False

        async def broken(event: Event) -> None:
            msg = "handler bug"
            raise RuntimeError(msg)

        async def fine(event: Event) -> None:
            nonlocal reached
            reached = True

        bus.subscribe(EventType.TRADE_FAILED, broken)
        bus.subscribe(EventType.TRADE_FAILED, fine)
        await bus.publish(Event(event_type=EventType.TRADE_FAILED, source="t"))
        assert reached is True

    async def test_publish_does_not_raise_when_a_handler_raises(self) -> None:
        bus = InProcessEventBus()

        async def broken(event: Event) -> None:
            msg = "handler bug"
            raise RuntimeError(msg)

        bus.subscribe(EventType.BOT_ERROR, broken)
        await bus.publish(Event(event_type=EventType.BOT_ERROR, source="t"))

    async def test_concurrent_publication_is_serialised_for_dedup(self) -> None:
        """A redelivery race must not let the same event through twice."""
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.ORDER_SUBMITTED, handler)
        event = Event(event_type=EventType.ORDER_SUBMITTED, source="t", idempotency_key="race-1")
        await asyncio.gather(*(bus.publish(event) for _ in range(20)))
        assert calls == 1

    async def test_clear_removes_handlers(self) -> None:
        """``clear()`` is a full reset, not just of the de-duplication window."""
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.PNL_UPDATED, handler)
        await bus.publish(Event(event_type=EventType.PNL_UPDATED, source="t"))
        bus.clear()
        await bus.publish(Event(event_type=EventType.PNL_UPDATED, source="t"))
        assert calls == 1

    async def test_clear_resets_the_dedup_window(self) -> None:
        bus = InProcessEventBus()
        calls = 0

        async def handler(event: Event) -> None:
            nonlocal calls
            calls += 1

        bus.subscribe(EventType.PNL_UPDATED, handler)
        event = Event(event_type=EventType.PNL_UPDATED, source="t", idempotency_key="c1")
        await bus.publish(event)
        bus.clear()
        bus.subscribe(EventType.PNL_UPDATED, handler)
        await bus.publish(event)
        assert calls == 2


class TestInterface:
    def test_base_interface_is_abstract(self) -> None:
        """Implementations must be checked against the contract (§99)."""
        bus = EventBus()
        with pytest.raises(NotImplementedError):
            bus.subscribe(EventType.ORDER_FILLED, lambda event: None)  # type: ignore[arg-type,return-value]

    def test_in_process_bus_satisfies_the_interface(self) -> None:
        assert isinstance(InProcessEventBus(), EventBus)
