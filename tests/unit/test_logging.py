"""Structured logging and secret redaction (§66, §127, §133).

The redaction assertions are the point of this file. Every log line in the
platform passes through this pipeline, so it is the last line of defence before
a credential reaches a log aggregator, a backup, or a support ticket.
"""

from __future__ import annotations

import io
import json
import logging
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr

from arb_core.context import clear_context, context_scope, reset
from arb_core.log import (
    ConsoleFormatter,
    JsonFormatter,
    configure_logging,
    get_logger,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def json_log() -> Iterator[io.StringIO]:
    """Capture JSON log output and restore logging configuration afterwards."""
    buffer = io.StringIO()
    configure_logging(
        level="DEBUG", log_format="json", service="unit-test", stream=buffer, redaction_enabled=True
    )
    try:
        yield buffer
    finally:
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)


def records(buffer: io.StringIO) -> list[dict[str, Any]]:
    """Parse every emitted line as JSON, failing loudly if one is not."""
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


class TestJsonFormat:
    def test_emits_the_documented_fields(self, json_log: io.StringIO) -> None:
        """§127 specifies this exact shape."""
        get_logger("arb_core.test").info("Order submitted")
        record = records(json_log)[0]
        assert record["level"] == "INFO"
        assert record["service"] == "unit-test"
        assert record["logger"] == "arb_core.test"
        assert record["message"] == "Order submitted"
        assert record["timestamp"].endswith("+00:00")  # UTC, offset-aware (§75)

    def test_one_json_object_per_line(self, json_log: io.StringIO) -> None:
        logger = get_logger("arb_core.test")
        logger.info("first")
        logger.info("second")
        lines = json_log.getvalue().splitlines()
        assert len(lines) == 2
        assert all(json.loads(line) for line in lines)

    def test_structured_extras_are_included(self, json_log: io.StringIO) -> None:
        get_logger("arb_core.test").info(
            "trade", extra={"trade_id": "trd_1", "exchange": "binance", "symbol": "BTC/USDT"}
        )
        record = records(json_log)[0]
        assert record["trade_id"] == "trd_1"
        assert record["exchange"] == "binance"
        assert record["symbol"] == "BTC/USDT"

    def test_exception_is_attached(self, json_log: io.StringIO) -> None:
        try:
            msg = "boom"
            # Raised inline on purpose: the test asserts how a real traceback is
            # rendered, so abstracting it into a helper would change exc_info.
            raise ValueError(msg)  # noqa: TRY301
        except ValueError:
            get_logger("arb_core.test").exception("failed")
        record = records(json_log)[0]
        assert "ValueError" in record["exception"]

    def test_decimal_is_serialised_exactly_not_as_a_float(self, json_log: io.StringIO) -> None:
        """§74 — a money value must not become a double in the log either."""
        from decimal import Decimal

        get_logger("arb_core.test").info("pnl", extra={"net_profit": Decimal("0.30")})
        line = json_log.getvalue()
        assert '"net_profit":"0.30"' in line

    def test_repeated_configuration_does_not_duplicate_output(self) -> None:
        """The app factory runs more than once under a test-suite."""
        buffer = io.StringIO()
        for _ in range(3):
            configure_logging(level="INFO", log_format="json", service="s", stream=buffer)
        get_logger("arb_core.test").info("once")
        assert len(buffer.getvalue().splitlines()) == 1


class TestAmbientContext:
    def test_bound_context_appears_on_every_record(self, json_log: io.StringIO) -> None:
        logger = get_logger("arb_core.test")
        with context_scope(request_id="req_1", user_id="user_1"):
            logger.info("inside")
            with context_scope(trade_id="trd_9", exchange="kraken"):
                logger.info("nested")
            logger.info("after nested")
        logger.info("outside")

        inside, nested, after, outside = records(json_log)
        assert inside["request_id"] == "req_1"
        assert nested["request_id"] == "req_1"
        assert nested["trade_id"] == "trd_9"
        assert "trade_id" not in after  # inner scope unwound
        assert "request_id" not in outside  # outer scope unwound

    def test_context_does_not_leak_between_scopes(self, json_log: io.StringIO) -> None:
        logger = get_logger("arb_core.test")
        with context_scope(request_id="a"):
            logger.info("one")
        with context_scope(request_id="b"):
            logger.info("two")
        first, second = records(json_log)
        assert first["request_id"] == "a"
        assert second["request_id"] == "b"


class TestRedaction:
    """§133: "API secrets never appear in logs" / "Passwords never appear in logs"."""

    @pytest.mark.parametrize(
        ("extra", "forbidden"),
        [
            ({"api_key": "vmPuREDnEP8kQkFbXqEz1L2n"}, "vmPuREDnEP8kQkFbXqEz1L2n"),
            ({"api_secret": "s3cr3t-value"}, "s3cr3t-value"),
            ({"password": "hunter2hunter2"}, "hunter2hunter2"),
            ({"token": "eyJhbGciOiJIUzI1NiJ9"}, "eyJhbGciOiJIUzI1NiJ9"),
            ({"authorization": "Bearer abc123abc123"}, "abc123abc123"),
            ({"private_key": "-----BEGIN-----"}, "-----BEGIN-----"),
            ({"userApiKey": "camelCaseSecret"}, "camelCaseSecret"),
        ],
    )
    def test_sensitive_extras_never_reach_output(
        self, json_log: io.StringIO, extra: dict[str, Any], forbidden: str
    ) -> None:
        get_logger("arb_core.test").info("connecting", extra=extra)
        output = json_log.getvalue()
        assert forbidden not in output
        assert "[REDACTED]" in output

    def test_secret_in_message_text_is_scrubbed(self, json_log: io.StringIO) -> None:
        get_logger("arb_core.test").info(
            "failed with password=Sup3rS3cretValue and token=eyJhbGciOiJIUzI1NiJ9.payload.sig"
        )
        output = json_log.getvalue()
        assert "Sup3rS3cretValue" not in output
        assert "eyJhbGciOiJIUzI1NiJ9" not in output

    def test_connection_string_in_message_is_scrubbed(self, json_log: io.StringIO) -> None:
        get_logger("arb_core.test").info(
            "could not connect to postgresql://arb:db-p4ssw0rd@db:5432/arbitrage"
        )
        output = json_log.getvalue()
        assert "db-p4ssw0rd" not in output
        assert "db:5432" in output  # the useful part survives

    def test_nested_extras_are_scrubbed(self, json_log: io.StringIO) -> None:
        get_logger("arb_core.test").info(
            "payload",
            extra={"account": {"exchange": "binance", "credentials": {"secret": "deep-secret"}}},
        )
        assert "deep-secret" not in json_log.getvalue()
        assert "binance" in json_log.getvalue()

    def test_exception_text_is_scrubbed(self, json_log: io.StringIO) -> None:
        try:
            msg = "auth failed for api_key=EXCHANGE-KEY-VALUE"
            raise RuntimeError(msg)  # noqa: TRY301 - the traceback is the subject
        except RuntimeError:
            get_logger("arb_core.test").exception("error")
        assert "EXCHANGE-KEY-VALUE" not in json_log.getvalue()

    def test_pydantic_secretstr_is_never_rendered(self, json_log: io.StringIO) -> None:
        """A SecretStr passed by mistake must not be unwrapped by logging."""
        get_logger("arb_core.test").info(
            "config", extra={"jwt_secret": SecretStr("super-secret-jwt-value")}
        )
        output = json_log.getvalue()
        assert "super-secret-jwt-value" not in output

    def test_operational_fields_survive_redaction(self, json_log: io.StringIO) -> None:
        """Over-redaction would make the logs useless during an incident."""
        get_logger("arb_core.test").info(
            "order",
            extra={
                "request_id": "req_42",
                "idempotency_key": "idem_42",
                "exchange": "kraken",
                "symbol": "BTC/USDT",
                "side": "buy",
                "quantity": "0.0025",
            },
        )
        record = records(json_log)[0]
        assert record["request_id"] == "req_42"
        assert record["idempotency_key"] == "idem_42"
        assert record["symbol"] == "BTC/USDT"

    def test_redaction_can_be_disabled_only_for_forensics(self) -> None:
        """The switch exists; production forces it on (asserted in test_config)."""
        buffer = io.StringIO()
        configure_logging(
            level="INFO",
            log_format="json",
            service="s",
            stream=buffer,
            redaction_enabled=False,
        )
        try:
            get_logger("arb_core.test").info("x", extra={"api_key": "visible-key-value"})
            assert "visible-key-value" in buffer.getvalue()
        finally:
            root = logging.getLogger()
            for handler in list(root.handlers):
                root.removeHandler(handler)


class TestConsoleFormat:
    def test_is_single_line_and_readable(self) -> None:
        formatter = ConsoleFormatter(service="svc", redaction_enabled=True, colour=False)
        record = logging.LogRecord(
            name="arb_core.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Order submitted",
            args=(),
            exc_info=None,
        )
        line = formatter.format(record)
        assert "Order submitted" in line
        assert "[svc]" in line
        assert "INFO" in line
        assert "\n" not in line

    def test_redacts_like_the_json_formatter(self) -> None:
        formatter = ConsoleFormatter(service="svc", redaction_enabled=True, colour=False)
        record = logging.LogRecord(
            name="arb_core.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="password=Sup3rS3cretValue",
            args=(),
            exc_info=None,
        )
        assert "Sup3rS3cretValue" not in formatter.format(record)

    def test_colour_is_disabled_for_non_tty_streams(self) -> None:
        buffer = io.StringIO()
        configure_logging(level="INFO", log_format="console", service="svc", stream=buffer)
        try:
            get_logger("arb_core.test").info("plain")
            assert "\033[" not in buffer.getvalue()
        finally:
            root = logging.getLogger()
            for handler in list(root.handlers):
                root.removeHandler(handler)


class TestJsonFormatterDirectly:
    def test_formatter_does_not_mutate_the_record_message(self) -> None:
        formatter = JsonFormatter(service="svc")
        record = logging.LogRecord(
            name="n",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="value=%s",
            args=("x",),
            exc_info=None,
        )
        formatter.format(record)
        assert record.msg == "value=%s"
        assert record.args == ("x",)


def test_clear_context_helper() -> None:
    token = clear_context()
    try:
        with context_scope(request_id="temp"):
            pass
    finally:
        reset(token)
