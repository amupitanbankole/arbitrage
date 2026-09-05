"""The ``arb-worker`` process entrypoint (§55, §86, §140).

These tests cover the CLI shell around :class:`arb_core.worker.WorkerRuntime`:
role resolution, exit-code discipline, and the one code path where logging
cannot be configured yet. The runtime itself is exercised by
``test_worker_runtime``; here ``run_cli`` is replaced with a recorder so no test
blocks inside ``asyncio.run``.

Exit codes are asserted as literals rather than through the module constants.
They are an external contract — a restart policy reads them to decide whether a
process that died will ever succeed — so a test that compares the constant to
itself would keep passing after the contract changed.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import pytest

from arb_core.config import Environment, Settings
from arb_core.errors import ConfigurationError
from arb_core.worker import FOUNDATION_ROLE, available_roles
from arb_worker import main as worker_main
from tests.support.config import override, production_kwargs

if TYPE_CHECKING:
    from collections.abc import Sequence


@pytest.fixture(autouse=True)
def logging_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record ``configure_logging`` calls instead of performing them.

    :func:`arb_core.log.configure_logging` removes every root handler, which
    would take ``caplog`` away from the rest of the test mid-run. The recorder
    keeps the assertion possible *and* keeps capture alive.
    """
    calls: list[dict[str, Any]] = []

    def _record(**kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(worker_main, "configure_logging", _record)
    return calls


@pytest.fixture
def run_cli_calls(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Replace ``run_cli`` with a recorder returning success."""
    calls: list[list[str]] = []

    def _record(roles: Sequence[str] | None = None) -> int:
        calls.append(list(roles or []))
        return 0

    monkeypatch.setattr(worker_main, "run_cli", _record)
    return calls


def _use_settings(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr(worker_main, "get_settings", lambda: settings)


class TestListRoles:
    def test_writes_the_registered_roles(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = worker_main.run(["--list-roles"])

        assert code == 0
        written = capsys.readouterr().out.split()
        assert written == sorted(available_roles())
        assert FOUNDATION_ROLE in written

    def test_works_when_configuration_is_broken(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Diagnostics must survive the failure they are diagnosing.

        An operator whose worker will not start needs ``--list-roles`` to work
        *precisely then*. Reading configuration first would make the one command
        that could explain a role typo fail with the same error as the typo.
        """

        def _explode() -> Settings:
            raise ConfigurationError("configuration is broken")

        monkeypatch.setattr(worker_main, "get_settings", _explode)

        assert worker_main.run(["--list-roles"]) == 0
        assert FOUNDATION_ROLE in capsys.readouterr().out


class TestRoleResolution:
    def test_defaults_to_the_worker_roles_setting(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        run_cli_calls: list[list[str]],
    ) -> None:
        _use_settings(monkeypatch, override(settings, worker_roles="foundation"))

        assert worker_main.run([]) == 0
        assert run_cli_calls == [[FOUNDATION_ROLE]]

    def test_command_line_overrides_the_setting(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        run_cli_calls: list[list[str]],
    ) -> None:
        _use_settings(monkeypatch, override(settings, worker_roles="never-used"))

        assert worker_main.run([FOUNDATION_ROLE]) == 0
        assert run_cli_calls == [[FOUNDATION_ROLE]]

    def test_comma_separated_values_are_split_and_trimmed(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        run_cli_calls: list[list[str]],
    ) -> None:
        _use_settings(monkeypatch, settings)

        assert worker_main.run([f" {FOUNDATION_ROLE} , ,{FOUNDATION_ROLE} "]) == 0
        # Duplicates survive to the runtime: two roles with the same name is a
        # deployment mistake worth surfacing, not something the CLI should
        # silently collapse into a process that looks correct.
        assert run_cli_calls == [[FOUNDATION_ROLE, FOUNDATION_ROLE]]


class TestExitCodes:
    def test_unknown_role_exits_with_usage(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        run_cli_calls: list[list[str]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A misspelled role must not become a crash loop (§140)."""
        _use_settings(monkeypatch, settings)

        code = worker_main.run(["market-datta"])

        assert code == 2
        assert run_cli_calls == []
        assert "unknown worker role" in caplog.text
        # The valid names travel in `extra`, not the message text, so they are
        # read off the record's dict: an operator gets them in the structured
        # payload that the JSON formatter renders.
        extra = vars(caplog.records[-1])
        assert extra["requested"] == ["market-datta"]
        assert extra["available"] == sorted(available_roles())

    def test_empty_role_list_exits_with_usage(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        run_cli_calls: list[list[str]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _use_settings(monkeypatch, override(settings, worker_roles=" , "))

        assert worker_main.run([]) == 2
        assert run_cli_calls == []
        assert "no worker roles to run" in caplog.text

    def test_runtime_exit_code_is_propagated(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The runtime's own failure status must reach the orchestrator."""
        _use_settings(monkeypatch, settings)
        monkeypatch.setattr(worker_main, "run_cli", lambda roles=None: 1)

        assert worker_main.run([FOUNDATION_ROLE]) == 1

    def test_configuration_error_exits_with_config_code(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def _explode() -> Settings:
            raise ConfigurationError("DATABASE_URL must use PostgreSQL in staging/production")

        monkeypatch.setattr(worker_main, "get_settings", _explode)

        assert worker_main.run([FOUNDATION_ROLE]) == 78
        captured = capsys.readouterr()
        assert "configuration error" in captured.err
        assert "PostgreSQL" in captured.err
        # Nothing reached the logger: it was not configured yet.
        assert captured.out == ""


class TestConfigurationErrorSafety:
    def test_stderr_never_carries_a_database_password(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """§127/§133 — a misconfigured worker must not print its own secrets.

        This is the path where logging (and therefore redaction) is not yet
        installed, so it writes straight to stderr. The check that fails here is
        unrelated to the DSN, which makes it the realistic case: an operator
        flips ``LOG_FORMAT`` in production, the worker refuses to start, and the
        full connection string would land in a container log that is shipped to
        a third party.
        """
        kwargs: dict[str, Any] = {**production_kwargs(), "log_format": "console"}
        password = "a-real-db-password"

        def _explode() -> Settings:
            # Constructing for real proves the message arb_core.config produces
            # is the one that would actually be written.
            with pytest.raises(ConfigurationError) as excinfo:
                Settings(**kwargs)
            raise excinfo.value

        monkeypatch.setattr(worker_main, "get_settings", _explode)

        assert worker_main.run([FOUNDATION_ROLE]) == 78
        err = capsys.readouterr().err
        assert password not in err
        assert "sup3rs3cret" not in err
        assert kwargs["jwt_secret"] not in err
        assert kwargs["encryption_key"] not in err


class TestLoggingBootstrap:
    def test_logging_is_configured_from_settings_before_roles_start(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        logging_calls: list[dict[str, Any]],
    ) -> None:
        """§127 — no line may be emitted before the redacting formatter exists."""
        order: list[str] = []

        def _record(roles: Sequence[str] | None = None) -> int:
            order.append("run_cli")
            assert logging_calls, "configure_logging must have run before the runtime starts"
            return 0

        _use_settings(monkeypatch, override(settings, log_level="DEBUG", service_name="worker-x"))
        monkeypatch.setattr(worker_main, "run_cli", _record)

        assert worker_main.run([FOUNDATION_ROLE]) == 0
        assert order == ["run_cli"]
        assert logging_calls == [
            {
                "level": "DEBUG",
                "log_format": "json",
                "service": "worker-x",
                "redaction_enabled": True,
            }
        ]

    def test_not_configured_when_configuration_fails(
        self, monkeypatch: pytest.MonkeyPatch, logging_calls: list[dict[str, Any]]
    ) -> None:
        def _explode() -> Settings:
            raise ConfigurationError("nope")

        monkeypatch.setattr(worker_main, "get_settings", _explode)

        assert worker_main.run([FOUNDATION_ROLE]) == 78
        assert logging_calls == []


class TestEnvironmentReporting:
    def test_startup_line_names_environment_and_version(
        self,
        settings: Settings,
        monkeypatch: pytest.MonkeyPatch,
        run_cli_calls: list[list[str]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The first structured line identifies what started, where (§111)."""
        _use_settings(
            monkeypatch,
            override(settings, environment=Environment.TEST, app_version="9.9.9-test"),
        )

        # caplog defaults to WARNING; the startup line is INFO.
        with caplog.at_level(logging.INFO, logger="arb_worker.main"):
            assert worker_main.run([FOUNDATION_ROLE]) == 0

        assert "worker process starting" in caplog.text
        extra = vars(caplog.records[-1])
        assert extra["version"] == "9.9.9-test"
        assert extra["environment"] == "test"
        assert extra["roles"] == [FOUNDATION_ROLE]
