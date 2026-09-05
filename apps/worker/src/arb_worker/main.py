"""Worker process entrypoint (§55, §86, §140).

One process runs one or more *roles*. Roles are registered with
:func:`arb_core.worker.register_role`. Phase 1 ships ``foundation``, which keeps
a process alive so that heartbeats, staleness detection and graceful shutdown
can be verified end-to-end before any real job exists.

Run through the ``arb-worker`` console script::

    arb-worker                    # roles come from WORKER_ROLES
    arb-worker foundation         # explicit; a comma-separated list is accepted
    arb-worker --list-roles       # what this build can actually run

Logging is configured here rather than inside :mod:`arb_core.worker`, for the
same reason the API does it in :func:`arb_api.app.create_app`: nothing may emit
a line before the structured, redacting formatter is installed (§127).
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from arb_core.config import get_settings
from arb_core.errors import ConfigurationError
from arb_core.log import configure_logging, get_logger
from arb_core.worker import available_roles, run_cli

if TYPE_CHECKING:
    from collections.abc import Sequence

    from arb_core.config import Settings

__all__ = ["build_parser", "run"]

_logger = get_logger("arb_worker.main")

#: ``EX_USAGE`` from sysexits.h: the operator asked for something this build
#: cannot do. Kept distinct from ``EX_CONFIG`` and from an unhandled crash so a
#: restart policy can tell "will never succeed" from "might succeed next time"
#: — restarting a process with a misspelled role is a pure crash loop (§140).
_EXIT_USAGE = 2

#: ``EX_CONFIG``: the environment is not a configuration this platform will run
#: under. Raised by :meth:`Settings.validate_deployed_environment` for cases
#: such as SQLite or disabled redaction in production.
_EXIT_CONFIG = 78


def build_parser() -> argparse.ArgumentParser:
    """Build the ``arb-worker`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="arb-worker",
        description="Run one or more arbitrage platform worker roles.",
    )
    parser.add_argument(
        "roles",
        nargs="?",
        default=None,
        help=(
            "Comma-separated role names, for example 'foundation,market-data'. "
            "Defaults to the WORKER_ROLES setting."
        ),
    )
    parser.add_argument(
        "--list-roles",
        action="store_true",
        help="Print the roles registered in this build and exit.",
    )
    return parser


def _resolve_roles(raw: str | None, settings: Settings) -> list[str]:
    """Roles from the command line, else from ``WORKER_ROLES``."""
    if raw is not None:
        return [role.strip() for role in raw.split(",") if role.strip()]
    return settings.worker_role_list


def run(argv: Sequence[str] | None = None) -> int:
    """Start the worker process. Returns a process exit code.

    The console script hands this value to :func:`sys.exit`, so a failed
    dependency check produces a distinguishable status rather than a traceback.
    """
    args = build_parser().parse_args(argv)

    if args.list_roles:
        # T20 forbids print() in service code; this is the same channel, written
        # explicitly so the intent is unambiguous.
        sys.stdout.write("\n".join(available_roles()) + "\n")
        return 0

    try:
        settings = get_settings()
    except ConfigurationError as exc:
        # Logging is not installed yet on this path, so stderr is the only
        # available channel. The message is the configuration error itself,
        # which arb_core.config builds without ever interpolating a secret.
        sys.stderr.write(f"configuration error: {exc}\n")
        return _EXIT_CONFIG

    configure_logging(
        level=settings.log_level,
        log_format=settings.log_format.value,
        service=settings.service_name,
        redaction_enabled=settings.log_redaction_enabled,
    )

    roles = _resolve_roles(args.roles, settings)
    if not roles:
        _logger.error(
            "no worker roles to run; set WORKER_ROLES or pass roles on the command line",
            extra={"available": list(available_roles())},
        )
        return _EXIT_USAGE

    # Checked here rather than left to WorkerRuntime so the failure is a
    # structured log line and a clean exit code, not an exception escaping
    # asyncio.run() after the process has already announced itself as started.
    unknown = sorted(set(roles) - set(available_roles()))
    if unknown:
        _logger.error(
            "unknown worker role(s) requested",
            extra={"requested": unknown, "available": list(available_roles())},
        )
        return _EXIT_USAGE

    _logger.info(
        "worker process starting",
        extra={
            "roles": roles,
            "environment": settings.environment.value,
            "version": settings.app_version,
            "heartbeat_interval_seconds": settings.worker_heartbeat_interval_seconds,
            "stale_after_seconds": settings.worker_stale_after_seconds,
        },
    )
    return run_cli(roles)


if __name__ == "__main__":
    sys.exit(run())
