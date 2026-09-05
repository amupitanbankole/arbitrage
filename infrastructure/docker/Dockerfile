# syntax=docker/dockerfile:1.7
# =============================================================================
#  Arbitrage platform — API and worker image (§86, §88)
# =============================================================================
#  One image, two entrypoints. The API (`arb-api`) and the worker
#  (`arb-worker`) share an identical dependency set and code base, and shipping
#  them from a single build means the process serving traffic and the process
#  writing heartbeats cannot drift onto different library versions — which is
#  exactly how a heartbeat format stops matching the reader that parses it.
#
#  Build from the repository root:
#      docker build -f infrastructure/docker/Dockerfile -t arbitrage-platform .
#
#  The compose file selects the entrypoint per service with `command:`.
# =============================================================================

# --- Stage 1: resolve and install dependencies -------------------------------
FROM python:3.12-slim AS builder

# uv is copied from its published image rather than pip-installed: the version is
# pinned by digest-able tag, and no resolver is needed to obtain the resolver.
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    # Never download an interpreter: the base image provides one, and a build
    # that fetches Python from the network is not reproducible.
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# The lock file is the contract: --frozen refuses to build if it disagrees with
# any pyproject.toml, so an image can never be produced from an unlocked
# dependency graph.
COPY pyproject.toml uv.lock README.md ./
COPY packages/core/pyproject.toml packages/core/README.md packages/core/
COPY packages/persistence/pyproject.toml packages/persistence/README.md packages/persistence/
COPY apps/api/pyproject.toml apps/api/
COPY apps/worker/pyproject.toml apps/worker/

# Source is copied after the dependency metadata so that editing application
# code does not invalidate the (slow) resolution layer.
COPY packages/core/src packages/core/src
COPY packages/persistence/src packages/persistence/src
COPY packages/persistence/alembic packages/persistence/alembic
COPY apps/api/src apps/api/src
COPY apps/worker/src apps/worker/src
COPY alembic.ini ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --all-packages --no-dev

# --- Stage 2: runtime --------------------------------------------------------
FROM python:3.12-slim AS runtime

# `apt` is deliberately not used: the image needs no system packages, and every
# package added is another CVE surface on a host that holds exchange API keys.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    VIRTUAL_ENV=/app/.venv

WORKDIR /app

# Created before any COPY so the files below are owned by it, not by root.
RUN groupadd --gid 10001 arb \
    && useradd --uid 10001 --gid arb --shell /usr/sbin/nologin --create-home arb

COPY --from=builder --chown=arb:arb /app /app

USER arb

# Unprivileged port, so the container can run without CAP_NET_BIND_SERVICE and
# nginx terminates the public listener (§87, §88).
EXPOSE 8000

# No shell form: an ENTRYPOINT of `arb-api` would make the image single-purpose.
# Compose sets `command:` per service, and a plain exec form keeps PID 1 as the
# Python process so SIGTERM reaches it directly — which is what makes the
# graceful shutdown in arb_core.worker actually run (§140).
CMD ["arb-api"]
