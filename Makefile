# =============================================================================
#  Arbitrage platform — developer and operator entry points
# =============================================================================
#  `make check` is the gate: every target CI runs, in the same order. Nothing is
#  considered done until it passes (§147, §148).
#
#  Requires: uv (https://docs.astral.sh/uv/), and docker for the `up`/`down`
#  targets. Python itself is provisioned by uv from .python-version.
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

ROOT := $(shell pwd)
UV   ?= uv
# Explicit --env-file: the compose file lives in infrastructure/docker/, so
# compose would otherwise look for .env next to it rather than at the root.
COMPOSE := docker compose -f infrastructure/docker/docker-compose.yml --env-file $(ROOT)/.env

# ---------------------------------------------------------------------------
# Quality gates
# ---------------------------------------------------------------------------
.PHONY: check lint format typecheck test test-unit test-integration test-security coverage

check: lint typecheck test  ## Run every gate CI runs, in order.

lint:  ## Ruff lint + format check (no writes).
	$(UV) run ruff check .
	$(UV) run ruff format --check .

format:  ## Rewrite sources with ruff format and apply safe fixes.
	$(UV) run ruff check . --fix
	$(UV) run ruff format .

typecheck:  ## mypy, strict, over packages/ apps/ and tests/.
	$(UV) run mypy packages apps tests

test:  ## Full suite. PostgreSQL-backed tests skip unless TEST_POSTGRES_URL is set.
	$(UV) run pytest

test-unit:  ## Only tests/unit.
	$(UV) run pytest tests/unit -q

test-integration:  ## Only tests/integration.
	$(UV) run pytest tests/integration -q

test-security:  ## Only tests/security.
	$(UV) run pytest tests/security -q

coverage:  ## Full suite with a coverage report.
	$(UV) run pytest --cov --cov-report=term-missing

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
.PHONY: install secrets env doctor python-version

install:  ## Create/refresh the virtualenv from uv.lock (all workspace members).
	$(UV) sync --all-packages --group dev

secrets:  ## Generate .env from .env.example with strong random credentials.
	infrastructure/scripts/bootstrap-secrets.sh

env:  ## Print where configuration comes from, without printing secrets.
	@[[ -f .env ]] && echo ".env present" || echo ".env MISSING — run 'make secrets'"
	@[[ -f .env ]] && stat -c '%a %n' .env || true

doctor:  ## Verify the toolchain and report which optional services are reachable.
	@$(UV) --version
	@$(UV) run python -c "import sys; print(f'python {sys.version.split()[0]}')"
	@$(UV) run python -c "import fastapi, sqlalchemy, alembic, redis, pydantic; \
		print('fastapi', fastapi.__version__); print('sqlalchemy', sqlalchemy.__version__); \
		print('alembic', alembic.__version__); print('pydantic', pydantic.VERSION)"
	@command -v docker >/dev/null && docker --version || echo "docker: not installed (up/down/migrate unavailable)"

python-version:  ## Print the pinned local Python version.
	@cat .python-version

# ---------------------------------------------------------------------------
# Migrations (§44, §141) — never edit a schema by hand, in any environment
# ---------------------------------------------------------------------------
.PHONY: migration migrate migrate-down migration-history

migration:  ## Autogenerate a revision: make migration m="add orders table"
	@if [[ -z "$(m)" ]]; then echo "usage: make migration m=\"describe the change\"" >&2; exit 2; fi
	$(UV) run alembic revision --autogenerate -m "$(m)"

migrate:  ## Upgrade the configured database to head.
	$(UV) run alembic upgrade head

migrate-down:  ## Step back one revision.
	$(UV) run alembic downgrade -1

migration-history:  ## Show the revision chain.
	$(UV) run alembic history --verbose

# ---------------------------------------------------------------------------
# Stack
# ---------------------------------------------------------------------------
.PHONY: build up down restart ps logs api-logs worker-logs psql redis-cli backup

build:  ## Build the platform image.
	$(COMPOSE) build

up:  ## Build, migrate, then start the whole stack.
	$(COMPOSE) up -d --build
	@echo
	@$(COMPOSE) ps

down:  ## Stop and remove containers. Volumes (and therefore data) survive.
	$(COMPOSE) down

restart:  ## Restart the api and worker containers.
	$(COMPOSE) restart api worker

ps:  ## Container state and health.
	$(COMPOSE) ps

logs:  ## Follow the platform services.
	$(COMPOSE) logs -f --tail=100 api worker migrate

api-logs:  ## Follow the API container.
	$(COMPOSE) logs -f --tail=200 api

worker-logs:  ## Follow the worker container.
	$(COMPOSE) logs -f --tail=200 worker

psql:  ## Open a psql shell inside the postgres container.
	$(COMPOSE) exec postgres psql -U "$${POSTGRES_USER}" -d "$${POSTGRES_DB}"

redis-cli:  ## A redis-cli shell inside the redis container.
	$(COMPOSE) exec redis redis-cli

backup:  ## Consistent dump of the source of truth into backups/.
	infrastructure/scripts/backup-database.sh

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
.PHONY: clean clean-all help

clean:  ## Remove caches. Never touches .env or any volume.
	rm -rf .mypy_cache .ruff_cache .pytest_cache .coverage coverage.xml tmpfiles
	find . -type d -name __pycache__ -not -path "./.venv/*" -prune -exec rm -rf {} +

clean-all: clean  ## Also remove the virtualenv (recreated by `make install`).
	rm -rf .venv

help:  ## List every target with its description.
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
