# Arbitrage Platform

A production-grade, multi-user cryptocurrency arbitrage trading platform:
automated opportunity detection across exchanges, paper and controlled live
trading, a risk engine with hard limits and circuit breakers, portfolio and P&L
reporting, backtesting, and an RBAC-gated admin platform.

> **Current state: Phase 2 — Authentication, authorization & session management.**
> Nothing here can trade yet. There is no exchange integration, no order path and
> no web UI. What exists is the substrate every later phase is built on —
> configuration, structured logging with secret redaction, a Decimal-only
> persistence layer under Alembic, Redis with a distributed lock, health and
> metrics, a worker runtime with heartbeats, feature flags, an append-only audit
> log, the HTTP error/security envelope — plus, since Phase 2, real accounts:
> argon2id passwords, server-side sessions with refresh-token rotation and reuse
> detection, TOTP and single-use recovery codes, CSRF-protected cookie flows,
> account lockout, seven-role RBAC enforced per request, and rate limits that fail
> closed when Redis is unreachable. Nineteen endpoints under `/api/v1/auth`.
> Email *delivery* does not exist yet, so verification and reset tokens are
> returned to the caller on a development environment and labelled as such.
>
> **[`docs/STATUS.md`](docs/STATUS.md) is the authoritative capability list**,
> labelling every requirement IMPLEMENTED / PARTIALLY IMPLEMENTED / MOCKED /
> NOT IMPLEMENTED. Nothing in this repository is mocked.

---

## Non-negotiable principles

These are properties of the system, not aspirations. Each one is enforced in code
and asserted by a test **where the code that would violate it exists yet** — three
of them are marked below with the phase that makes them live, because a principle
written down ahead of the subsystem it governs is a design constraint, not a
guarantee, and calling it a guarantee would be exactly the kind of claim this
repository does not make. [`docs/STATUS.md`](docs/STATUS.md) carries the current
enforcement status of everything.

1. **Non-custodial.** The platform never holds user funds, never requests
   withdrawal permission, and never initiates a withdrawal. Exchange keys are
   trade-and-read scoped, encrypted at rest, and the encryption envelope is bound
   to a tenant context so a ciphertext cannot be replayed elsewhere. *The
   envelope, the validation and the tenant binding exist and are tested; the keys
   themselves arrive in Phase 3, and no withdrawal has ever been possible because
   no order path exists.*
2. **No live order without explicit activation.** Live trading is off by
   default and gated by three independent switches — a global configuration flag,
   a database feature flag, and a per-bot activation that is permission-gated and
   audited. Killing any one of them stops everything. *The first two switches are
   implemented, validated and surfaced read-only; per-bot activation arrives with
   live trading in Phase 11. There is no order path to activate today.*
3. **Money is `Decimal`, everywhere.** `float` is rejected at the conversion
   boundary (`arb_core.money.to_decimal`) rather than rounded later. Storage uses
   `NUMERIC(38,18)`; NaN and Infinity are refused on write.
4. **UTC, always.** Timezone-aware datetimes only; naive values are a type error.
5. **PostgreSQL is the source of truth.** Redis is cache, pub/sub and locks —
   never authoritative. A cold Redis is a correct Redis; a restored one would
   resurrect locks nobody holds.
6. **Every schema change is a migration.** No exceptions, including development.
7. **The audit log is append-only** — enforced by a database trigger, not by
   application discipline.
8. **Secrets are never logged, never returned, never committed.** Redaction is on
   by default and cannot be disabled in a deployed environment.
9. **Trading operations are idempotent.** A retried request must not produce a
   second order. *Phase 11. The pattern is already in use where it matters today:
   refresh-token rotation and one-time auth tokens are single-use by construction,
   and `IDEMPOTENCY_CONFLICT` is defined in the error taxonomy.*
10. **Honest labelling.** No fake integrations, no simulated exchange described
    as a real one, no claim of execution without an exchange confirmation.

---

## Quickstart

Requires [`uv`](https://docs.astral.sh/uv/) and Docker.

```bash
make install    # virtualenv from uv.lock
make secrets    # generate .env with strong random credentials (mode 0600)
make check      # lint + mypy strict + full test suite
make up         # build the image, run migrations, start the stack
```

Then: <http://localhost/> for service identity, <http://localhost/health> for
dependency health. OpenAPI docs and `/metrics` are served by the API on
`127.0.0.1:8000` and deliberately refused with 404 at nginx.

Sign up and sign in against a development stack — `EMAIL_PROVIDER=none` returns
the verification token in the response, because no email sender exists yet:

```bash
curl -sX POST localhost:8000/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct-horse-battery-42","display_name":"You"}'
# 201 -> {"user":{"role":"TRADER","status":"PENDING_VERIFICATION",...},
#         "requires_email_verification":true,"message":"...","dev_verification_token":"ev_..."}

curl -sX POST localhost:8000/api/v1/auth/email/verify \
  -H 'content-type: application/json' -d '{"token":"ev_..."}'
# 200 -> {"message":"Email address confirmed. You can sign in now.","code":null}

curl -siX POST localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct-horse-battery-42"}'
# 200 -> {"user":{...},"tokens":{"access_token":"...","refresh_token":"rt_...",
#         "csrf_token":"...","token_type":"bearer","expires_in":900,"session_id":"..."}}
# Set-Cookie: arb_refresh=rt_...; HttpOnly; Path=/api/v1/auth; SameSite=lax
# Set-Cookie: arb_csrf=...;             Path=/api/v1/auth; SameSite=lax
```

`dev_verification_token` (and `dev_reset_token`) appear only when
`EMAIL_PROVIDER=none` on an environment that is neither staging nor production; on a
deployed stack they are `null`, because nothing sends the email yet. Both cookies are
path-scoped to `/api/v1/auth`, and only the refresh one is `HttpOnly` — the CSRF
cookie has to be readable for a double-submit check to work at all.
`POST /api/v1/auth/refresh` requires that CSRF token echoed in the `X-CSRF-Token`
header **even when the refresh token is sent in the body**: a cross-site form can post
JSON under `text/plain` without provoking a CORS preflight, so a token arriving in the
body is not proof of same-origin intent. Every endpoint is listed in
[`docs/STATUS.md`](docs/STATUS.md#api-surface).

Without Docker, the Python services still run against a local PostgreSQL and
Redis:

```bash
make migrate
uv run arb-api
uv run arb-worker foundation
```

---

## Architecture

```
apps/
  api/        arb_api        FastAPI: versioned REST, health, metrics, middleware,
                             authentication endpoints, services and dependencies
  worker/     arb_worker     Role-based background processes with heartbeats
  web/        —              Next.js frontend (Phase 8; currently empty)
packages/
  core/       arb_core       Configuration, logging, errors, money, clock, identity,
                             database, Redis + locks, health, metrics, events, worker,
                             and the security primitives: password hashing and policy,
                             TOTP, tokens, AES-GCM envelope, CSRF, rate limiting, RBAC
  persistence/arb_persistence ORM models, repositories, Alembic migrations
infrastructure/
  docker/     Dockerfile, docker-compose.yml, nginx/, prometheus/, grafana/
  scripts/    bootstrap-secrets.sh, backup-database.sh
tests/        unit/ integration/ security/ support/
docs/         STATUS.md (capability ledger), OPERATIONS.md (runbook)
```

Dependency direction is one-way: `apps/*` → `packages/persistence` →
`packages/core`. Nothing in `packages/` imports from `apps/`, which is what makes
the worker and the API share models without sharing a process.

**Request path.** nginx terminates the public listener, refuses paths nobody
should reach, and proxies to the API. `RequestContextMiddleware` (outermost)
assigns a uuid7 request id, logs the route template and latency, and observes
metrics. `SecurityHeadersMiddleware` attaches the platform header set. Handlers
raise typed `AppError`s that the exception handlers turn into a client-safe
envelope — and, because Starlette's `ServerErrorMiddleware` sits above every user
middleware, the handlers attach those headers themselves so an unhandled 500 is
not the one response that escapes them.

**Worker path.** `WorkerRuntime` owns dependency construction, one task per role,
a heartbeat loop writing to Redis, and a graceful shutdown on SIGTERM that
records a final `status=stopped`. `arb-worker` is the CLI: it configures logging
before anything can emit a line, resolves roles, and exits with a code that tells
a restart policy whether retrying could ever help.

---

## Development

| Command | Effect |
| --- | --- |
| `make check` | The CI gate: `ruff check`, `ruff format --check`, `mypy` strict, `pytest`. |
| `make lint` / `make format` | Lint, and rewrite. |
| `make typecheck` | mypy strict over `packages/`, `apps/`, `tests/`. |
| `make test` | Full suite (1710 tests). |
| `make migration m="…"` | Autogenerate an Alembic revision. |
| `make migrate` | `alembic upgrade head`. |
| `make doctor` | Toolchain versions and docker availability. |

Full target list: `make help`. Runbook: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

Tooling is configured once, at the workspace root, and inherited: Ruff with a
strict production rule set (bandit, blind-except, async, timezone, type-checking
imports), mypy `strict = true` with `warn_unreachable` and the pydantic plugin,
and pytest with `--strict-markers`, `--strict-config` and warnings-as-errors.

Python 3.11 is the declared floor (`.python-version`) and what local development
runs; the production image and CI use 3.12, and CI runs the suite on both.

---

## Testing

```
tests/unit          856   isolated: money, clock, config, errors, events, logging,
                          pagination, redaction, identifiers, passwords, TOTP,
                          tokens, CSRF, rate limiting, RBAC
tests/integration   808   database, migrations, health, system endpoints, Redis
                          locks, feature flags, audit, worker runtime and CLI,
                          metrics endpoint, the 59-test authentication suite
                          driving the real ASGI application, and 8 tests holding
                          docs/STATUS.md to the routes and error codes it
                          documents (+3 PostgreSQL-gated)
tests/security       49   endpoint invariants: error-envelope safety, universal
                          security headers, metrics access control, CORS, and that
                          the Phase 1 observability surface exposes no write path
```

The three gated tests are the PostgreSQL-backed database and migration suites.
They skip locally without `TEST_POSTGRES_URL` and **run in CI**, which provides
real `postgres:16` and `redis:7` service containers — and CI fails if it sees
their skip reason, so they cannot quietly stop running.

Redis tests use `fakeredis` (with `lupa`, so the Lua compare-and-delete in the
distributed lock executes for real rather than being mocked away). That is a test
double for a cache; nothing anywhere simulates an exchange.

---

## Roadmap

Phases are implemented one at a time, in order, each ending with tests, lint,
typecheck and a status report before the next begins.

| # | Phase | Status |
| --- | --- | --- |
| 1 | Foundation | **Complete** — see `docs/STATUS.md` |
| 2 | Authentication, users, sessions, RBAC | **Complete** — see `docs/STATUS.md` |
| 3 | Exchange integrations (read-only) | Not started |
| 4 | Market data & order books | Not started |
| 5 | Arbitrage detection | Not started |
| 6 | Risk engine, circuit breakers, kill switches | Not started |
| 7 | Paper trading | Not started |
| 8 | User dashboard & frontend | Not started |
| 9 | Admin platform | Not started |
| 10 | Backtesting | Not started |
| 11 | Controlled live trading | Not started |
| 12 | Rebalancing (recommendation-only) | Not started |
| 13 | Monitoring & production infrastructure | Not started |
| 14 | Final security and correctness audit | Not started |

---

## Security

Report a vulnerability privately rather than opening a public issue. This
platform is designed to hold exchange API credentials and to place orders; a
disclosed-in-public flaw is an immediately exploitable one.

Licensed proprietarily. See `pyproject.toml`.
