# Implementation status

**Last updated:** 2026-09-05 · **Phase:** 1 — Foundation · **Branch:** `arena/01a07264-arbitrage`

This document is the authoritative answer to "what does this platform actually do
today?". [`OPERATIONS.md`](./OPERATIONS.md) is the companion: how to run,
migrate, back up, observe and maintain it — including the audit-log archival
procedure that the database trigger's own error message points to. Every capability is labelled with one of four statuses, and the label
describes *verified behaviour*, not intent:

| Status | Meaning |
| --- | --- |
| **IMPLEMENTED** | Real code, exercised by a test that runs in this repository, no stub on the path. |
| **PARTIALLY IMPLEMENTED** | Real code covering part of the requirement; the remainder is named explicitly below. |
| **MOCKED** | A stand-in exists that pretends to work. **Nothing in this repository is mocked.** |
| **NOT IMPLEMENTED** | Absent. Configuration keys or metric names may exist for it, but no behaviour does. |

> **No fake integrations.** There is no exchange adapter, no order execution path
> and no live-trading code in this repository at any level of completeness. Where
> a test needs Redis it uses `fakeredis`, and that is labelled as such in the test
> module docstring — it is a test double for a *cache*, never a simulation of an
> exchange.

---

## Quality gates (all green, verified locally)

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `uv run ruff check .` | All checks passed (strict rule set: `S`, `BLE`, `ASYNC`, `DTZ`, `TRY`, `TC`, …) |
| Format | `uv run ruff format --check .` | 92 files already formatted |
| Types | `uv run mypy packages apps tests` | Success: no issues in 89 files (`strict = true`, `warn_unreachable`, pydantic plugin) |
| Tests | `uv run pytest` | **1049 passed, 2 skipped** |

The 2 skips are the PostgreSQL-backed database and migration suites. They are
gated on `TEST_POSTGRES_URL` and **do run in CI**, which provides a real
`postgres:16` service container. CI additionally fails the build if it sees their
skip reason, so they cannot silently stop running.

Test distribution: `tests/unit` 336 · `tests/integration` 664 (+2 gated) ·
`tests/security` 49.

---

## Phase 1 — Foundation

### IMPLEMENTED

| Capability | Where | Notes |
| --- | --- | --- |
| Configuration & startup validation | `arb_core.config` | Pydantic v2 `Settings`; `SecretStr` for every credential; cross-field validator; `validate_deployed_environment()` refuses to start in staging/production with `DEBUG=true`, console logs, disabled redaction, SQLite, insecure cookies, weak/known secrets or a placeholder `ENCRYPTION_KEY`. |
| Secret masking in logs & repr | `arb_core.security.redaction`, `Settings.*_safe` | DSN password → `[REDACTED]` while host/database stay visible; credential-named keys redacted wholesale; `_safe` column suffix on audit payloads. |
| Structured logging | `arb_core.log` | JSON and console formatters, redaction on by default and force-enabled in production, request-id correlation, no uvicorn `dictConfig` clobbering. |
| Error taxonomy & client-safe envelopes | `arb_core.errors`, `arb_api.middleware.error_handlers` | `AppError` + `ErrorCode` → HTTP status map; every response is `{"error": {code, message, request_id[, details]}}`; validation errors strip pydantic's `input`/`ctx` so a mistyped field cannot echo a submitted password. |
| Database foundation | `arb_core.db` | SQLAlchemy 2.x async, one engine per process, `Decimal`-only money columns (`PreciseDecimal(38,18)`) that reject non-finite values on write, timezone-aware UTC datetime type, JSON type, naming convention for constraints. |
| Migrations | `packages/persistence/alembic`, `alembic.ini` | Revision `0001_platform_infrastructure`; URL resolved from settings (never committed); sync driver for online migration; compose runs it as a gating one-shot before the API starts. |
| Redis client & health probe | `arb_core.redis.client` | Async client, namespaced keys, latency-aware probe returning `ComponentCheck`. |
| Distributed lock | `arb_core.redis.locks` | SET NX PX with a unique token, Lua compare-and-delete release (no releasing someone else's lock), extension, async context manager, and a renewal task that exits rather than silently losing ownership. |
| Health & readiness | `arb_api.api.health`, `arb_api.services.health_service` | `/health/live` (always 200 if the process is up), `/health/ready` (503 on dependency failure), `/health` (per-component detail). Startup does **not** fail when dependencies are down, so the diagnostic endpoint survives the outage. |
| Prometheus metrics | `arb_core.metrics`, `arb_api.api.metrics` | Per-process registry (never the global default), 26 collectors namespaced `arb_`, request counter + latency histogram, unmatched paths collapsed to `_unmatched` so URL probing cannot inflate cardinality. Endpoint hidden with 404 when disabled, bearer-token protected with `secrets.compare_digest`. |
| Worker runtime | `arb_core.worker`, `arb_worker.main` | Role registry, per-role tasks, Redis heartbeat + expiring liveness key, staleness window, graceful shutdown on SIGTERM writing a final `status=stopped`, `arb-worker` CLI with `EX_USAGE`/`EX_CONFIG` exit discipline. |
| Feature flags | `arb_persistence.*.feature_flags`, `arb_api.services.feature_flag_service` | DB rows authoritative, env bootstrap defaults only, rollout percentage, `allowed_user_ids` fast-path, `require_enabled()` raising `FEATURE_DISABLED`. |
| Audit logging | `arb_persistence.*.audit`, `arb_api.services.audit_service` | Append-only table (UPDATE/DELETE blocked by trigger in the migration), unconditional redaction of payloads, `resource_id` stringified from UUID/int/str, four indexes matching the admin query patterns. |
| Security headers | `arb_api.middleware.security_headers` | CSP `default-src 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `Permissions-Policy`, `Cache-Control: no-store`, HSTS only when deployed. Applied to error envelopes directly as well, because an unhandled 500 is sent from outside the middleware stack. |
| Request context & correlation | `arb_api.middleware.request_context` | `X-Request-ID` (uuid7) generated or propagated, contextvar-scoped, access log with route template and latency, metrics observation. |
| Money arithmetic | `arb_core.money` | `Decimal` only; `to_decimal()` rejects `float` by default and rejects `bool`; precision profiles for price/amount/money/rate/percent. |

### PARTIALLY IMPLEMENTED

| Capability | What exists | What is missing |
| --- | --- | --- |
| Risk & trading safety gates | `LIVE_TRADING_ENABLED` and `GLOBAL_KILL_SWITCH_ENABLED` are validated, surfaced read-only at `/api/v1/system/info`, and combined with feature flags under a documented precedence (environment switch-off beats an enabled flag). Default limits (`DEFAULT_MAX_TRADE_USD=25`, `DEFAULT_MAX_DAILY_LOSS_USD=25`, `DEFAULT_MAX_CONCURRENT_TRADES=1`) are parsed and exposed. | No enforcement engine, no circuit breakers, no kill-switch activation flow, no per-bot limits, no exposure tracking. Phase 6. |
| Credential encryption | `ENCRYPTION_KEY` is validated as a usable Fernet key and rejected outright if it is the committed development value in a deployed environment; `ENCRYPTION_CONTEXT` binds ciphertext to a tenant/environment. | No encryption service, no `exchange_credentials` table, nothing is encrypted yet because nothing is stored yet. Phase 3. |
| Monitoring stack | `docker-compose.yml` defines Prometheus (bounded retention, bearer-token scrape, internal network only) and Grafana (anonymous access off, sign-up off, provisioned datasource + a 9-panel dashboard built from the real metric names). | Never executed — see *Not verified in this environment*. No alert rules, no alertmanager, no dashboards beyond the foundation one. Phase 13. |
| Reverse proxy | nginx configuration is written: `server_tokens off`, `/metrics` and `/docs` refused with 404, coarse `limit_req`, forwarded-headers wiring, WebSocket upgrade map, TLS template with HSTS. | Never executed. No real certificate provisioning, no application-level rate limiting (§76). Phase 13 / Phase 2. |
| CI/CD | `.github/workflows/ci.yml` defines six jobs: lock sync, lint, mypy, tests on Python 3.11 **and** 3.12 with real PostgreSQL and Redis service containers, image build with in-image smoke tests, and compose/nginx/prometheus/grafana configuration validation plus a committed-secret scan. | Never executed — no GitHub Actions run has happened from this environment. No deploy workflow, no registry push, no environment promotion. |

### NOT IMPLEMENTED

Absent by design at this phase. Listed so that nothing is assumed to exist:

* **Authentication & identity** — users, passwords (argon2id config keys exist, no hashing code), sessions, JWT issuing/refresh, MFA, CSRF. Phase 2.
* **RBAC** — the seven roles and granular permissions. Phase 2/9.
* **Exchange integrations** — Binance, OKX, Bybit, Coinbase, Kraken; the `ExchangeAdapter` interface; CCXT is not a dependency yet. Phase 3. **No exchange is contacted anywhere in this repository.**
* **Market data** — REST/WebSocket ingestion, order books, staleness enforcement, symbol/market metadata. Phase 4. Metric names exist; nothing increments them.
* **Arbitrage detection** — cross-exchange, triangular, stablecoin; opportunity model and TTL. Phase 5.
* **Paper trading** — simulated fills, paper portfolio, paper P&L. Phase 7.
* **Live trading** — order submission, idempotency keys, reconciliation. Phase 11. Gated behind three independent switches, none of which can currently be turned on because no order path exists.
* **Portfolio & P&L** — balances, positions, realized/unrealized P&L, history. Phase 8.
* **Backtesting** — engine, data snapshots, results. Phase 10.
* **Rebalancing** — recommendation-only analysis. Phase 12.
* **Notifications** — email (SMTP/SES), Telegram, in-app inbox. `EMAIL_PROVIDER=none` is the only working setting. Phase 8+.
* **Web frontend** — `apps/web/` contains no files. Phase 8.
* **Admin platform** — no admin API or UI. Phase 9.
* **Rate limiting** — application-level per-user/per-endpoint buckets. Only nginx's coarse zone exists. Phase 2.
* **Security monitoring** — `arb_security_events_total` is defined and never incremented; no anomaly detection, no login-failure tracking. Phase 9/13.

---

## Data model

One migration, `0001_platform_infrastructure`, creates four tables:

| Table | Purpose | Indexes |
| --- | --- | --- |
| `feature_flags` | Runtime feature gates; DB is authoritative over env defaults | `created_at`, `updated_at` |
| `audit_logs` | Append-only actor/resource/result history; UPDATE and DELETE blocked by a trigger | `actor_id+occurred_at`, `resource_type+resource_id`, `action+occurred_at`, `occurred_at` |
| `worker_heartbeats` | Durable worker liveness history (live detection reads Redis) | `role+last_heartbeat_at`, `last_heartbeat_at` |
| `system_health_snapshots` | Dependency health over time | `service+observed_at`, `observed_at` |

No user, order, balance, position or exchange-credential table exists yet.

---

## API surface

All responses are JSON; all failures use the standard error envelope.

| Method & path | Status | Purpose |
| --- | --- | --- |
| `GET /` | IMPLEMENTED | Service identity, version, entry points, trading-gate summary |
| `GET /health/live` | IMPLEMENTED | Liveness. 200 whenever the process can answer. |
| `GET /health/ready` | IMPLEMENTED | Readiness. 503 if PostgreSQL or Redis is unreachable, or before startup completes. |
| `GET /health` | IMPLEMENTED | Per-component detail. Emits exception *type* only — never a message, DSN or path. |
| `GET /metrics` | IMPLEMENTED | Prometheus text format. 404 when disabled; bearer token when configured. Excluded from OpenAPI. |
| `GET /api/v1/system/info` | IMPLEMENTED | Server clock, version, environment, demo mode, live-trading and kill-switch gates. |
| `GET /api/v1/system/workers` | IMPLEMENTED | Worker fleet liveness. Hostnames and PIDs are deliberately absent from this public view. |
| `GET /openapi.json`, `/docs`, `/redoc` | IMPLEMENTED | Served by the app; **refused with 404 at nginx** so the route surface is not public. |

No mutating route exists in Phase 1. `tests/security/test_endpoint_security.py`
asserts that `POST`, `PUT`, `PATCH` and `DELETE` against every public path return
404 or 405, so the read-only property cannot regress silently.

---

## Repository layout

```
packages/core          arb_core       4,435 lines · 22 modules
packages/persistence   arb_persistence  955 lines · 11 modules + alembic/
apps/api               arb_api        2,502 lines · 25 modules
apps/worker            arb_worker       151 lines · entrypoint only
apps/web               —              empty (Phase 8)
tests                  7,264 lines · 28 modules (unit / integration / security / support)
infrastructure/        docker-compose, Dockerfile, nginx, prometheus, grafana, scripts
.github/workflows/     ci.yml
```

Python: 3.11 locally (`.python-version`), 3.12 in the production image and in
CI. `requires-python = ">=3.11"`; mypy checks against 3.11 so the floor stays
honest, and CI runs the suite on both.

---

## Not verified in this environment

Stated plainly, because an unverified artefact that is described as working is
worse than one described as absent:

* **No Docker build or `docker compose up` has been executed.** The sandbox has
  no Docker daemon. The Dockerfile, compose file, nginx configuration,
  Prometheus configuration and Grafana provisioning are written to be correct
  and are syntax-validated where possible without a daemon (YAML/JSON parse, and
  CI validates `nginx -t` and `promtool check config`), but they have never
  started a container.
* **No CI run has been observed.** `.github/workflows/ci.yml` has not executed on
  GitHub Actions from here.
* **The PostgreSQL-backed suites have not run locally** (no server available).
  They pass structurally against SQLite where applicable and are env-gated; CI is
  the first place they meet a real server.
* **No exchange, no order and no money has ever been involved.** Nothing in this
  phase can trade.

---

## Defects found and fixed while bringing up the gates

Recorded because each one was a live failure mode, not a style complaint:

1. **`error_handlers` read `exc.status_code`, which does not exist.** `AppError`
   exposes `http_status`. Every current caller passes `status_code` explicitly so
   the branch was unreachable — but the first caller that did not would have
   raised `AttributeError` *inside* the error handler, replacing a clean JSON
   envelope with an opaque 500 at exactly the moment a client needed the real
   error. Found by mypy.
2. **Security headers were missing from the unhandled-exception 500.** Starlette
   installs `ServerErrorMiddleware` above every user middleware, so that response
   is sent from outside `SecurityHeadersMiddleware`. It was the one response the
   platform emitted with no CSP, no `nosniff` and no `Cache-Control: no-store`.
   The handlers now attach the platform header set themselves, so no error path
   depends on middleware ordering. Found by
   `tests/security/test_endpoint_security.py`.
3. **`AuditService.record` annotated `resource_id: str | None` while the
   implementation stringified UUIDs and ints.** The annotation lied about the
   contract its own test documented. Widened to `str | UUID | int | None`.
4. **`types-redis` was shadowing redis-py's own types.** The retired typeshed
   package's final release describes redis 4.6; installed alongside redis-py
   8.1.0 it made `Redis.aclose()` (added in 5.0.1) appear not to exist. The
   obvious "fix" would have been a `type: ignore[attr-defined]` — a suppression
   that hides every future real attribute error on the client. The dependency was
   removed instead.
5. **Feature-flag rollout ignored `allowed_user_ids` when a percentage gate
   closed.** An explicitly allow-listed user could be excluded by a 0% rollout.
   The allow-list is now an additive fast-path ahead of the percentage check, in
   both the model and the service.
6. **The audit repository used `select` without importing it**, so the §50
   timeline query raised `NameError` on first use.
7. **`arb-api`'s package manifest did not declare `arb-persistence` or
   `sqlalchemy`**, both of which it imports directly. It resolved only because
   the workspace happened to install them; a slimmed image would have failed at
   import time.
8. **`apps/worker` advertised an `arb-worker` console script whose module did not
   exist.** Installed but unrunnable.
