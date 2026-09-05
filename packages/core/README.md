# arb-core — shared foundation

Framework-agnostic primitives shared by the API and every worker.

| Module | Responsibility | Spec |
|---|---|---|
| `config` | Single source of environment configuration + production fail-closed validation | §89, §90 |
| `log` | Structured JSON logging with automatic secret redaction | §66, §127 |
| `context` | `contextvars` request/operation correlation (`request_id`, `trade_id`, …) | §66 |
| `errors` | Stable `ErrorCode` taxonomy + client-safe error payloads | §71, §77 |
| `identifiers` | UUIDv7 primary keys (time-ordered for index locality) | §82 |
| `clock` | UTC-only, timezone-aware time handling and staleness checks | §75, §79 |
| `money` | `Decimal` arithmetic; binary floating point is forbidden | §74 |
| `security.redaction` | Key- and pattern-based secret scrubbing | §12, §133 |
| `events` | Idempotent internal event envelope + in-process bus | §99 |
| `db` | Async SQLAlchemy engine/session, declarative base, portable types | §9, §63 |
| `redis` | Async Redis client, health probe, distributed locks | §64, §65 |
| `health` | Aggregated dependency health reporting | §78, §111 |
| `metrics` | Prometheus collector registry and standard metrics | §112 |
| `worker` | Worker runtime: role registry, heartbeat, graceful shutdown | §55 |

## Rules for contributing to this package

1. No framework imports (no FastAPI, no CCXT, no exchange names).
2. No imports from `apps/*` or other `packages/*` — `arb_core` is the root of the
   dependency graph and must stay acyclic.
3. Financial values are `Decimal`; timestamps are aware UTC.
4. Anything that can end up in a log must pass through `security.redaction`.
