# arb-persistence — ORM models, repositories, migrations

PostgreSQL is the source of truth for every financial and audit record (§64).
This package owns that schema and is the only place ORM models are defined.

## Why this package exists

The suggested layout (§8, §115) places `models/` and `repositories/` inside
`apps/api`. That works while the API is the only process that touches the
database, but from Phase 4 onward the market-data, arbitrage, execution,
rebalancing and notification workers all read and write the same tables
(`worker_heartbeats`, `order_books`, `orders`, `pnl_records`, `audit_logs`).

Leaving models in `apps/api` would then force every worker to import the FastAPI
application package — pulling a web framework, its middleware and its routes into
processes that never serve HTTP, and creating a dependency from the worker tier
into the API tier. Models therefore live in their own workspace package that
both tiers depend on:

```
apps/api  ─┐
           ├──>  packages/persistence  ──>  packages/core
apps/worker┘
```

The API keeps `schemas/` (Pydantic request/response contracts), `services/` and
`api/` routers per §115; only persistence moves here.

## Contents

| Path | Purpose | Spec |
|---|---|---|
| `models/enums.py` | Portable enum column helper + status vocabularies | §9 |
| `models/audit.py` | Append-only audit log | §53 |
| `models/feature_flags.py` | Database-driven feature flags | §58, §110 |
| `models/observability.py` | Worker heartbeats, system health snapshots | §10, §54, §55 |
| `repositories/` | Query/write objects — the only code that builds SQL | §114, §115 |
| `alembic/` | Migrations. Every schema change requires one | §9, §141 |

## Conventions

* **No `Float` anywhere.** Monetary columns use `arb_core.db.PreciseDecimal`.
* **No naive timestamps.** All datetimes use `arb_core.db.UTCDateTime`.
* **Enums are `VARCHAR` + `CHECK`, not native PostgreSQL enums.** Adding a value
  to a native enum needs `ALTER TYPE`, which is not transactional on older
  PostgreSQL releases and cannot be reverted by a downgrade migration. A CHECK
  constraint is ordinary DDL, migrates cleanly in both directions, and behaves
  identically on SQLite so the test-suite exercises the real schema (§141).
* **Repositories, not raw queries in services.** Routers and services never
  construct SQLAlchemy statements; that keeps query logic testable in one place
  and stops N+1 patterns from spreading (§114).
* **Append-only tables have no `updated_at` and no soft delete** — `audit_logs`
  in particular (§53, §83).
