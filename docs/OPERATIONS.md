# Operations

**Phase 2 — Authentication, authorization & session management.** This document
describes how to run, migrate, observe and maintain what exists today. It does not
describe trading operations, because nothing in this repository can trade yet: see
[`STATUS.md`](./STATUS.md) for the authoritative capability list.

Everything here assumes the repository root as the working directory and `uv`
installed. Every routine action has a `make` target; the raw commands are shown
where they differ in a way that matters during an incident.

---

## 1. First run

```bash
make install    # create .venv from uv.lock (all workspace members)
make secrets    # generate .env from .env.example with strong random values
make doctor     # report toolchain versions and whether docker is available
make up         # build the image, run migrations, start the stack
```

`make secrets` refuses to overwrite an existing `.env`. That is deliberate: the
database has already been initialised with the old password, and rotating it in
`.env` alone leaves a stack that cannot connect. To rotate on purpose, re-run
with `--force` **and** change `POSTGRES_PASSWORD` inside the running container
(or recreate the volume in a development environment).

The generated file is mode `0600` and is git-ignored. Verify with `make env`.

| URL | What |
| --- | --- |
| `http://localhost/` | Platform identity (through nginx) |
| `http://localhost/health` | Dependency health |
| `http://127.0.0.1:8000/docs` | OpenAPI docs — **direct to the API**, because nginx refuses `/docs` with 404 |
| `http://127.0.0.1:8000/metrics` | Prometheus metrics — same reason |
| `http://127.0.0.1:9090` | Prometheus (loopback only) |
| `http://127.0.0.1:3001` | Grafana (loopback only) |

---

## 2. Routine commands

| Command | What it does |
| --- | --- |
| `make check` | The CI gate: lint, typecheck, full test suite. |
| `make test` | Full suite. PostgreSQL-backed tests **skip** unless `TEST_POSTGRES_URL` is set. |
| `make logs` | Follow `api`, `worker`, `migrate`. |
| `make ps` | Container state and health. |
| `make psql` | A `psql` shell inside the postgres container. |
| `make migrate` | `alembic upgrade head` against `DATABASE_MIGRATION_URL`. |
| `make migration m="…"` | Autogenerate a new revision. |
| `make backup` | Consistent `pg_dump` into `backups/`. |
| `make down` | Stop and remove containers. **Volumes survive.** |

---

## 3. Configuration

Precedence, lowest to highest: `.env.example` defaults compiled into
`arb_core.config` → dotenv files → process environment → (in compose) the
service's `environment:` block.

* Inside the compose network the database host is `postgres` and Redis is
  `redis`. A `.env` written for host-side tooling points both at `localhost`,
  which is why `docker-compose.yml` sets `DATABASE_URL`,
  `DATABASE_MIGRATION_URL` and `REDIS_URL` in `environment:` — that block wins
  over `env_file:`.
* `Settings` validates on construction. A production or staging configuration
  with `DEBUG=true`, console log format, disabled redaction, a SQLite URL,
  insecure cookies, or a known/placeholder secret **will not start**. This is a
  feature: a misconfigured financial service that starts is worse than one that
  refuses.
* Secrets are never logged. `database_url_safe` and `redis_url_safe` mask the
  password while keeping host and database visible, because an operator needs to
  know *which* database failed.

### Rotating `ENCRYPTION_KEY`

**No longer free.** Phase 2 stores `users.totp_secret_encrypted` as AES-256-GCM
ciphertext under this key, with the additional authenticated data `totp_secret`.
Changing the key without re-encrypting those rows leaves every enrolled
authenticator unverifiable: decryption fails, MFA verification fails, and the
accounts affected lose the second factor they were told to rely on.

Two ways to rotate, in order of preference:

1. **Re-encrypt in place.** Read each row, decrypt under the old key, encrypt
   under the new one, write back — in a transaction, with both keys available to
   the process for the duration. This is a script, not an environment-variable
   change, and it must be rehearsed against a copy of production first.
2. **Force re-enrolment.** Clear `totp_secret_encrypted`, `totp_confirmed_at` and
   `totp_last_used_step`, set `mfa_enabled = false`, and delete the account's
   `mfa_recovery_codes` rows. Simpler and harder to get wrong, visibly disruptive,
   and the only option when the old key is lost rather than merely compromised.

From Phase 3 onward every stored exchange credential is encrypted under the same
key, which turns rotation from a maintenance task into a project. Do not rotate it
in a deployed environment without a written, rehearsed procedure.

### Rotating `JWT_SECRET` and `SESSION_SECRET`

Both are safe to rotate, and both are disruptive in a specific, predictable way:

* **`JWT_SECRET`** signs access tokens. Rotating it invalidates every outstanding
  token at once — each fails signature verification — and clients recover on their
  next refresh, which needs no JWT secret. Expect a burst of 401s lasting up to
  `ACCESS_TOKEN_TTL_MINUTES` (15 by default) and no data loss.
* **`SESSION_SECRET`** signs CSRF tokens. Rotating it invalidates every CSRF
  cookie, and because `/refresh` requires a valid CSRF token, **every session
  becomes unrefreshable**: users are signed out when their access token expires
  and must sign in again. Nothing is corrupted; the server-side sessions stay
  valid and are simply not reachable without a fresh login.

Rotating either is a "schedule it, tell users, expect re-authentication" operation,
not a rolling-restart detail. Changing `JWT_ISSUER` or `JWT_AUDIENCE` has the same
effect with none of the benefit, which is also how a rotation can be forced without
changing a secret.

### When Redis is unreachable, sign-ins are refused

Every authentication rate-limit scope **fails closed**: with Redis down, `POST
/login`, `/register`, `/refresh`, `/mfa/login` and `/password/reset` are refused
rather than allowed unlimited attempts, and the refusal is logged at ERROR with the
driver's exception type. This is deliberate — a limiter that fails open during an
outage is a limiter that is off exactly when somebody is probing — but it means **a
Redis outage presents as "nobody can sign in"**, not as a cache problem. Access
tokens already issued keep working until they expire, because authentication reads
PostgreSQL rather than Redis. Restore Redis; do not relax the limiter.

`API_PER_USER` (600 requests/minute) is the exception: it fails **open**, loudly,
reporting `enforced=False`, because refusing all read traffic when a cache is down
trades an availability problem for a larger one.

---

## 4. Migrations

**Every schema change goes through Alembic, in every environment, including
development** (§44). A change made by hand in a `psql` shell is a change that
does not exist on the VPS, and the divergence surfaces during an incident.

```bash
make migration m="add orders table"   # autogenerate; REVIEW THE DIFF
make migrate                          # upgrade head
make migrate-down                     # downgrade one revision
uv run alembic history --verbose
```

Rules that are enforced rather than merely recommended:

* `alembic.ini` contains **no** connection URL. `env.py` resolves it from
  settings and raises if it cannot, rather than silently migrating the wrong
  database.
* Migrations run on the **sync** driver (`DATABASE_MIGRATION_URL`, `psycopg`).
  `async_engine_from_config` cannot accept a sync URL; using the async URL here
  fails at connect time.
* Enum columns inline their member values instead of importing the live enum. A
  migration describes the schema as it was when written; importing a class would
  retroactively change the DDL of an already-applied revision whenever a member
  is added.
* In compose, `migrate` is a one-shot service with `restart: "no"`, and `api`
  and `worker` depend on `service_completed_successfully`. A failed migration
  therefore stops the deployment instead of looping, because each retry could
  apply part of a revision.
* CI runs `upgrade → downgrade → upgrade` against a real PostgreSQL, and fails
  if the PostgreSQL-marked tests were skipped.
* DDL that PostgreSQL alone supports is guarded by `_is_postgresql()` — see
  `0003_totp_replay_guard`, which adds a CHECK constraint to an existing table.
  The same revision must run against PostgreSQL in CI and against SQLite in the
  local suite, and SQLite has no `ALTER TABLE … ADD CONSTRAINT`. Alembic's batch
  copy-and-move mode is deliberately **not** used instead: it cannot run in
  offline `--sql` mode without a live connection to reflect the table, and
  passing `copy_from` means restating every column of the table inside the
  revision, where an omitted column is one the copy silently drops.

**Review every autogenerated revision.** Autogenerate cannot see a semantic
change: it will not add a trigger, will not notice that a column needs a
backfill, and will happily emit a `DROP COLUMN` for a model attribute you
renamed by accident.

---

## 5. Audit log archival (the procedure the trigger points at)

`audit_logs` is append-only. Migration `0001` installs a PostgreSQL trigger that
raises on any `UPDATE` or `DELETE`, and the exception message directs the
operator here. The application has no code path that mutates or deletes an audit
row, so this procedure is the **only** supported way to remove one.

Use it for retention/compliance erasure only. It is destructive, it is manual,
and it must be recorded outside the table being modified — you cannot audit a
deletion inside the log you are deleting from.

### Preconditions

1. Written authorisation for the erasure (legal, compliance or a user request
   under a data-protection right), naming the exact time range or row keys.
2. A current backup: `make backup`, and confirm it validated.
3. Two operators — one to run it, one to read the commands before they execute.
4. A maintenance window. The `DELETE` takes a row lock per row and generates WAL.

### Procedure

```sql
-- 0. Connect as the table owner.
\c arbitrage

BEGIN;

-- 1. Establish exactly what will be removed, and write it down.
SELECT count(*), min(occurred_at), max(occurred_at)
FROM audit_logs
WHERE occurred_at < TIMESTAMPTZ '2026-01-01T00:00:00+00';

-- 2. Archive to a file OUTSIDE the database, and verify the copy.
\copy (SELECT * FROM audit_logs WHERE occurred_at < TIMESTAMPTZ '2026-01-01T00:00:00+00') TO '/tmp/audit-archive-20260101.csv' WITH CSV HEADER
COMMIT;

-- 3. Verify the archive before deleting anything. Row counts must match the
--    count from step 1. Move the file to durable, access-controlled storage.
--    If this step is skipped, the deletion is unrecoverable.

BEGIN;

-- 4. Disable ONLY the delete trigger, for this table, in this transaction.
ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_delete;

DELETE FROM audit_logs
WHERE occurred_at < TIMESTAMPTZ '2026-01-01T00:00:00+00';

-- 5. Re-enable immediately, in the same transaction, so a crash or a dropped
--    session cannot leave the table unprotected.
ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_delete;

COMMIT;

-- 6. Prove the guard is back. This MUST fail with the append-only exception.
DELETE FROM audit_logs WHERE id = (SELECT id FROM audit_logs LIMIT 1);
```

Step 6 is not optional. A trigger left disabled is an audit log that silently
accepts deletion, which is worse than no audit log: it produces false assurance.

### What not to do

* **Do not** use `SET session_replication_role = replica`. It disables *every*
  trigger on *every* table for the session, including foreign-key enforcement,
  so an unrelated mistake during the same session is no longer caught. Disabling
  the one named trigger is narrower and reversible in the same transaction.
* **Do not** `DROP TRIGGER`. Re-creating it later means writing DDL under
  pressure, and the window between drop and recreate is unprotected.
* **Do not** truncate. `TRUNCATE` is not blocked by a row-level trigger and
  removes the whole history.
* **Do not** script this. A procedure that runs unattended will eventually run
  with the wrong date.

Record the operation in your external change log: who authorised it, who ran it,
the row count from step 1, the archive location, and the confirmation from step 6.

### Test environments

SQLite has no portable equivalent of this procedural trigger, so the append-only
property is enforced there by the absence of any mutation path in
`AuditRepository` plus the security test-suite. Real enforcement is
PostgreSQL-only, which is why production never runs on SQLite
(`arb_core.config` refuses to start if it does).

---

## 6. Backup and restore

```bash
make backup                    # -> backups/arbitrage-<UTC>.dump (mode 600)
```

The script dumps with `pg_dump --format=custom` from inside the container (so the
client version matches the server), then **validates the archive with
`pg_restore --list`** and fails if it cannot be read. A dump that cannot be
restored is not a backup.

Restore — the command is printed at the end of every successful backup:

```bash
docker exec -i arbitrage-platform-postgres-1 pg_restore \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --clean --if-exists --no-owner < backups/arbitrage-20260101T000000Z.dump
```

`--clean --if-exists` drops and recreates the objects in the dump. Against a
live database this destroys anything written since the dump; do it only when
that is the intent.

**Redis is not backed up.** It holds cache, pub/sub and locks — never
authoritative data (§64). A cold Redis is the correct state after a restart, and
a *restored* Redis would resurrect locks nobody holds.

Off-host copies are the operator's responsibility: a backup on the same disk as
the database does not survive losing the disk.

---

## 7. Workers

A worker process runs one or more **roles**. Phase 1 registers exactly one:

| Role | Behaviour |
| --- | --- |
| `foundation` | Does no work. Stays alive so heartbeats, staleness detection and graceful shutdown are observable before any real job exists. |

```bash
arb-worker --list-roles        # what this build can run — works even if config is broken
arb-worker foundation          # explicit roles
arb-worker                     # roles from WORKER_ROLES
```

Exit codes are meaningful to a restart policy:

| Code | Meaning |
| --- | --- |
| `0` | Clean shutdown. |
| `1` | A role task failed. The runtime logs the exception type, shuts every role down, and exits. |
| `2` | `EX_USAGE` — no roles, or a role name this build does not have. Restarting will never help. |
| `78` | `EX_CONFIG` — the environment is not a configuration the platform will run under. |

`--list-roles` is answered **before** configuration is read, because the command
an operator needs when a worker will not start is the one that must not depend on
the configuration being valid.

### Liveness

Each role writes a Redis heartbeat hash every
`WORKER_HEARTBEAT_INTERVAL_SECONDS` and an expiring liveness key with a
`WORKER_STALE_AFTER_SECONDS` TTL. The hash persists after shutdown (with
`status=stopped`) so the last known state is inspectable; the expiring key is
what makes staleness observable without a scan. `/api/v1/system/workers` reads
them.

A worker is **stale** when its heartbeat is older than the window or its status
is terminal, regardless of age. Hostnames and PIDs are present in Redis and
deliberately absent from the public response.

On `SIGTERM` the runtime stops accepting work, lets roles unwind within a grace
period, writes the final heartbeat, deletes the liveness key, and closes only
the dependencies **it** constructed — an injected `Database` or `RedisClient`
belongs to whoever injected it. `stop_grace_period: 45s` in compose must stay
above `WORKER_STALE_AFTER_SECONDS`-adjacent work or the container is killed
mid-shutdown.

Adding a role: decorate a coroutine with `@register_role("name")` taking a
`WorkerContext`, then add the name to `WORKER_ROLES`. Registering the same name
twice raises — a silent override would mean the process runs different code than
the one operators believe is deployed.

---

## 8. Observability

### Health endpoints

| Path | Meaning | Use |
| --- | --- | --- |
| `/health/live` | The process can answer. 200 even when every dependency is down. | Container/orchestrator restart decisions. |
| `/health/ready` | Dependencies reachable and startup complete. 503 otherwise. | nginx routing, load-balancer membership. |
| `/health` | Per-component detail. | Humans and dashboards. |

Restarting a container because the *database* is down would take away the
endpoint an operator needs to diagnose the outage. That is why liveness and
readiness are separate and why startup does not fail on an unreachable
dependency.

`/health` emits an exception **type** only — never a message, DSN or file path —
so a dependency failure cannot become an information leak (§111).

### Metrics catalogue (§112)

26 collectors, all namespaced `arb_`, each bound to a per-process registry
(never the global default, so counts stay attributable to one service).

**Live in Phase 1** — something increments these today:

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `arb_api_requests_total` | Counter | `method`, `route`, `status` | Total HTTP requests handled by the API. |
| `arb_api_request_latency_seconds` | Histogram | `method`, `route`, `status` | HTTP request latency. |

**Defined, not yet incremented.** They exist so dashboards and alert rules do not
have to change shape when the phase that produces them lands. An empty panel is
honest; a missing one is discovered during an incident.

| Metric | Type | Labels | Meaning | Arrives |
| --- | --- | --- | --- | --- |
| `arb_workers_online` | Gauge | `role` | Workers whose heartbeat is fresh. | Phase 5 |
| `arb_worker_jobs_total` | Counter | `role`, `result` | Jobs processed by role. | Phase 4 |
| `arb_worker_failures_total` | Counter | `role`, `error_type` | Job failures by role and error type. | Phase 4 |
| `arb_queue_depth` | Gauge | `queue` | Pending items per queue. | Phase 4 |
| `arb_market_data_messages_total` | Counter | `exchange`, `feed`, `result` | Market-data messages received. | Phase 4 |
| `arb_market_data_latency_seconds` | Histogram | `exchange` | Exchange timestamp → local processing. | Phase 4 |
| `arb_market_data_age_seconds` | Histogram | `exchange` | Age of the newest order book (§79). | Phase 4 |
| `arb_opportunities_detected_total` | Counter | `strategy` | Opportunities detected. | Phase 5 |
| `arb_opportunities_rejected_total` | Counter | `strategy`, `reason` | Rejected before execution. | Phase 5 |
| `arb_opportunity_detection_latency_seconds` | Histogram | `strategy` | Update → opportunity emission. | Phase 5 |
| `arb_trades_started_total` | Counter | `mode`, `strategy` | Trades that entered execution. | Phase 7 |
| `arb_trades_completed_total` | Counter | `mode`, `strategy` | Trades reaching terminal success. | Phase 7 |
| `arb_trades_failed_total` | Counter | `mode`, `strategy`, `reason` | Failed trades, by reason. | Phase 7 |
| `arb_execution_latency_seconds` | Histogram | `mode`, `exchange` | End-to-end execution latency. | Phase 7 |
| `arb_orders_submitted_total` | Counter | `mode`, `exchange`, `side` | Orders submitted (or paper-simulated). | Phase 7 |
| `arb_orders_filled_total` | Counter | `mode`, `exchange` | Orders reaching FILLED. | Phase 7 |
| `arb_orders_rejected_total` | Counter | `mode`, `exchange`, `reason` | Rejected by exchange or pre-submission validation. | Phase 7 |
| `arb_risk_rejections_total` | Counter | `limit`, `scope` | Pre-trade risk rejections, by limit. | Phase 6 |
| `arb_circuit_breaker_events_total` | Counter | `breaker`, `state` | Circuit-breaker transitions. | Phase 6 |
| `arb_kill_switch_events_total` | Counter | `scope`, `action` | Kill-switch activations and clears. | Phase 6/9 |
| `arb_active_bots` | Gauge | `mode` | Bots in RUNNING state. | Phase 8 |
| `arb_open_trades` | Gauge | `mode` | Trades not yet terminal. | Phase 7 |
| `arb_notifications_sent_total` | Counter | `channel`, `result` | Notifications dispatched. | Phase 8 |
| `arb_security_events_total` | Counter | `category` | Security events, by category. | Phase 9 |

### Cardinality is a safety property

The `route` label carries the FastAPI **route template**
(`/api/v1/bots/{bot_id}`), never the concrete path. `arb_core.metrics.normalize_route`
enforces this, and a request that matched no route collapses to `_unmatched`.

Without that, an unauthenticated caller enumerating URLs creates one time series
per guess and eventually exhausts Prometheus memory — taking down monitoring for
the whole platform, which is the thing you need most while being scanned. A
sustained rise in `route="_unmatched"` is either a broken client or someone
probing; the foundation dashboard has a panel for exactly that.

**Never** put a user id, bot id, order id or symbol into a label.

### Scraping

`/metrics` is refused with **404** at nginx, so it is unreachable from outside
the host. Prometheus scrapes it over the internal compose network. When
`METRICS_AUTH_TOKEN` is set the endpoint requires `Authorization: Bearer <token>`
compared with `secrets.compare_digest` — a `==` comparison short-circuits on the
first differing byte and leaks token content through response timing.

Metrics reveal traffic shape, error rates and which exchanges are in use. That
is reconnaissance, which is why the endpoint is neither public nor unauthenticated
in production.

### Grafana

Datasource and dashboards are **provisioned from files in git**, not configured
through the UI. A dashboard built by clicking exists only on one host: it cannot
be reviewed, cannot be reverted, and is gone the moment the volume is recreated.

`Platform Foundation` (`infrastructure/docker/grafana/dashboards/platform-foundation.json`)
has nine panels: request rate, 5xx rate, p95 latency, security events/minute,
requests by status class, latency percentiles by route, unmatched-route rate,
worker jobs, and kill-switch events. Anonymous access and sign-up are disabled.

---

## 9. Security operations

* **No secret is committed.** `.env.example` and `.env.development` contain only
  obviously-fake development values, and `arb_core.config.KNOWN_INSECURE_SECRETS`
  lists them so a deployed environment refuses to start with any of them.
* **TLS is opt-in and off by default.** The mounted nginx configuration has no
  443 listener; an nginx that references an unmounted certificate fails to
  start, and a stack that cannot start in a fresh clone is worse than one that
  starts on port 80 and documents how to add TLS. See
  `infrastructure/docker/nginx/README.md`.
* **Loopback-only bindings.** PostgreSQL (5432), Redis (6379), Prometheus (9090)
  and Grafana (3001) publish on `127.0.0.1`. Remove those mappings entirely on a
  hardened VPS; the services reach each other over the internal networks.
* **Containers drop all capabilities** and set `no-new-privileges`. The
  application image runs as UID 10001 (`arb`) with a read-only root filesystem
  and a `/tmp` tmpfs.
* **Redis runs `noeviction`.** This is correctness, not tuning: a distributed
  lock is a Redis key, and an LRU policy would evict a held lock under memory
  pressure, silently destroying mutual exclusion and letting two processes trade
  the same opportunity. Failing a write is the safe outcome.
* **The audit log cannot be modified by the application.** See §5.
* **`make down` does not delete volumes.** Data survives a redeploy;
  `docker compose … down -v` is how you destroy it, and that is never in a
  Makefile target.
* **No credential is stored in a usable form.** Passwords are argon2id digests;
  refresh tokens, one-time tokens and recovery codes are stored only as SHA-256
  digests; the TOTP secret is AES-256-GCM ciphertext. A database dump is not a
  credential dump — and rotating `ENCRYPTION_KEY` is the one operation that turns
  those ciphertexts into a maintenance problem (§3).
* **`X-Forwarded-For` is believed only when `TRUST_PROXY_HEADERS=true` and the
  direct peer is listed in `FORWARDED_ALLOW_IPS`.** Behind nginx both must be set
  or every request is attributed to the proxy, which empties the per-IP rate
  limits and makes the audit log name nobody. Never set `FORWARDED_ALLOW_IPS=*` in
  a deployed environment: with `*`, any client chooses the address it is
  rate-limited and audited under.

### Account operations

The interventions an operator needs and, in Phase 2, must make by hand — there is
no administrative API yet (Phase 9). Each is a single statement against
PostgreSQL. None of them is recorded in `audit_logs`, because the platform only
audits actions it takes itself; write the intervention down wherever your incident
record lives.

* **Unlock an account** locked by five wrong passwords (fifteen minutes by
  default):

  ```sql
  UPDATE users SET failed_login_count = 0, locked_until = NULL,
                   last_failed_login_at = NULL
   WHERE email = lower('User@Example.com');
  ```

  `email` is stored lower-cased — a CHECK constraint enforces `email =
  lower(email)` — so lower-casing the *literal* rather than the column keeps the
  unique index usable.

  Read the `USER_LOGIN` failures in `audit_logs` first. If they all came from one
  address, the lock did its job and unlocking only invites the next round; if they
  came from the user's own address, they have forgotten their password and need a
  reset instead.
* **Sign a user out everywhere** (suspected compromise). The user can do this
  themselves with `POST /api/v1/auth/logout-all`; from the server side:

  ```sql
  UPDATE user_sessions
     SET status = 'REVOKED', revoked_at = now(), revoke_reason = 'ADMIN_REVOKED'
   WHERE user_id = '<uuid>' AND status = 'ACTIVE';
  ```

  `revoke_reason` is free text up to 64 characters. The application's own
  vocabulary is `USER_LOGOUT`, `USER_LOGOUT_ALL`, `PASSWORD_CHANGED`,
  `PASSWORD_RESET`, `TOKEN_REUSE` and `USER_INACTIVE`; use a distinct value for a
  hand-made revocation so the two are separable later. Access tokens stop working
  on the *next* request, because authentication re-reads the session row instead of
  trusting the token.
* **Force a password change at the next sign-in**: set `users.must_change_password =
  true`. `GET /api/v1/auth/me` returns it and a client is expected to route
  straight to the change form. An administrator **cannot set a password** for a
  user in this phase: there is no endpoint, and hand-writing an argon2id digest
  into the column is not a supported path.
* **Reset a user's MFA** when the phone is gone and the recovery codes are spent:

  ```sql
  UPDATE users SET totp_secret_encrypted = NULL, totp_confirmed_at = NULL,
                   totp_last_used_step = NULL, mfa_enabled = false
   WHERE id = '<uuid>';
  DELETE FROM mfa_recovery_codes WHERE user_id = '<uuid>';
  ```

  They re-enrol at their next sign-in. Verify who is asking before running this: it
  is exactly the action an account thief would request from support.
* **Read what an account has been doing**:

  ```sql
  SELECT occurred_at, action, result, resource_type, ip_address, user_agent,
         request_id
    FROM audit_logs
   WHERE actor_id = '<uuid>'
   ORDER BY occurred_at DESC
   LIMIT 200;
  ```

  Failures and denials are here too, and deliberately so: a refusal raises and
  rolls back its own transaction, so `AuditService.record_failure()` writes in a
  separate one. An audit log holding only successes would be a log of nothing
  anybody tried. A run of `result = 'DENIED'` against administrative permissions
  from an ordinary account is privilege-escalation probing until proved otherwise.

---

## 10. Troubleshooting

| Symptom | First thing to check |
| --- | --- |
| `api` restarts in a loop | `make logs`. A `ConfigurationError` on stderr means the environment is invalid, not that the database is down. |
| Nobody can sign in but `/health/live` is 200 | Redis. Authentication rate limits fail **closed**, so an unreachable Redis refuses `/login`, `/refresh`, `/mfa/login` and `/password/reset` — look for `rate_limit.fail_closed` at ERROR (§3). Issued access tokens still work; authentication reads PostgreSQL. |
| A user is signed out immediately after changing their password | Correct behaviour, and the response says so: `/password/change` revokes every session including the caller's and returns a replacement token set. A client that discards `tokens` from that response is signed out by design (`STATUS.md`, judgment call 1). |
| `/refresh` returns `CSRF_FAILED` with a valid refresh token | The `X-CSRF-Token` header must carry the value of the `arb_csrf` cookie for the *same* session. It is required even when the token is in the body, and it is checked before anything is mutated. |
| Refresh returns `SESSION_REVOKED` for a token that was just issued | Rotation is single-use: presenting a superseded token revokes the whole family, including the presenter's. Two clients sharing one session (or a retry after a timeout) look exactly like theft, and that is the point. |
| `migrate` exits non-zero and nothing starts | By design — `api` and `worker` wait for `service_completed_successfully`. Read `docker compose … logs migrate`. |
| `/health/ready` is 503 but `/health/live` is 200 | Correct behaviour. `/health` names the failing component and the exception *type*. |
| Worker shows as stale | Compare `last_heartbeat_at` in the Redis hash against `WORKER_STALE_AFTER_SECONDS`. Terminal statuses are always stale regardless of age. |
| `arb-worker` exits 2 | Role name typo, or `WORKER_ROLES` empty. `arb-worker --list-roles` shows what the build has — and works even when configuration is broken. |
| Grafana panel is empty | Check whether the metric is in the "defined, not yet incremented" table above. Only the two API metrics have data so far; authentication adds audit rows, not metrics. |
| Prometheus target down | `METRICS_AUTH_TOKEN` must match between compose's `environment:` for prometheus and the api service. An empty token means no auth. |
| nginx 502 | The API is not healthy. `make ps`, then `make api-logs`. |

---

## 11. Known operational limitations

* **The stack has never been started in the environment that produced it.** The
  sandbox has no Docker daemon. Compose, nginx, Prometheus and Grafana
  configuration are syntax-validated and CI runs `nginx -t` and
  `promtool check config`, but no container has run here. Treat the first
  `make up` as a commissioning step and read the logs.
* **No CI run has been observed.** The workflow is written; its first execution
  is the first evidence.
* **No alerting.** Prometheus records; nothing pages. Alert rules and
  Alertmanager are Phase 13.
* **No email delivery.** `EMAIL_PROVIDER=none` is the only working provider, so
  address verification and password reset return their token to the caller on a
  development environment and cannot complete at all on a deployed one. SMTP/SES
  arrive with notifications in Phase 8+; until then a deployed stack can create
  accounts nobody can verify.
* **No administrative API.** Every account operation above is a hand-written
  statement against PostgreSQL. User management, role assignment and a session
  view for support staff are Phase 9.
* **Rate limiting uses a fixed window.** Seven buckets are enforced atomically and
  the authentication scopes fail closed, but a fixed window admits up to twice the
  intended count across a boundary, and nothing coordinates with nginx's coarse
  10r/s zone.
* **No browser has exercised the cookie flow.** The endpoints are tested through
  the real ASGI application; `SameSite` behaviour, third-party-cookie blocking and
  redirect-after-login are browser decisions, unverified until Phase 8 ships a
  frontend.
* **Single-node.** One API replica, one worker, no queue, no leader election.
  The distributed lock is correct across processes and is exercised by tests, but
  nothing runs more than one worker yet.
* **No frontend.** `apps/web/` is empty; there is no UI to operate.
