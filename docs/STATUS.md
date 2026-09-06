# Implementation status

**Last updated:** 2026-09-06 · **Phase:** 2 — Authentication, authorization & session
management · **Branch:** `arena/01a07264-arbitrage`

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
| Format | `uv run ruff format --check .` | 124 files already formatted |
| Types | `uv run mypy packages apps tests` | Success: no issues in 116 files (`strict = true`, `warn_unreachable`, pydantic plugin) |
| Tests | `uv run pytest` | **1710 passed, 3 skipped** |

The 3 skips are the PostgreSQL-backed database and migration suites. They are
gated on `TEST_POSTGRES_URL` and **do run in CI**, which provides a real
`postgres:16` service container. CI additionally fails the build if it sees their
skip reason, so they cannot silently stop running.

Test distribution (collected): `tests/unit` 856 · `tests/integration` 808 (+3
gated) · `tests/security` 49. Phase 2 added 660 tests: 59 driving the
authentication endpoints through the real ASGI application, and 8 holding this
document to the code it describes.

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
| Request context & correlation | `arb_api.middleware.request_context` | `X-Request-ID` (uuid7) generated or propagated, contextvar-scoped, access log with the full route template and latency, metrics observation. |
| Money arithmetic | `arb_core.money` | `Decimal` only; `to_decimal()` rejects `float` by default and rejects `bool`; precision profiles for price/amount/money/rate/percent. |

### PARTIALLY IMPLEMENTED

| Capability | What exists | What is missing |
| --- | --- | --- |
| Risk & trading safety gates | `LIVE_TRADING_ENABLED` and `GLOBAL_KILL_SWITCH_ENABLED` are validated, surfaced read-only at `/api/v1/system/info`, and combined with feature flags under a documented precedence (environment switch-off beats an enabled flag). Default limits (`DEFAULT_MAX_TRADE_USD=25`, `DEFAULT_MAX_DAILY_LOSS_USD=25`, `DEFAULT_MAX_CONCURRENT_TRADES=1`) are parsed and exposed. | No enforcement engine, no circuit breakers, no kill-switch activation flow, no per-bot limits, no exposure tracking. Phase 6. |
| Credential encryption | `ENCRYPTION_KEY` is validated as a usable Fernet key and rejected outright if it is the committed development value in a deployed environment; `ENCRYPTION_CONTEXT` binds ciphertext to a tenant/environment. | No encryption service, no `exchange_credentials` table, nothing is encrypted yet because nothing is stored yet. Phase 3. |
| Monitoring stack | `docker-compose.yml` defines Prometheus (bounded retention, bearer-token scrape, internal network only) and Grafana (anonymous access off, sign-up off, provisioned datasource + a 9-panel dashboard built from the real metric names). | Never executed — see *Not verified in this environment*. No alert rules, no alertmanager, no dashboards beyond the foundation one. Phase 13. |
| Reverse proxy | nginx configuration is written: `server_tokens off`, `/metrics` and `/docs` refused with 404, coarse `limit_req`, forwarded-headers wiring, WebSocket upgrade map, TLS template with HSTS. | Never executed, and no real certificate provisioning. (Application-level rate limiting has since arrived — see Phase 2 below.) Phase 13. |
| CI/CD | `.github/workflows/ci.yml` defines six jobs: lock sync, lint, mypy, tests on Python 3.11 **and** 3.12 with real PostgreSQL and Redis service containers, image build with in-image smoke tests, and compose/nginx/prometheus/grafana configuration validation plus a committed-secret scan. | Never executed — no GitHub Actions run has happened from this environment. No deploy workflow, no registry push, no environment promotion. |

### NOT IMPLEMENTED

Absent by design at this phase. Listed so that nothing is assumed to exist:

* ~~**Authentication & identity**~~ — **delivered in Phase 2**, see below: users, argon2id/bcrypt hashing, server-side sessions, JWT access tokens, refresh rotation, TOTP + recovery-code MFA, CSRF.
* ~~**RBAC**~~ — **delivered in Phase 2**: the seven roles, granular permissions and a `require_permission()` dependency that audits denials. The administrative endpoints it will protect arrive in Phase 9.
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
* ~~**Rate limiting**~~ — **delivered in Phase 2**: seven named buckets enforced by an atomic Lua script, with authentication scopes failing closed. nginx's coarse zone is unchanged.
* **Security monitoring** — partly delivered: login failures, lockouts, MFA refusals and permission denials are now written to `audit_logs` with actor, IP and user agent. `arb_security_events_total` is still never incremented, and there is no anomaly detection or alerting. Phase 9/13.

---

## Phase 2 — Authentication, authorization & session management

### IMPLEMENTED

| Capability | Where | Notes |
| --- | --- | --- |
| Password hashing | `arb_core.security.passwords` | argon2id (default) or bcrypt, both parameterised from settings. `needs_rehash()` so a cost increase is applied on the next successful login rather than by forcing a reset. `verify_unknown_account()` burns a full verification when no user matches, so response *timing* does not enumerate accounts either. `normalize_password()` NFKC-normalises, strips and caps length before hashing, so what is verified is what the policy checked; bcrypt input is truncated at 72 bytes explicitly instead of silently. |
| Password policy | `PasswordPolicy` | 12–128 characters; non-whitespace required; a byte cap that exists only when the configured scheme has one (bcrypt's 72); refusal of a single repeated character; a local screen against 43 commonly-chosen passwords — including `arbitrage`, `changeme` and `administrator`; and refusal of a password containing the account's own email address, its local part, or its display name, when either identifier is at least four characters. Rejections raise `PasswordPolicyError` carrying every problem at once, so a client can say *which* rules failed without the server weakening any of them, and no reason echoes the password back. `describe()` publishes the policy for a sign-up form **including the three checks this platform does not perform** — character classes, periodic expiry, breached-corpus screening — so a client cannot assume them (judgment call 11). |
| TOTP (RFC 6238) | `arb_core.security.totp` | SHA-1 / 30 s / 6 digits by default, all configurable; ±1 step drift; `provisioning_uri()` for QR enrolment. Checked against the RFC's published vectors and cross-checked with `pyotp` — no expected value in this repository's tests was written from memory. |
| TOTP replay guard | `users.totp_last_used_step`, migration `0003` | The last accepted time step is recorded and any step `<=` it is refused: RFC 6238 §5.2's "MUST NOT accept the second attempt of the OTP". Without it the three-step drift window keeps a code that was seen once — over a shoulder, or typed into a phishing page — spendable for over a minute. Enrolment and disabling clear it, so a code cannot be rejected as a replay of one accepted under a different secret. |
| Recovery codes | `arb_core.security.totp`, `mfa_recovery_codes` | Ten single-use codes from `secrets`, stored as SHA-256 digests and consumed atomically. Enrolment replaces the previous set, so codes left over from an abandoned enrolment cannot be spent later. |
| JWT access & challenge tokens | `arb_core.security.tokens` | HS256 with `iss`/`aud`/`exp`/`iat`/`jti` and a `type` claim separating an access token from a five-minute MFA challenge. `decode()` requires the expected type, so a challenge token cannot be presented where an access token is wanted — it carries no role and reaches only the second-factor endpoints. |
| Opaque refresh tokens | `arb_core.security.tokens` | 256-bit url-safe random values, stored only as SHA-256 digests under a unique constraint. A database leak yields no usable credential. |
| CSRF double-submit | `arb_core.security.csrf` | The CSRF cookie is an HMAC of the session id under `SESSION_SECRET`; verification returns `False` for an unknown session, so a token cannot be minted for a session that does not exist. Required on `/refresh` **unconditionally** — judgment call 3. |
| Rate limiting | `arb_core.security.ratelimit` | Seven buckets enforced by one atomic Lua script, so there is no check-then-act race between concurrent requests. Authentication scopes **fail closed**: with Redis unreachable the request is refused rather than allowed unlimited. `API_PER_USER` (600/min) fails **open**, loudly, returning `enforced=False`, because refusing all read traffic when a cache is down trades an availability problem for a larger one. A failed `reset()` is logged and never fails a successful login. |
| RBAC | `arb_core.security.rbac` | Seven roles — OWNER, ADMIN, COMPLIANCE_OFFICER, RISK_MANAGER, TRADER, SUPPORT_AGENT, VIEWER — mapped to granular permissions by `permissions_for()`. Owner-only, public and self-service permission sets are explicit constants rather than scattered conditionals. `require_permission()` reads the caller's current role from the database on every request and audits refusals as `DENIED`, so demotion takes effect immediately and a run of denials against an administrative permission is visible as probing. |
| Account lockout | `users.failed_login_count`, `users.locked_until` | Five wrong passwords lock the account for fifteen minutes, and the check runs *before* verification so a locked account cannot be used to make the platform perform unbounded argon2 work. |
| Session lifecycle | `arb_api.services.session_service` | Issue, authenticate, rotate, revoke, revoke-all, list. Every authentication re-reads the session row **and** the account row it points at: revocation ends a session immediately rather than after up to fifteen more minutes of token validity, a role change applies on the next request, and a password change invalidates every session established before it. Both the idle timeout and the absolute deadline are enforced, and a rotation inherits the family's deadline instead of renewing it — otherwise refreshing every fifteen minutes would produce a session that never ends and `SESSION_TTL_HOURS` would be decoration. |
| Refresh rotation & theft detection | `user_sessions.family_id` | Each rotation supersedes the previous token. Presenting a superseded one revokes the **whole family**, including the presenter's own token, because reuse means two parties hold the same credential and nothing server-side can say which is the owner. |
| MFA enrolment & verification | `arb_api.services.mfa_service` | Enrol → confirm (proving possession of the secret) → active; cancel discards a pending enrolment; disable re-authorises with the current password. Verification dispatches on the *shape* of the submitted code rather than trying both factors: trying both would double an attacker's guesses per request and could spend a recovery code on a request that meant to send a TOTP code. |
| Password change & reset | `arb_api.services.password_service` | Change requires the current password, applies the policy, revokes every session and issues a replacement in the same transaction (judgment call 1). A reset request issues a single-use opaque token and invalidates prior ones; confirmation re-applies the policy and revokes all sessions. Re-authorisation failures are audited. |
| Registration, login, verification | `arb_api.services.auth_service` | Self-service registration assigns the default role (TRADER) server-side and accepts no role from the request body. Status moves PENDING_VERIFICATION → ACTIVE on confirmation. Login refuses an unverified account with `EMAIL_NOT_VERIFIED` *before* the generic `ACCOUNT_DISABLED` test, because `is_active` is false for both and the order decides whether the user is told "verify your address" or "this account is disabled" (judgment call 2). |
| Authentication HTTP layer | `arb_api.api.v1.auth`, `arb_api.api.dependencies` | Nineteen endpoints, listed under *API surface* below. Protection is a dependency (`CurrentAuthDep` in the signature) rather than middleware, so it appears in the OpenAPI document, is visible to a reviewer reading the route, and can be overridden by a test — middleware-enforced authentication is none of those, and its failure mode is an endpoint somebody forgot to list in an exclusion table. |
| Cookie handling | `arb_api.api.v1.auth` | The refresh cookie is `HttpOnly`, `SameSite` from settings, `Secure` when deployed, and path-scoped to `/api/v1/auth` so it is attached only to requests that can use it. It is cleared with the same path and domain it was set with: a `delete_cookie` whose path does not match leaves the credential in the browser while the server has already revoked the session, which reads to a user exactly like a broken sign-out. |
| Client IP attribution | `arb_api.api.dependencies.get_client_ip` | `X-Forwarded-For` is believed only when `TRUST_PROXY_HEADERS=true` **and** the direct peer appears in `FORWARDED_ALLOW_IPS`. Believing it unconditionally hands every caller control of their own identity — a fresh address per request is an unlimited rate-limit budget and an audit trail naming nobody. Ignoring it entirely attributes every request behind a reverse proxy to the proxy, which is the same loss by other means. |
| Audit integration | `arb_api.services.audit_service` | Success entries share the caller's transaction; `record_failure()` opens its own and commits independently, because a refusal raises and the request's transaction rolls back with it — an entry written into that transaction would disappear along with the event it describes, which is how a platform ends up with an audit log full of successes and no record of anything anybody tried. It raises `ValueError` if called with `result=SUCCESS`. |
| Auth schemas | `arb_api.schemas.auth` | Every model is `frozen=True, extra="forbid"`. On an authentication endpoint that matters more than elsewhere: a request that silently accepts extra fields is one where a client can send `role` and hope. |

### PARTIALLY IMPLEMENTED

| Capability | What exists | What is missing |
| --- | --- | --- |
| Email delivery | Verification and password-reset tokens are issued, persisted, single-used, expired and verified; both flows are tested end to end. | **Nothing sends an email.** `EMAIL_PROVIDER=none` is the only working provider, so `dev_verification_token` and `dev_reset_token` return the plaintext token to the caller — and only when the provider is `none` **and** the environment is not deployed, so a deployed response can never carry one. SMTP/SES arrive with notifications in Phase 8+. |
| RBAC enforcement | Permission checks, denial auditing and role resolution work across the auth surface. | No administrative endpoints exist yet to protect (Phase 9). Roles are a fixed enum: there is no custom-role model and no way to edit a permission set at runtime. |
| Security monitoring | Login failures, lockouts, MFA refusals, token reuse and permission denials are written to `audit_logs` with actor, IP, user agent and request id. | `arb_security_events_total` is still never incremented. No anomaly detection, no alerting, no aggregation of failures into a security view (Phase 9/13). |
| Session & device management | Users can list their own sessions, revoke one, or revoke all; each session stores IP and user agent at creation and at last use. | No administrative view of another user's sessions, no device fingerprinting beyond the stored user agent, no notification when a new sign-in occurs elsewhere. |
| Application rate limiting | Seven named buckets, atomically enforced, with an explicit fail-closed/fail-open policy per scope. | No per-endpoint tuning, no coordination with nginx's coarse zone, and a fixed window rather than a sliding one or token bucket — so a burst straddling a window boundary can pass twice the intended count. |

### NOT IMPLEMENTED

Absent by design at this phase, listed so nothing is assumed to exist:

* **OAuth2 / social login / SAML / OIDC / passkeys (WebAuthn).** Password + TOTP + recovery codes only.
* **Email change flow.** `AuthTokenPurpose.EMAIL_CHANGE` exists as an enum member; nothing issues or consumes it.
* **Account deletion and self-service data export** (GDPR erasure/portability).
* **IP allow-listing, session pinning to an IP or device, "trusted device" memory.**
* **Administrative user management** — creating, inviting, disabling, role-assigning or impersonating other users. `SUPPORT_AGENT` and `ADMIN` have permissions defined and no endpoints to exercise them.
* **Captcha or proof-of-work on registration/login.** The defence today is the rate limiter and the lockout.
* **Breached-password screening.** `_COMMON_PASSWORDS` is a 43-entry local floor, not a corpus check; a real one (k-anonymity against a breached-password database) needs a network call and does not exist. `PasswordPolicy.describe()` reports `screened_against_breach_corpus: False` so no client can assume it.
* **Character-class requirements and scheduled password expiry.** Both are declined deliberately and published as absent — see judgment call 11.
* **Password history** — reusing a previous password is refused only by the policy's general rules, not by memory of past hashes.
* **Session concurrency limits** — nothing caps how many sessions one account may hold.
* **Frontend.** `apps/web/` is still empty. No browser has exercised the cookie flow.

### Judgment calls and deviations

Recorded because each one departs from the obvious reading of a requirement, and a
later reader is entitled to know it was decided rather than overlooked.

1. **A password change revokes the caller's own session and issues a replacement.** The obvious design — exempt the session making the change — is self-defeating here: `SessionService.authenticate` refuses any session created before `password_changed_at`, and the acting session necessarily predates the change, so it would be revoked anyway. Exempting it explicitly would keep alive the one session an attacker who has just taken over an account is most likely to hold. `POST /password/change` therefore returns `PasswordChangeResponse{message, sessions_revoked, tokens}` and sets fresh cookies. **Clients must store the returned tokens**; a client that discards them is signed out, by design.
2. **Login checks account status in a deliberate order.** `PENDING_VERIFICATION` is refused with `EMAIL_NOT_VERIFIED` before the generic `is_active` test, because `is_active` is false for both states and the order alone decides whether the user gets an actionable message.
3. **CSRF is required on `/refresh` unconditionally**, not only when the refresh token arrived as a cookie. A cross-site form can post a JSON-looking body under `text/plain`, which provokes no CORS preflight, and FastAPI parses it anyway — so "the token was in the body" is not evidence of same-origin intent. Verification runs before any state change, because a forged request that reached the rotation branch would revoke the victim's whole family and turn a CSRF hole into a denial of service.
4. **Three login responses reveal that an account exists** (locked, disabled, unverified), while wrong-password and unknown-account are indistinguishable in code, message, status and `WWW-Authenticate`, and the unknown-account path still burns a full password verification. Each of the three discloses something the account owner needs and cannot learn elsewhere, and each is reachable only after a rate-limit budget has been spent.
5. **The TOTP replay guard lives in PostgreSQL, not Redis.** A security control held in a cache fails open: when the cache is unreachable the check is either skipped or every MFA login fails, and an operator under pressure chooses "skip". The column costs one UPDATE on a path that already writes.
6. **Lockout is short (15 minutes) and a correct password clears the per-account counter but never the per-IP one.** An unexpiring lock is a denial-of-service primitive aimed at somebody else's account, and an attacker holding one valid account must not be able to clear their own guessing budget at will.
7. **Migration `0003`'s CHECK constraint is PostgreSQL-only**, behind the same `_is_postgresql()` guard the audit trigger in `0001` uses. SQLite has no `ALTER TABLE ... ADD CONSTRAINT`, and Alembic's batch copy-and-move mode was tried first and rejected: it cannot run in offline `--sql` mode without a live connection to reflect the table, and passing `copy_from` would mean restating every column of `users` inside the revision, where an omitted column is one the copy silently drops.
8. **`filterwarnings` carries one narrow ignore.** Starlette 1.6 deprecated the `HTTP_422_UNPROCESSABLE_ENTITY` constant that FastAPI 0.141 still reads while building its validation-error response, so under `filterwarnings = ["error"]` every malformed request failed the suite from inside FastAPI's own handler on the way to producing a correct 422. The ignore is scoped to that exact message rather than to the warning class, so nothing else is silenced. It is an upstream mismatch, not ours to fix.
9. **Session cookies are path-scoped to `/api/v1/auth`.** Stricter than the default `/`, and it means a future endpoint outside that prefix cannot rely on the refresh cookie — it must be sent explicitly. Intentional, but a constraint Phase 8's frontend inherits.
10. **The test database fixture builds through `Database.from_settings`** so an in-memory SQLite URL acquires a `StaticPool`. Without it each connection sees its own empty database, which is invisible while a test uses one session and fatal the moment anything opens a second — exactly what an audited refusal does. `Database.create` deliberately does *not* do this, because a production engine must not be pinned to a single connection.
11. **The password policy requires no character classes and forces no periodic expiry.** Composition rules push people towards predictable substitutions — `Password1!` rather than a passphrase — and scheduled expiry produces passwords written on notes, without making a stolen one less useful in the window that matters. Current guidance (NIST SP 800-63B) advises against both. What is enforced instead is length, a local common-password screen, and refusal of anything containing the account's own identifiers. Because a client might reasonably assume the opposite, `PasswordPolicy.describe()` publishes `requires_character_classes: False` and `expires_periodically: False` alongside the rules that *are* enforced, so a sign-up form cannot promise a check the server will not perform.

---

## Data model

Migration `0001_platform_infrastructure` creates four tables:

| Table | Purpose | Indexes |
| --- | --- | --- |
| `feature_flags` | Runtime feature gates; DB is authoritative over env defaults | `created_at`, `updated_at` |
| `audit_logs` | Append-only actor/resource/result history; UPDATE and DELETE blocked by a trigger | `actor_id+occurred_at`, `resource_type+resource_id`, `action+occurred_at`, `occurred_at` |
| `worker_heartbeats` | Durable worker liveness history (live detection reads Redis) | `role+last_heartbeat_at`, `last_heartbeat_at` |
| `system_health_snapshots` | Dependency health over time | `service+observed_at`, `observed_at` |

Migration `0002_authentication` creates the four authentication tables, and
`0003_totp_replay_guard` adds one column to `users`:

| Table | Purpose | Constraints & indexes |
| --- | --- | --- |
| `users` | Accounts: identity, status, password hash, lockout counters, MFA state | unique `email`; `email = lower(email)`, so uniqueness cannot be evaded by capitalisation; `failed_login_count >= 0`; `totp_last_used_step >= 0` (PostgreSQL only — judgment call 7); indexes on `created_at`, `updated_at`, `deleted_at` and `status+created_at` for the administrative listings Phase 9 will need |
| `user_sessions` | One row per issued session — the authority on whether a token still works | unique `refresh_token_hash`; `family_id` groups a session with every rotation descended from it; `parent_session_id` with a CHECK that it is not the row itself; indexes on `created_at`, `updated_at`, `expires_at`, `family_id` and `user_id+status` |
| `auth_tokens` | Single-use opaque tokens: email verification, password reset (and `EMAIL_CHANGE`, defined but never issued) | unique `token_hash`; indexes on `created_at`, `expires_at` and `user_id+purpose` |
| `mfa_recovery_codes` | One row per recovery code, consumed in place | unique `user_id+code_hash`; indexes on `created_at` and `user_id` |

No credential is stored in a usable form. `password_hash` is an argon2id or bcrypt
digest; `refresh_token_hash`, `token_hash` and `code_hash` are SHA-256 digests of
values the server never keeps; `totp_secret_encrypted` is AES-256-GCM ciphertext
under `ENCRYPTION_KEY` with the additional authenticated data `totp_secret` — the
one secret that *must* be reversible, because the server has to recompute the code
to compare against it, and binding the AAD to a purpose means ciphertext written
for one use cannot be replayed as another.

No order, balance, position or exchange-credential table exists yet.

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

Phase 1 exposed no mutating route, and `TestMethodExposure` in
`tests/security/test_endpoint_security.py` still asserts that `POST`, `PUT`,
`PATCH` and `DELETE` against each of those observability paths return 404 or 405.
Phase 2 adds the first write surface, under `/api/v1/auth`:

| Method & path | Authentication | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/register` | public | Self-service sign-up. Assigns the default role server-side; `REGISTRATION_ENABLED=false` refuses with `REGISTRATION_DISABLED`. |
| `POST /api/v1/auth/login` | public | Password login. Returns tokens, or an MFA challenge when the account has a second factor. Sets the refresh and CSRF cookies. |
| `POST /api/v1/auth/mfa/login` | MFA challenge token | Second factor: a TOTP code or a recovery code. Exchanges the challenge for a real session. |
| `POST /api/v1/auth/refresh` | refresh token **+ CSRF** | Rotates the refresh token. A superseded token revokes the whole family. |
| `GET /api/v1/auth/me` | bearer | The caller's own account: role, status, verification and MFA state, and whether an administrator reset the password. Read from the database on every call rather than from token claims, so a suspension is reflected immediately. Carries no credential material of any kind. |
| `GET /api/v1/auth/sessions` | bearer | The caller's own active sessions, with IP and user agent. |
| `DELETE /api/v1/auth/sessions/{session_id}` | bearer | Revoke one of the caller's own sessions. Another account's id is a 404, not a 403 — it does not confirm the session exists. |
| `POST /api/v1/auth/logout` | bearer | Revoke the calling session and clear the cookies. |
| `POST /api/v1/auth/logout-all` | bearer | Revoke every session belonging to the caller. |
| `POST /api/v1/auth/password/change` | bearer | Change password. Revokes all sessions **including the caller's** and returns a replacement token set (judgment call 1). |
| `POST /api/v1/auth/password/reset` | public | Request a reset token. Always succeeds identically whether or not the address exists. |
| `POST /api/v1/auth/password/reset/confirm` | public | Consume a reset token and set a new password. Revokes all sessions. |
| `POST /api/v1/auth/email/verify` | public | Consume a verification token; PENDING_VERIFICATION → ACTIVE. |
| `POST /api/v1/auth/email/verify/request` | public | Re-issue a verification token, invalidating prior ones. |
| `POST /api/v1/auth/mfa/enroll` | bearer | Begin enrolment: returns the secret and a provisioning URI. |
| `POST /api/v1/auth/mfa/confirm` | bearer | Prove possession with a live code; activates MFA and returns recovery codes **once**. |
| `POST /api/v1/auth/mfa/cancel` | bearer | Discard a pending enrolment. |
| `POST /api/v1/auth/mfa/disable` | bearer | Turn MFA off. Re-authorises with the current password. |
| `GET /api/v1/auth/mfa` | bearer | MFA status: whether it is active, pending or absent. |

Every response is JSON and every failure uses the standard error envelope, with the
`error.code` string as the machine-readable contract. The authentication codes, and
the status each maps to:

| `error.code` | HTTP | Raised when |
| --- | --- | --- |
| `NOT_FOUND` | 404 | A session id that is not the caller's own. Reported as *not found* rather than forbidden, so the response does not confirm that the session exists. |
| `SERVICE_UNAVAILABLE` | 503 | A sign-in reported success without issuing a credential set — a service-layer programming error, surfaced as retryable rather than papered over with a null. |
| `VALIDATION_ERROR` | 422 | The request body did not parse against the schema (`extra="forbid"`, so an unknown field lands here). |
| `UNAUTHENTICATED` | 401 | No bearer token, or one that does not decode. Carries `WWW-Authenticate: Bearer`. |
| `PERMISSION_DENIED` | 403 | The caller's current role lacks the required permission. Audited as `DENIED`. |
| `RATE_LIMITED` | 429 | A bucket is exhausted, or Redis is unreachable and the scope fails closed. |
| `INVALID_CREDENTIALS` | 401 | Wrong password, or no such account — deliberately the same response for both. |
| `ACCOUNT_LOCKED` | 423 | Five wrong passwords inside fifteen minutes. Carries `retry_after_seconds`. |
| `ACCOUNT_DISABLED` | 403 | The account is `DISABLED` or `SUSPENDED`. |
| `EMAIL_NOT_VERIFIED` | 403 | The account is still `PENDING_VERIFICATION`. Checked before `ACCOUNT_DISABLED`. |
| `EMAIL_ALREADY_REGISTERED` | 409 | Registration with an address that exists. |
| `REGISTRATION_DISABLED` | 403 | `REGISTRATION_ENABLED=false`. |
| `MFA_REQUIRED` | 401 | The password was right and a second factor is needed. Carries a challenge token. |
| `MFA_INVALID` | 401 | The TOTP or recovery code was wrong, already spent, or a replay of an accepted step. |
| `TOKEN_INVALID` | 400 | A one-time or refresh token does not match any stored digest. |
| `TOKEN_EXPIRED` | 401 | A one-time token or access token is past its `exp`. |
| `SESSION_REVOKED` | 401 | The session was revoked, expired, or its refresh token was already rotated. |
| `CSRF_FAILED` | 403 | The `X-CSRF-Token` header is missing or does not match the session being refreshed. |
| `PASSWORD_POLICY_REJECTED` | 422 | The new password fails the policy. `details.password` names each problem. |

`tests/integration/test_documentation.py` asserts this table and the endpoint table
above against the code, so neither can drift into fiction. `dev_verification_token` and
`dev_reset_token` appear only when `EMAIL_PROVIDER=none` on a non-deployed
environment and are `null` otherwise — the stand-in for an email sender that does
not exist yet, and labelled as such.

---

## Repository layout

```
packages/core          arb_core       7,365 lines · 29 modules
packages/persistence   arb_persistence 3,356 lines · 17 modules + alembic/
apps/api               arb_api         6,436 lines · 33 modules
apps/worker            arb_worker        151 lines · entrypoint only
apps/web               —               empty (Phase 8)
tests                  13,167 lines · 38 modules (unit / integration / security / support)
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
* **No browser has exercised the authentication flow.** The 59 endpoint tests drive
  the real ASGI application through `httpx`'s transport — real middleware, real
  argon2, real HMAC, real cookies — but `SameSite` handling, third-party-cookie
  blocking, redirect-after-login and cookie-jar behaviour are browser decisions, and
  no browser has been involved. `apps/web/` is empty; that verification belongs to
  Phase 8.
* **Redis in the authentication tests is `fakeredis`.** It executes the rate
  limiter's real Lua scripts, so the atomicity logic is genuinely exercised, but a
  network partition, a real eviction policy and Redis Cluster key placement are not.
* **The authentication suite runs against SQLite**, which is why migration `0003`'s
  CHECK constraint is dialect-guarded (judgment call 7). The unique constraints that
  the replay and rotation guarantees lean on do exist in SQLite, so those properties
  are tested; PostgreSQL-specific behaviour is first met in CI.
* **No exchange, no order and no money has ever been involved.** Nothing in this
  phase can trade.

---

## Defects found and fixed while bringing up the gates

Recorded because each one was a live failure mode, not a style complaint. Items
1–9 are Phase 1; 10–16 were found while building Phase 2.

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
9. **Every nested v1 route was labelled with a truncated path.** FastAPI resolves
   an *ancestor* router's prefix at match time, so `scope["route"].path` was
   `/system/info` for a request to `/api/v1/system/info`. That value feeds both
   the Prometheus `route` label and the access log, so the platform labelled its
   own traffic with a path nobody can request — and once Phase 9 mounts
   `/api/v1/admin`, `admin/users/{id}` and `users/{id}` would have collapsed into
   a single series. Leaf routers now spell their complete prefix
   (`arb_api.api.paths`), with two tests that fail against the old shape.
10. **`SessionService.refresh` hashed a token the repository hashes itself.**
    `SessionRepository.get_by_refresh_token(plaintext)` computes the SHA-256 digest
    internally, while `start()` and `rotate()` take an already-computed
    `refresh_token_hash`. The service passed a digest to the lookup, producing a
    digest-of-a-digest that matched no row, and every legitimate refresh was refused
    as an unknown token. Two conventions in one repository, neither wrong in
    isolation. Fixed by passing the plaintext and documenting the split on the
    repository itself: **lookups take the secret, mutators take its digest.** Found
    by the integration suite reporting `SESSION_REVOKED` for a token issued one line
    earlier; confirmed by instrumenting the lookup to print both digests.
11. **Exempting the caller's session from a password change does not work.** This was
    a design error rather than a coding one, and the test that caught it was correct
    to fail: the acting session was created before the change, so the
    `created_at < password_changed_at` check revoked it regardless of any exemption
    list. Sparing it explicitly would have kept alive the one session an account
    thief is most likely to hold. Resolved by revoking everything and issuing a
    replacement in the same transaction (judgment call 1).
12. **The test database fixture had no `StaticPool`, so a second session saw an empty
    database.** In-memory SQLite gives each connection its own database; the fixture
    built through `Database.create`, which does not add one. Every test that used a
    single session passed, and every assertion about an audited *refusal* failed,
    because `record_failure()` deliberately opens its own transaction and found
    nothing there. It looked like the audit service not writing. Fixed by routing the
    fixture through `Database.from_settings`, where `build_engine_kwargs` supplies the
    pool — and deliberately *not* by changing `Database.create`, since pinning a
    production engine to one connection would be a far worse defect than the one being
    fixed.
13. **Login reported `ACCOUNT_DISABLED` for an unverified account.** Both states have
    `is_active == False` and the generic check ran first, so a user who had simply not
    clicked a link yet was told their account was disabled — true, useless, and the
    reason they would never sign in again. Reordered so the status-specific refusal
    wins (judgment call 2).
14. **Every malformed request failed the suite from inside FastAPI's own 422
    handler.** Starlette 1.6 deprecated `HTTP_422_UNPROCESSABLE_ENTITY`; FastAPI 0.141
    still reads that constant while building its validation-error response, and
    `filterwarnings = ["error"]` turned the resulting `DeprecationWarning` into a test
    failure on a path that was behaving correctly. Silencing the warning class would
    have hidden every other deprecation in the suite, so the ignore is scoped to the
    exact message (judgment call 8).
15. **A multi-device test borrowed `client._transport` to build a second client.**
    It worked and mypy rejected it: a private attribute with no type. Replaced with a
    client constructed from the `app` fixture through `ASGITransport`, which is both
    typed and independent of httpx internals that may change.
16. **TOTP and HOTP expected values written from memory were wrong.** The recalled
    counter values for RFC 4226's test key did not match the RFC. The implementation
    was correct and the test was not — the dangerous direction, because a wrong
    expected value invites "fixing" working crypto to satisfy it. Both suites now use
    values transcribed from RFC 4226 Appendix D and RFC 6238 Appendix B, cross-checked
    against `pyotp`. Rule adopted for this repository: **no cryptographic test vector
    is ever written from memory.**
