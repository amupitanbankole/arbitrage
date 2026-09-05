# apps/web — **NOT IMPLEMENTED** (Phase 8)

This directory contains no application code. It is a placeholder for the Next.js
frontend, and it exists so the monorepo layout described in the build plan is
stable from Phase 1 rather than being restructured under a working system later.

Status is tracked in [`../../docs/STATUS.md`](../../docs/STATUS.md).

## Why nothing is here yet

The frontend consumes authenticated endpoints. Phase 1 has no users, no sessions
and no RBAC, so any dashboard built now would have to invent an auth surface and
then be rewritten when Phase 2 lands. Building it out of order would produce
exactly the thing the build plan forbids: a UI that appears to work against data
it cannot actually be authorised to read.

## Planned stack

Next.js (App Router) · TypeScript · Tailwind · shadcn/ui · TanStack Query ·
React Hook Form · Zod · Recharts.

Zod schemas will mirror the Pydantic response models in `apps/api/src/arb_api/schemas`
rather than being written independently: a contract expressed twice drifts, and
the drift is discovered by a user.

## Planned layout

The empty subdirectories below are the intended shape. Git does not track empty
directories, so they will not appear in a fresh clone until the phase that fills
them creates them; they are listed here so the structure is a decision rather
than an accident.

```
apps/web/
  app/               App Router routes, layouts, server components
  components/ui/     shadcn primitives (design-system layer, no domain knowledge)
  features/system/   Domain slices: one directory per capability, each holding
                     its own components, hooks and schemas. Phase 8 adds
                     dashboard/ and portfolio/; Phase 9 adds admin/.
  lib/               Framework-agnostic helpers (formatting, fetch wrapper)
  services/          API clients — the only layer that knows endpoint paths
  types/             Shared TypeScript types generated from the OpenAPI document
  public/            Static assets
```

`features/<domain>/` owning its own hooks and schemas is deliberate: a single
shared `components/` directory becomes a place where unrelated domains couple
through one file, and a rename in trading then breaks notifications.

## Configuration

Frontend environment keys are already reserved in `.env.example`:

| Key | Purpose |
| --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | Browser-facing API origin. Must be reachable from the *browser*, not from the container — inside compose that is not `http://api:8000`. |
| `NEXT_PUBLIC_APP_NAME` | Display name. |
| `NEXT_PUBLIC_DEMO_MODE` | Mirrors the server-computed demo mode. The server value is authoritative; this only shapes first paint. |
| `INTERNAL_API_URL` | Server-side origin used by the Next.js container to reach the API over the compose network. |
| `FRONTEND_URL` | The API's allowed CORS origin (§61). |

Anything prefixed `NEXT_PUBLIC_` is shipped to the browser. No secret may ever
carry that prefix — a `NEXT_PUBLIC_` key is public by construction, not by
configuration mistake.
