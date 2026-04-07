# Agent Guidelines for compliance-code-scanner

## Project Overview

This is a GitHub Action (`prodcycle/compliance-code-scanner`) that scans PR file
changes for SOC 2, HIPAA, and NIST compliance violations via the ProdCycle API. It runs
as a Node.js action (`node24`) with the compiled bundle at `dist/index.js`.

## Architecture

```
src/
  index.ts        # Entry point: parses inputs, orchestrates the flow
  diff.ts         # Collects changed files from git diff between base/head
  api-client.ts   # Calls POST /v1/compliance/validate with batching & retry
  annotate.ts     # Creates PR annotations, comments, and job summaries
  types.ts        # Shared TypeScript interfaces
__tests__/        # Vitest tests mirroring src/ structure
dist/             # Compiled bundle (ncc) — MUST be committed and kept in sync
action.yml        # GitHub Action metadata (inputs, outputs, branding)
```

## Key Commands

- `pnpm run test` — run all tests (vitest)
- `pnpm run type-check` — TypeScript type checking
- `pnpm run lint` — ESLint
- `pnpm run build` — compile with ncc into `dist/`
- `pnpm run all` — type-check + lint + test + build

## Critical Rules

### dist/ must always be rebuilt

The `dist/` directory is the compiled action bundle and **must be committed**.
CI enforces this with a `git diff --name-only dist/` check. After any source
change:

1. Run `pnpm run build`
2. Commit the updated `dist/` files alongside source changes

### API payload batching

The ProdCycle API enforces a ~5 MB request payload limit. The client
(`api-client.ts`) handles this with:

- **Proactive batching**: files are grouped into batches under `MAX_BATCH_BYTES`
  (currently 2 MB) before sending.
- **Reactive splitting**: if the API returns HTTP 413, the failing batch is
  automatically split in half and retried. This uses a queue so batches can be
  recursively halved until they succeed or reach single-file granularity.
- A single file that exceeds the API limit on its own will still throw — this is
  intentional so the user gets an actionable error.

When modifying batching logic, ensure the `PayloadTooLargeError` class is used
for 413 responses so `validate()` can catch and re-split rather than failing.

### File collection constraints

In `diff.ts`, changed files are subject to:

- **512 KB per-file limit** — files larger than this are silently skipped
- **500 file cap** — remaining files beyond this are skipped with a warning
- **Include/exclude globs** — user-configurable via action inputs

All changed files are collected (no extension allowlist), including migration
files (Alembic, Prisma, Django, Flyway, etc.).

### Error handling in the API client

- **4xx errors** (except 429 and 413): thrown immediately, no retry
- **413**: thrown as `PayloadTooLargeError`, caught by `validate()` for re-splitting
- **429**: retried with backoff
- **5xx errors**: retried up to `MAX_RETRIES` (2) with increasing delay
- **Timeout**: 120 seconds per request

### Version tagging

This action uses the standard GitHub Actions versioning convention:

- `v1.0.x` — specific patch releases (immutable tags)
- `v1` — floating major tag, must always point to the latest `v1.x.x` release

After every release, update both:
```bash
git tag v1.x.x
git tag -f v1
git push origin v1.x.x
git push --force origin v1
```

### Testing

Tests live in `__tests__/` and use Vitest. `@actions/core` and `fetch` are
mocked. When adding API client tests, use `vi.spyOn(globalThis, "fetch")` to
mock responses. Tests must pass before any PR merge — CI runs them
automatically.
