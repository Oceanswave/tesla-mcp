# Notes for agents working in this repository

This is a public MIT repository for an MCP server that controls a real car. Correctness of Tesla command signing
and of the lock retry logic matters more than speed.

## Hard rules

- Never print, log, commit, or write secrets, tokens, or keys. Tests generate every credential at runtime with
  WebCrypto. Never commit a PEM private key, not even a fake one (it trips secret scanners). Public keys are fine.
- No `.bak` files, no fallback or legacy code paths, and never weaken or skip a check (tests, lint, types,
  confirmation gates, auth) to make something pass.
- Never push, and never commit to `main`. Work on a feature branch in logical commits.
- Do not name Cloudflare's default worker subdomain in public-facing text; the only exception is the one
  "your ... URL" mention in the README self-host section.
- TypeScript strict, ESM. npm with a committed `package-lock.json`; pin exact dependency versions. Biome for lint
  and format.
- New vehicle commands: add them to `SIGNED_COMMANDS` in `src/tesla/vcp/protocol.ts` with test vectors. Anything
  that unlocks, opens, starts, or weakens security must declare a `dangerousAction` (see `src/mcp/dangerous.ts`)
  so it stays unregistered unless `DANGEROUS_COMMANDS_ENABLED` is `"true"`.
- Every state-changing tool requires `confirm: true` and supports `dryRun: true` (via `commandGate` in
  `src/mcp/server.ts`). Read tools must never wake the car.
- CI uses `pull_request` (never `pull_request_target`), `contents: read`, and actions pinned by full SHA.

## Layout

- `src/index.ts`: routes, security headers, `/mcp` transport, cron handler.
- `src/auth.ts`: `McpAuthenticator` interface and the bearer-token implementation.
- `src/mcp/`: tool definitions and the dangerous-command gate.
- `src/owner/`: `OwnerState` Durable Object (encrypted tokens, audit log, nightly alarm, command lane), schedule
  math, lock retry policy, token encryption.
- `src/tesla/`: Fleet REST client, bounded HTTP helpers, and `vcp/` (Vehicle Command Protocol codec, crypto, and
  the per-VIN `TeslaVcpSession` Durable Object).
- `test/`: Workers-runtime tests with a simulated Tesla in `test/helpers/fake-tesla.ts`.

## Checks

Run `npm run check` (typecheck, lint, test) and `npm run deploy:dry` before finishing. Regenerate VCSEC vectors
with `scripts/vcsec_vectors.py` if the signer's encoding changes on purpose.
