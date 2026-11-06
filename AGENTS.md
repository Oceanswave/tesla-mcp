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
- New vehicle commands: add a payload builder to `src/tesla/vcp/payloads.ts` (it lands in `SIGNED_COMMANDS` in
  `src/tesla/vcp/protocol.ts`), a vector to `test/vectors/vcp-commands.json`, and the matching Tesla method call to
  `teslaCalls` in `conformance/go/tesla_mcp_commands_test.go`; take the expected bytes from Tesla's code, never from
  ours. New REST calls go in `src/tesla/endpoints.ts`, and every tool is a spec in `src/mcp/catalog.ts`. Anything
  that unlocks, opens, starts, or weakens security must declare a `dangerousAction` (see `src/mcp/dangerous.ts`),
  both on the tool and in `dangerousSignedCommand` or the endpoint, so it stays unregistered and unsent unless
  `DANGEROUS_COMMANDS_ENABLED` is `"true"`.
- No schedules, routines, alarms, or cron triggers in the Worker, and no owner-specific callers in this repo: a
  routine (such as a nightly lock) runs in the caller and calls the MCP tools.
- Every state-changing tool requires `confirm: true` and supports `dryRun: true` (via `commandGate` in
  `src/mcp/server.ts`). Read tools must never wake the car.
- CI uses `pull_request` (never `pull_request_target`), `contents: read`, and actions pinned by full SHA.

## Layout

- `src/index.ts`: the Worker entry: the fetch handler and the Durable Object classes only (workerd refuses
  any other export from the entry module).
- `src/routes.ts`: routes, security headers, `/mcp` transport.
- `src/auth.ts`: `McpAuthenticator` interface; the default accepts the static bearer token or an OAuth access token.
- `src/oauth/`: the OAuth front door for `/mcp` on `@cloudflare/workers-oauth-provider` (discovery, `/token`,
  `/register`, token validation), the passphrase-gated `/authorize` page, `/admin/clients`, and the redirect URI
  allowlist. Storage is the `OAUTH_KV` namespace.
- `src/mcp/`: core tool definitions and the confirm gate (`server.ts`), the declarative catalog of every other tool
  (`catalog.ts`), and the dangerous-command gate.
- `src/owner/`: `OwnerState` Durable Object (encrypted tokens, sign-in state, audit log, command lane), the lock
  retry policy, token encryption, the audit webhook (`notify.ts`).
- `src/tesla/`: Fleet REST client, the REST endpoint allowlist (`endpoints.ts`), bounded HTTP helpers, and `vcp/`
  (protobuf wire codec, command payload builders, envelope and crypto, and the per-VIN `TeslaVcpSession` Durable
  Object).
- `test/`: Workers-runtime tests with a simulated Tesla in `test/helpers/fake-tesla.ts`.
- `conformance/`: Go tests compiled inside a pinned checkout of Tesla's `vehicle-command`: one in
  `internal/authentication` rebuilds the envelope vectors (`vcsec-lock.json`, `infotainment-honk.json`) with Tesla's
  signer, one in `pkg/vehicle` checks every payload in `vcp-commands.json` against Tesla's own command methods.

## Checks

Run `npm run check` (typecheck, lint, test), `npm run deploy:dry`, and `bash conformance/run.sh` before finishing
(without a local Go: `docker run --rm -v "$PWD":/repo:ro -w /repo golang:1.27.3 bash conformance/run.sh`).
`GAP.md` maps Tesla's API to tools; keep it current when tools change. Regenerate VCSEC vectors
with `scripts/vcsec_vectors.py` if the signer's encoding changes on purpose.
