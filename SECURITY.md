# Security

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Oceanswave/tesla-mcp/security/advisories/new). Do not open a
public issue. Include what you found, how to reproduce it, and its impact. You will get an acknowledgement, and a
fix or mitigation will be coordinated with you before any disclosure.

## Threat model summary

This server can lock a real car and read its status, so the assets are the owner's Tesla account tokens, the
vehicle-command private key, and control of the car.

| Threat                                 | Mitigation                                                                                                                                                                                                                            |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized MCP caller                | `/mcp` requires a bearer token compared in constant time (SHA-256 of both values). No configured token means every request is refused.                                                                                                |
| Assistant acts without the user asking | Every state-changing tool requires `confirm: true`; `dryRun` describes without acting. Refusals are audited.                                                                                                                          |
| Harmful commands                       | Only lock is implemented. Unlock, remote start, openings, valet/PIN/speed limit, HomeLink, and erase are not implemented and sit behind `DANGEROUS_COMMANDS_ENABLED` (default off). The signer builds only explicitly named payloads. |
| Token theft from storage               | Tesla tokens are AES-256-GCM encrypted (random IV, purpose-bound AAD) with a key held only in Worker secrets.                                                                                                                         |
| Secrets leaking into logs or audit     | Logs carry only error codes and protocol stages. Audit details are internally generated codes, additionally redacted for token-shaped strings. No location data is requested or returned.                                             |
| Refresh-token loss or replay storms    | Load, seeding, and refresh are single-flight; seeding never overwrites newer tokens. The rotated refresh token is persisted before use. A rejected refresh token stops all refreshes (`reauth_required`).                             |
| Forged or replayed vehicle responses   | The VCP session handshake is authenticated with the session-info HMAC and bound to the request UUID; commands use a monotonic counter and short expiry. Responses must echo the request UUID.                                         |
| Key mismatch or misconfiguration       | The private key must match the published public key (checked by signing and verifying) before any command is signed.                                                                                                                  |
| Request smuggling of large bodies      | `/mcp` bodies are capped at 64 KiB; upstream Tesla responses are size- and time-bounded; redirects are not followed.                                                                                                                  |

Known limitations of the MVP: a single static bearer token (no per-user identity); VCSEC replies are not encrypted
by the vehicle, so the lock result is reported as Tesla returns it; if a token refresh response is lost in transit
after Tesla rotated the refresh token, the owner must provide a new bootstrap token.

CI runs pull request code on a self-hosted runner; the repository requires maintainer approval before any workflow
run from an external contributor.
