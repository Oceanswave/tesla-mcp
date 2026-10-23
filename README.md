# tesla-mcp

A private [Model Context Protocol](https://modelcontextprotocol.io) server for one Tesla owner, running on
Cloudflare Workers. It lets an assistant (Claude, Grok in the car, or any Streamable HTTP MCP client) check the
car and lock it, and it locks the car automatically every night.

Lock is sent as a signed Vehicle Command Protocol message (the VCSEC domain), so it works on vehicles that require
Tesla's command signing. The signer is a WebCrypto port checked byte for byte against the owner's production
Python implementation.

**Status: owner-only MVP.** One owner, one static bearer token, one Tesla account. Multi-user sign-in with Tesla
OAuth is planned; the auth and storage seams are already in place for it.

## Tools

| Tool                        | Kind    | What it does                                                                                                                                                                |
| --------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tesla_vehicles_list`       | read    | Cars on the account with id, name, and online/asleep/offline.                                                                                                               |
| `tesla_vehicle_status`      | read    | Online or asleep; when online: locked, open doors/trunks/windows, battery, range, charging, temperatures, climate, Sentry Mode, odometer. Never wakes the car. No location. |
| `tesla_wake`                | command | Wake the car.                                                                                                                                                               |
| `tesla_lock`                | command | Lock the doors with a signed command. Wakes the car and retries if needed.                                                                                                  |
| `tesla_nightly_lock_status` | read    | Whether the nightly lock is on, its local time and zone, next run, last result.                                                                                             |
| `tesla_audit_recent`        | read    | Newest audit log entries (default 20).                                                                                                                                      |

## Safety model

- **Confirmation required.** Every state-changing tool refuses to act unless called with `confirm: true`, and
  accepts `dryRun: true` to describe the action without contacting the car. Refusals are audited.
- **No dangerous commands.** Unlock, remote start, opening trunks/frunk/windows, valet/PIN/speed-limit changes,
  HomeLink, and data erase are not implemented. A single gate (`DANGEROUS_COMMANDS_ENABLED`, default `"false"`)
  must be explicitly enabled before any such tool could even be registered.
- **Never wakes implicitly.** Status reads report "asleep" instead of waking the car. Only `tesla_wake`,
  `tesla_lock`, and the nightly lock wake it.
- **Explicit command allowlist.** The signer can only build the commands it names (today: door lock). It is not a
  generic vehicle-command proxy.
- **Secrets stay secret.** Tesla tokens are stored AES-256-GCM encrypted in a Durable Object. Tokens, keys, and
  raw Tesla responses are never logged or written to the audit log.
- **Fail closed.** No `MCP_BEARER_TOKEN` means every `/mcp` request is refused. A command key that does not match
  the published public key refuses to sign.

## Nightly lock

At `NIGHTLY_LOCK_TIME` in `NIGHTLY_LOCK_TIMEZONE` (default 22:00 America/New_York, correct across daylight saving
changes), a Durable Object alarm sends the signed lock. If the car is asleep or offline it is woken, polled until
online (up to about 90 seconds), and the lock is retried, up to 4 attempts in total. An already locked car counts as
success. Failures Tesla marks as not retryable stop at once. If a lock response is lost, or the car only
acknowledges the command without confirming it ran, the car's lock state is checked instead of sending the lock
again. The whole run stops starting new attempts after 7 minutes, well inside the 15-minute limit Cloudflare gives an
alarm. A night that finished never runs again. A run interrupted part way (for example, the Durable Object was
restarted) is resumed up to 3 times, within 3 hours of the scheduled time, and a resumed run checks whether the car
is already locked before sending anything. After that it is audited as missed or abandoned. If an outage delays the
alarm past the next night's lock time, that night still runs (within the same 3-hour window) instead of being
skipped. Every run is audited. A cron trigger every 15 minutes keeps the alarm armed; it does nothing else, so right
after a first deploy `tesla_nightly_lock_status` shows no next run until the first cron tick.

## Self-hosting

You need a Tesla developer account, a Cloudflare account, and a domain you control (Tesla fetches your public key
from it). Node 22 or newer.
1. **Create a Tesla developer application** at [developer.tesla.com](https://developer.tesla.com). Set the allowed
   origin to `https://<your-domain>` and the redirect URI to `https://<your-domain>/callback`. Request the scopes
   `openid offline_access vehicle_device_data vehicle_cmds`.

2. **Generate a P-256 command key** somewhere outside this repository (`*.pem` and `keys/` are gitignored, but keep
   the private key off disk where you can):

   ```sh
   openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
   openssl ec -in private-key.pem -pubout -out public-key.pem
   ```

3. **Publish the public key.** Put the contents of `public-key.pem` in `TESLA_PUBLIC_KEY_PEM` in `wrangler.jsonc`
   (newlines as `\n`). After deploying, it is served at
   `https://<your-domain>/.well-known/appspecific/com.tesla.3p.public-key.pem`. If your account is outside North
   America, change `TESLA_FLEET_BASE_URL` to your region's Fleet API host.

4. **Set secrets** (see `.dev.vars.example` for what each one is):

   ```sh
   npx wrangler secret put MCP_BEARER_TOKEN
   npx wrangler secret put TESLA_CLIENT_ID
   npx wrangler secret put TESLA_CLIENT_SECRET
   openssl pkcs8 -topk8 -nocrypt -in private-key.pem -outform DER | base64 | tr -d '\n' \
     | npx wrangler secret put TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64
   openssl rand -base64 32 | npx wrangler secret put TOKEN_ENCRYPTION_KEY
   npx wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN   # see step 7
   npx wrangler secret put TESLA_VEHICLE_ID                # optional
   ```

5. **Deploy** with `npm ci && npx wrangler deploy`, then attach your domain to the Worker (Workers & Pages → your
   Worker → Domains & Routes → Custom domain). You can smoke-test `/healthz` on your workers.dev URL first, but
   Tesla registration needs your own domain.

6. **Register as a Tesla partner** for your domain (once per region), using a partner token:

   ```sh
   PARTNER_TOKEN=$(curl -s -X POST https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token \
     -d grant_type=client_credentials -d client_id="$TESLA_CLIENT_ID" -d client_secret="$TESLA_CLIENT_SECRET" \
     -d scope="openid vehicle_device_data vehicle_cmds" \
     -d audience=https://fleet-api.prd.na.vn.cloud.tesla.com | jq -r .access_token)
   curl -s -X POST https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/partner_accounts \
     -H "Authorization: Bearer $PARTNER_TOKEN" -H 'Content-Type: application/json' \
     -d '{"domain":"<your-domain>"}'
   ```

7. **Get a refresh token for your account.** Browser sign-in is not built yet. Complete Tesla's OAuth
   authorization-code flow once (for example with Tesla's documented flow or a tool you trust), then store the
   refresh token with `wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN`. It seeds the encrypted token store once;
   Tesla rotates refresh tokens, and the Worker keeps the newest. If Tesla later rejects it, the server reports
   `reauth_required` and stops retrying until you set a new bootstrap token.

8. **Pair the virtual key with the car.** On the phone with the Tesla app, open `https://tesla.com/_ak/<your-domain>`
   and approve the key. Signed commands fail with "pairing required" until this is done.

9. **Connect your MCP client** to `https://<your-domain>/mcp` with the header
   `Authorization: Bearer <MCP_BEARER_TOKEN>`.

## Development

```sh
npm ci
npm run check       # typecheck, Biome lint, tests
npm run deploy:dry  # bundle without deploying
```

Tests run in the Workers runtime against a simulated Tesla (Fleet API, OAuth, and a vehicle that performs the real
ECDH handshake and verifies every signature). All test credentials are generated at runtime. The VCSEC vectors in
`test/vcp-vectors.test.ts` come from `scripts/vcsec_vectors.py`.

## License

MIT. See [LICENSE](LICENSE).
