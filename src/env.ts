import type { OwnerState } from "./owner/state";
import type { TeslaVcpSession } from "./tesla/vcp/session";

/** Worker bindings. Vars come from wrangler.jsonc; secrets from
 * `wrangler secret put` (see .dev.vars.example). Secrets are optional in the
 * type because every consumer must fail closed when one is missing. */
export interface Env {
  OWNER: DurableObjectNamespace<OwnerState>;
  TESLA_VCP: DurableObjectNamespace<TeslaVcpSession>;
  /** OAuth front door (src/oauth/): server-issued tokens, registered clients,
   * one-time approval tokens, and failed-passphrase counters. */
  OAUTH_KV: KVNamespace;

  TESLA_FLEET_BASE_URL: string;
  TESLA_AUTH_TOKEN_URL: string;
  TESLA_PUBLIC_KEY_PEM: string;
  DANGEROUS_COMMANDS_ENABLED: string;
  /** https origin (or base URL) Tesla redirects to: sign-in uses
   * `${OAUTH_REDIRECT_BASE}/callback`. */
  OAUTH_REDIRECT_BASE: string;
  /** Vehicle used when a tool gets no vehicle_id: a VIN or Fleet vehicle id.
   * Empty means "the account's only vehicle". */
  DEFAULT_VIN: string;
  /** Comma-separated redirect URIs allowed for OAuth clients beyond the
   * built-in Claude and loopback ones. */
  OAUTH_EXTRA_REDIRECT_URIS: string;

  MCP_BEARER_TOKEN?: string;
  TESLA_CLIENT_ID?: string;
  TESLA_CLIENT_SECRET?: string;
  TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64?: string;
  TOKEN_ENCRYPTION_KEY?: string;
  TESLA_BOOTSTRAP_REFRESH_TOKEN?: string;
  /** Passphrase the owner types on /authorize to approve a client. */
  OAUTH_ADMIN_PASSPHRASE?: string;
}
