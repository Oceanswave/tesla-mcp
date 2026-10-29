import type { OwnerState } from "./owner/state";
import type { TeslaVcpSession } from "./tesla/vcp/session";

/** Worker bindings. Vars come from wrangler.jsonc; secrets from
 * `wrangler secret put` (see .dev.vars.example). Secrets are optional in the
 * type because every consumer must fail closed when one is missing. */
export interface Env {
  OWNER: DurableObjectNamespace<OwnerState>;
  TESLA_VCP: DurableObjectNamespace<TeslaVcpSession>;

  TESLA_FLEET_BASE_URL: string;
  TESLA_AUTH_TOKEN_URL: string;
  TESLA_PUBLIC_KEY_PEM: string;
  DANGEROUS_COMMANDS_ENABLED: string;

  MCP_BEARER_TOKEN?: string;
  TESLA_CLIENT_ID?: string;
  TESLA_CLIENT_SECRET?: string;
  TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64?: string;
  TOKEN_ENCRYPTION_KEY?: string;
  TESLA_BOOTSTRAP_REFRESH_TOKEN?: string;
  TESLA_VEHICLE_ID?: string;
}
