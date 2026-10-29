// Authentication for /mcp behind a small interface. The default accepts the
// static MCP_BEARER_TOKEN or an access token issued by this server's OAuth
// front door (src/oauth/).

import { secretsEqual } from "./bytes";
import type { Env } from "./env";
import { oauthTokenValid, resourceMetadataUrl } from "./oauth/server";

/** Who the request acts for. `ownerId` names the OwnerState Durable Object. */
export type Principal = { ownerId: string };

export type AuthResult = { ok: true; principal: Principal } | { ok: false; response: Response };

export interface McpAuthenticator {
  authenticate(request: Request, env: Env): Promise<AuthResult>;
}

/** The single-owner MVP identity. */
export const OWNER_ID = "owner";

/** The challenge points MCP clients at the protected-resource metadata
 * (RFC 9728) for this request's origin, where OAuth discovery starts. */
function unauthorized(request: Request, error: "invalid_request" | "invalid_token", description: string): Response {
  const metadata = resourceMetadataUrl(new URL(request.url).origin);
  return new Response(JSON.stringify({ error, error_description: description }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer realm="tesla-mcp", resource_metadata="${metadata}", error="${error}", error_description="${description}"`,
    },
  });
}

/** Whether `presented` is the static MCP_BEARER_TOKEN. Fails closed when it
 * is unset, and hashes either way so an unconfigured server is not
 * distinguishable by timing; the comparison hides content and length. */
export async function staticBearerMatches(presented: string | null, env: Env): Promise<boolean> {
  const expected = env.MCP_BEARER_TOKEN;
  if (!expected || !presented) {
    await secretsEqual(presented ?? "", "");
    return false;
  }
  return secretsEqual(presented, expected);
}

/** Static bearer token first (constant time), then OAuth-issued tokens. */
export const bearerTokenAuthenticator: McpAuthenticator = {
  async authenticate(request, env) {
    const header = request.headers.get("Authorization") ?? "";
    const presented = /^Bearer ([\x21-\x7e]{1,4096})$/.exec(header)?.[1] ?? null;
    const isStatic = await staticBearerMatches(presented, env);
    if (!presented) return { ok: false, response: unauthorized(request, "invalid_request", "Bearer token required") };
    if (isStatic || (await oauthTokenValid(new URL(request.url), presented, env))) {
      return { ok: true, principal: { ownerId: OWNER_ID } };
    }
    return { ok: false, response: unauthorized(request, "invalid_token", "Invalid bearer token") };
  },
};
