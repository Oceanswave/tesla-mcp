// Authentication for /mcp behind a small interface, so a later change can swap the
// static bearer token for an OAuth provider chained to Tesla sign-in.

import { constantTimeEqual, sha256 } from "./bytes";
import type { Env } from "./env";

/** Who the request acts for. `ownerId` names the OwnerState Durable Object. */
export type Principal = { ownerId: string };

export type AuthResult = { ok: true; principal: Principal } | { ok: false; response: Response };

export interface McpAuthenticator {
  authenticate(request: Request, env: Env): Promise<AuthResult>;
}

/** The single-owner MVP identity. */
export const OWNER_ID = "owner";

const encoder = new TextEncoder();

function unauthorized(error: "invalid_request" | "invalid_token", description: string): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer realm="tesla-mcp", error="${error}", error_description="${description}"`,
    },
  });
}

/** Static bearer token (MCP_BEARER_TOKEN). Fails closed when unset. Both
 * values are hashed before a constant-time comparison so neither the content
 * nor the length of the secret leaks through timing. */
export const bearerTokenAuthenticator: McpAuthenticator = {
  async authenticate(request, env) {
    const expected = env.MCP_BEARER_TOKEN;
    const header = request.headers.get("Authorization") ?? "";
    const match = /^Bearer ([\x21-\x7e]{1,4096})$/.exec(header);
    if (!expected) {
      // Hash anyway so an unconfigured server is not distinguishable by timing.
      await sha256(encoder.encode(match?.[1] ?? ""));
      return { ok: false, response: unauthorized("invalid_token", "Server authentication is not configured") };
    }
    if (!match?.[1]) {
      return { ok: false, response: unauthorized("invalid_request", "Bearer token required") };
    }
    const [presented, wanted] = await Promise.all([sha256(encoder.encode(match[1])), sha256(encoder.encode(expected))]);
    if (!constantTimeEqual(presented, wanted)) {
      return { ok: false, response: unauthorized("invalid_token", "Invalid bearer token") };
    }
    return { ok: true, principal: { ownerId: OWNER_ID } };
  },
};
