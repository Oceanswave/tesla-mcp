// The OAuth front door for /mcp, built on @cloudflare/workers-oauth-provider's
// authorization-server role. The library serves RFC 8414 metadata, /token
// (authorization_code and refresh_token, rotating refresh tokens), and /register
// (RFC 7591), stores every token, code, and client secret only as a hash, and
// validates access tokens. This module adds what is ours: the issuer and
// resource come from the request's origin, registration is held to the
// redirect allowlist, and the protected-resource metadata (RFC 9728).

import { OAuthAuthorizationServer } from "@cloudflare/workers-oauth-provider";
import type { Env } from "../env";
import { allowedRedirectUris } from "./redirects";

export const AUTHORIZE_PATH = "/authorize";
export const TOKEN_PATH = "/token";
export const REGISTER_PATH = "/register";
export const MCP_PATH = "/mcp";
export const AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";
export const PROTECTED_RESOURCE_METADATA_PATHS = [
  "/.well-known/oauth-protected-resource",
  `/.well-known/oauth-protected-resource${MCP_PATH}`,
];

/** The one MCP resource, at the request's origin. */
export function resourceFor(origin: string): string {
  return `${origin}${MCP_PATH}`;
}

export function resourceMetadataUrl(origin: string): string {
  return `${origin}/.well-known/oauth-protected-resource${MCP_PATH}`;
}

/** Workers serve https; plain http only for `wrangler dev` on a loopback host. */
function usableOrigin(url: URL): boolean {
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
}

// One instance per origin and allowlist: the library fixes its issuer and
// resource at construction, and the registration callback has no env.
const servers = new Map<string, OAuthAuthorizationServer<Env>>();

export function authorizationServer(url: URL, env: Env): OAuthAuthorizationServer<Env> | null {
  if (!usableOrigin(url)) return null;
  const origin = url.origin;
  const extra = env.OAUTH_EXTRA_REDIRECT_URIS ?? "";
  const key = `${origin}\n${extra}`;
  const existing = servers.get(key);
  if (existing) return existing;
  const server = new OAuthAuthorizationServer<Env>({
    issuer: origin,
    resources: [resourceFor(origin)],
    authorizeEndpoint: AUTHORIZE_PATH,
    tokenEndpoint: TOKEN_PATH,
    clientRegistrationEndpoint: REGISTER_PATH,
    clientRegistrationCallback: ({ clientMetadata }) => {
      if (allowedRedirectUris(clientMetadata.redirect_uris, { OAUTH_EXTRA_REDIRECT_URIS: extra })) return;
      // Redirect URIs are public client metadata (no secrets); log them so the owner can allow a new client.
      const rejected = Array.isArray(clientMetadata.redirect_uris)
        ? clientMetadata.redirect_uris.slice(0, 10).map((u) => String(u).slice(0, 300))
        : [];
      console.warn();
      return {
        code: "invalid_redirect_uri",
        description:
          "redirect_uris must be Claude's connector callback, http://localhost or http://127.0.0.1, or a URI the owner allowed.",
      };
    },
    // Status and code only: descriptions can echo client input.
    onError: ({ status, code }) => {
      console.warn(`[tesla-mcp] oauth ${status} ${code}`);
    },
  });
  servers.set(key, server);
  return server;
}

export function protectedResourceMetadata(origin: string): Response {
  return Response.json({
    resource: resourceFor(origin),
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    resource_name: "tesla-mcp",
  });
}

/** Whether `token` is an access token this server issued for /mcp at this
 * origin, from a client that still exists. Fails closed on storage errors. */
export async function oauthTokenValid(url: URL, token: string, env: Env): Promise<boolean> {
  // Issued tokens look like `user:grant:secret`; anything else is not ours.
  if (token.split(":").length !== 3 || !env.OAUTH_KV) return false;
  const server = authorizationServer(url, env);
  if (!server) return false;
  try {
    const validated = await server.validateToken(resourceFor(url.origin), token, env);
    if (!validated) return false;
    // A deleted client's tokens are revoked with it; checking the client too
    // closes the window while that revocation is still running.
    return (await server.getOAuthApi(env).lookupClient(validated.clientId)) !== null;
  } catch (error) {
    console.error(`[tesla-mcp] oauth token check failed: ${error instanceof Error ? error.name : typeof error}`);
    return false;
  }
}
