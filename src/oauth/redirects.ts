// Which OAuth redirect URIs a client may register and use. Enforced at
// dynamic registration, at admin client creation, and again on every
// authorization request (so shrinking OAUTH_EXTRA_REDIRECT_URIS takes effect
// for clients that registered earlier).

import type { Env } from "../env";

/** Claude's connector callbacks. */
export const CLAUDE_REDIRECT_URIS: readonly string[] = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

function parse(uri: string): URL | null {
  if (uri.length > 2048) return null;
  try {
    return new URL(uri);
  } catch {
    return null;
  }
}

/** Exact extra URIs from OAUTH_EXTRA_REDIRECT_URIS (comma separated). */
export function extraRedirectUris(env: Pick<Env, "OAUTH_EXTRA_REDIRECT_URIS">): string[] {
  return (env.OAUTH_EXTRA_REDIRECT_URIS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

/** Allowed: the Claude callbacks and the extra URIs exactly, plus
 * http://localhost or http://127.0.0.1 on any port and path (a local MCP
 * client, RFC 8252). Never userinfo or a fragment. */
export function redirectUriAllowed(uri: string, env: Pick<Env, "OAUTH_EXTRA_REDIRECT_URIS">): boolean {
  const url = parse(uri);
  if (!url || url.username || url.password || url.hash || uri.includes("#")) return false;
  if (CLAUDE_REDIRECT_URIS.includes(uri) || extraRedirectUris(env).includes(uri)) return true;
  return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
}

/** The redirect_uris of a registration, if every one is allowed. */
export function allowedRedirectUris(value: unknown, env: Pick<Env, "OAUTH_EXTRA_REDIRECT_URIS">): string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > 10) return null;
  if (!value.every((uri): uri is string => typeof uri === "string" && redirectUriAllowed(uri, env))) return null;
  return value;
}
