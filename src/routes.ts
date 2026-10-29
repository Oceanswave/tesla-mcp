// HTTP routes: security headers, CORS, the public key, browser sign-in (/login
// and /callback), the OAuth front door (discovery, /authorize, /token,
// /register, /admin/clients), and the /mcp transport.
// Kept out of index.ts because the Worker entry module may only export
// handlers and Durable Object classes.

import { createMcpHandler } from "@modelcontextprotocol/server";
import { bearerTokenAuthenticator, type McpAuthenticator, OWNER_ID } from "./auth";
import { readBoundedBody } from "./body";
import type { Env } from "./env";
import { escapeHtml } from "./html";
import { createMcpServer } from "./mcp/server";
import { handleAdminClients, isAdminClientsPath } from "./oauth/admin";
import { handleAuthorize } from "./oauth/authorize";
import {
  AUTHORIZATION_SERVER_METADATA_PATH,
  AUTHORIZE_PATH,
  authorizationServer,
  MCP_PATH,
  PROTECTED_RESOURCE_METADATA_PATHS,
  protectedResourceMetadata,
  REGISTER_PATH,
  TOKEN_PATH,
} from "./oauth/server";
import type { SignInResult } from "./owner/state";
import { authorizeUrl, signInRedirectUri } from "./tesla/oauth";

export const PUBLIC_KEY_PATH = "/.well-known/appspecific/com.tesla.3p.public-key.pem";
export const MAX_MCP_BODY_BYTES = 65_536;

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Cross-Origin-Resource-Policy": "same-origin",
};

/** Browser MCP and OAuth clients call these cross-origin. Bearer tokens are
 * not ambient credentials, so any origin may present one it holds. */
const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID",
  "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version",
  "Access-Control-Max-Age": "86400",
};

function corsPath(pathname: string): boolean {
  return (
    pathname === MCP_PATH ||
    pathname === TOKEN_PATH ||
    pathname === REGISTER_PATH ||
    pathname.startsWith("/.well-known/")
  );
}

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(CORS_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (!headers.has("Cache-Control")) headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function text(body: string, status = 200, contentType = "text/plain; charset=utf-8"): Response {
  return new Response(body, { status, headers: { "Content-Type": contentType } });
}

const HOME_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>tesla-mcp</title></head>
<body><h1>tesla-mcp</h1>
<p>A private MCP server for one Tesla owner. The MCP endpoint is /mcp and requires authorization.</p>
<p>Source: <a href="https://github.com/Oceanswave/tesla-mcp">github.com/Oceanswave/tesla-mcp</a></p>
</body></html>
`;

/** A plain sign-in page. `message` is escaped; it never carries a code or token. */
function signInPage(message: string, status: number): Response {
  return text(
    `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>tesla-mcp sign-in</title></head>
<body><h1>Tesla sign-in</h1>
<p>${escapeHtml(message)}</p>
</body></html>
`,
    status,
    "text/html; charset=utf-8",
  );
}

const SIGN_IN_FAILURES: Record<Exclude<SignInResult, { ok: true }>["reason"], [string, number]> = {
  invalid_state: ["This sign-in link is missing, expired, or already used. Start again at /login.", 400],
  denied: ["Tesla sign-in was cancelled or refused. Start again at /login.", 400],
  not_configured: ["Tesla sign-in is not configured on this server.", 503],
  exchange_failed: ["Tesla did not accept the sign-in. Start again at /login.", 502],
  account_mismatch: ["That is a different Tesla account from the one this server uses. Nothing was changed.", 403],
};

const REDIRECT_NOT_CONFIGURED =
  "Tesla sign-in is not configured on this server: OAUTH_REDIRECT_BASE must be an https URL.";

async function handleLogin(env: Env, ownerId: string): Promise<Response> {
  const redirectUri = signInRedirectUri(env.OAUTH_REDIRECT_BASE);
  if (!redirectUri) return signInPage(REDIRECT_NOT_CONFIGURED, 503);
  const clientId = env.TESLA_CLIENT_ID?.trim();
  if (!clientId) return signInPage(SIGN_IN_FAILURES.not_configured[0], 503);
  const owner = env.OWNER.get(env.OWNER.idFromName(ownerId));
  const state = await owner.beginSignIn(redirectUri);
  return new Response(null, { status: 302, headers: { Location: authorizeUrl({ clientId, redirectUri, state }) } });
}

async function handleCallback(url: URL, env: Env, ownerId: string): Promise<Response> {
  const redirectUri = signInRedirectUri(env.OAUTH_REDIRECT_BASE);
  if (!redirectUri) return signInPage(REDIRECT_NOT_CONFIGURED, 503);
  const param = (name: string) => {
    const value = url.searchParams.get(name);
    return value && /^[\x21-\x7e]{1,2048}$/.test(value) ? value : null;
  };
  const owner = env.OWNER.get(env.OWNER.idFromName(ownerId));
  const result = await owner.completeSignIn({
    state: param("state") ?? "",
    code: param("code"),
    error: url.searchParams.has("error") ? "error" : null,
    redirectUri,
  });
  if (result.ok) return signInPage(`Tesla sign-in updated, scopes: ${result.scope || "none reported"}`, 200);
  const [message, status] = SIGN_IN_FAILURES[result.reason];
  return signInPage(message, status);
}

async function handleMcp(request: Request, env: Env, authenticator: McpAuthenticator): Promise<Response> {
  const auth = await authenticator.authenticate(request, env);
  if (!auth.ok) return auth.response;

  let forwarded = request;
  if (request.method === "POST") {
    const body = await readBoundedBody(request, MAX_MCP_BODY_BYTES);
    if (!body) {
      return Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Request body too large." } },
        { status: 413 },
      );
    }
    forwarded = new Request(request, { body });
  }
  const owner = env.OWNER.get(env.OWNER.idFromName(auth.principal.ownerId));
  // Stateless Streamable HTTP: a fresh server per request, no session state.
  const handler = createMcpHandler(() => createMcpServer(env, owner), {
    legacy: "stateless",
    responseMode: "auto",
    maxRequestBodySize: MAX_MCP_BODY_BYTES,
  });
  const response = await handler.fetch(forwarded);
  await handler.close();
  return response;
}

export type RouteOptions = {
  /** Authenticates /mcp; tests substitute their own. */
  authenticator?: McpAuthenticator;
  /** The OwnerState browser sign-in updates (the single owner; tests pass their own). */
  signInOwnerId?: string;
};

async function route(request: Request, env: Env, ctx: ExecutionContext, options: RouteOptions): Promise<Response> {
  const url = new URL(request.url);
  const read = request.method === "GET" || request.method === "HEAD";
  // Preflights are answered before any authentication.
  if (request.method === "OPTIONS" && corsPath(url.pathname)) return new Response(null, { status: 204 });
  if (url.pathname === MCP_PATH) return handleMcp(request, env, options.authenticator ?? bearerTokenAuthenticator);
  if (read && url.pathname === "/") return text(HOME_PAGE, 200, "text/html; charset=utf-8");
  if (read && url.pathname === "/healthz") return Response.json({ status: "ok", service: "tesla-mcp" });
  if (read && url.pathname === PUBLIC_KEY_PATH) {
    const response = text(env.TESLA_PUBLIC_KEY_PEM, 200, "application/x-pem-file");
    response.headers.set("Cache-Control", "public, max-age=3600");
    return response;
  }
  if (read && PROTECTED_RESOURCE_METADATA_PATHS.includes(url.pathname)) return protectedResourceMetadata(url.origin);
  // GET only: a HEAD (a link check, a prefetch) must not create or consume a sign-in.
  const signInOwnerId = options.signInOwnerId ?? OWNER_ID;
  if (request.method === "GET" && url.pathname === "/login") return handleLogin(env, signInOwnerId);
  if (request.method === "GET" && url.pathname === "/callback") return handleCallback(url, env, signInOwnerId);

  const oauthPath =
    url.pathname === AUTHORIZATION_SERVER_METADATA_PATH ||
    url.pathname === AUTHORIZE_PATH ||
    url.pathname === TOKEN_PATH ||
    url.pathname === REGISTER_PATH ||
    isAdminClientsPath(url.pathname);
  if (oauthPath) {
    const server = authorizationServer(url, env);
    if (!server) return text("Not found\n", 404);
    if (url.pathname === AUTHORIZE_PATH) return handleAuthorize(request, env, server);
    if (isAdminClientsPath(url.pathname)) return handleAdminClients(request, env, server);
    return server.fetch(request, env, ctx);
  }
  return text("Not found\n", 404);
}

export async function handleRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  options: RouteOptions = {},
): Promise<Response> {
  const response = await route(request, env, ctx, options);
  const secured = secure(response);
  return corsPath(new URL(request.url).pathname) ? withCors(secured) : secured;
}
