// HTTP routes: security headers, the public key, browser sign-in (/login and
// /callback), and the /mcp transport.
// Kept out of index.ts because the Worker entry module may only export
// handlers and Durable Object classes.

import { createMcpHandler } from "@modelcontextprotocol/server";
import { bearerTokenAuthenticator, type McpAuthenticator, OWNER_ID } from "./auth";
import type { Env } from "./env";
import { createMcpServer } from "./mcp/server";
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

function secure(response: Response, cache = "no-store"): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  if (!headers.has("Cache-Control")) headers.set("Cache-Control", cache);
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

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char,
  );
}

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

async function handleLogin(url: URL, env: Env, ownerId: string): Promise<Response> {
  const clientId = env.TESLA_CLIENT_ID?.trim();
  const redirectUri = signInRedirectUri(env.TESLA_REDIRECT_URI, url);
  if (!clientId || !redirectUri) return signInPage(SIGN_IN_FAILURES.not_configured[0], 503);
  const owner = env.OWNER.get(env.OWNER.idFromName(ownerId));
  const state = await owner.beginSignIn(redirectUri);
  return new Response(null, { status: 302, headers: { Location: authorizeUrl({ clientId, redirectUri, state }) } });
}

async function handleCallback(url: URL, env: Env, ownerId: string): Promise<Response> {
  const param = (name: string) => {
    const value = url.searchParams.get(name);
    return value && /^[\x21-\x7e]{1,2048}$/.test(value) ? value : null;
  };
  const owner = env.OWNER.get(env.OWNER.idFromName(ownerId));
  const result = await owner.completeSignIn({
    state: param("state") ?? "",
    code: param("code"),
    error: url.searchParams.has("error") ? "error" : null,
  });
  if (result.ok) return signInPage(`Tesla sign-in updated, scopes: ${result.scope || "none reported"}`, 200);
  const [message, status] = SIGN_IN_FAILURES[result.reason];
  return signInPage(message, status);
}

async function readBoundedBody(request: Request): Promise<Uint8Array | null> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_MCP_BODY_BYTES)) return null;
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_MCP_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function handleMcp(request: Request, env: Env, authenticator: McpAuthenticator): Promise<Response> {
  const auth = await authenticator.authenticate(request, env);
  if (!auth.ok) return auth.response;

  let forwarded = request;
  if (request.method === "POST") {
    const body = await readBoundedBody(request);
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

/** `signInOwnerId` names the OwnerState that browser sign-in updates (the
 * single owner; tests pass their own). */
export async function handleRequest(
  request: Request,
  env: Env,
  authenticator: McpAuthenticator = bearerTokenAuthenticator,
  signInOwnerId: string = OWNER_ID,
): Promise<Response> {
  const url = new URL(request.url);
  const read = request.method === "GET" || request.method === "HEAD";
  if (url.pathname === "/mcp") return secure(await handleMcp(request, env, authenticator));
  if (read && url.pathname === "/") return secure(text(HOME_PAGE, 200, "text/html; charset=utf-8"));
  if (read && url.pathname === "/healthz") {
    return secure(Response.json({ status: "ok", service: "tesla-mcp" }));
  }
  if (read && url.pathname === PUBLIC_KEY_PATH) {
    return secure(text(env.TESLA_PUBLIC_KEY_PEM, 200, "application/x-pem-file"), "public, max-age=3600");
  }
  // GET only: a HEAD (a link check, a prefetch) must not create or consume a sign-in.
  if (request.method === "GET" && url.pathname === "/login") return secure(await handleLogin(url, env, signInOwnerId));
  if (request.method === "GET" && url.pathname === "/callback") {
    return secure(await handleCallback(url, env, signInOwnerId));
  }
  return secure(text("Not found\n", 404));
}
