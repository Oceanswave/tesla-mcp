// /authorize: the owner approves an MCP client by typing OAUTH_ADMIN_PASSPHRASE.
// The library parses and validates the request (client, registered redirect
// URI, PKCE method); this page adds the redirect allowlist, requires PKCE S256
// for every client, and guards the passphrase with a one-time approval token
// bound to the exact request and a per-IP limit on wrong attempts.

import {
  AuthorizationError,
  type AuthRequest,
  authorizationErrorRedirect,
  type OAuthAuthorizationServer,
} from "@cloudflare/workers-oauth-provider";
import { OWNER_ID } from "../auth";
import { readBoundedBody } from "../body";
import { bytesToHex, secretsEqual, sha256 } from "../bytes";
import type { Env } from "../env";
import { escapeHtml, htmlPage } from "../html";
import { redirectUriAllowed } from "./redirects";

/** How long an approval page stays usable. */
const APPROVAL_TTL_SECONDS = 600;
/** Wrong passphrases allowed per IP per window. */
export const PASSPHRASE_FAILURE_LIMIT = 5;
export const PASSPHRASE_FAILURE_WINDOW_SECONDS = 900;
const MAX_FORM_BYTES = 4096;
/** KV never expires a key sooner than this. */
const KV_MIN_TTL_SECONDS = 60;

const encoder = new TextEncoder();

async function digest(value: string): Promise<string> {
  return bytesToHex(await sha256(encoder.encode(value)));
}

function message(title: string, text: string, status: number, headers: HeadersInit = {}): Response {
  return htmlPage(title, `<h1>${escapeHtml(title)}</h1>\n<p>${escapeHtml(text)}</p>`, status, headers);
}

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

// ---------------------------------------------------------------------------
// One-time approval tokens (CSRF). Stored hashed, bound to the request's query
// string, and deleted on first use.
// ---------------------------------------------------------------------------

async function issueApprovalToken(env: Env, url: URL): Promise<string> {
  const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  await env.OAUTH_KV.put(`approval:${await digest(token)}`, await digest(url.search), {
    expirationTtl: APPROVAL_TTL_SECONDS,
  });
  return token;
}

async function consumeApprovalToken(env: Env, url: URL, token: string): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(token)) return false;
  const key = `approval:${await digest(token)}`;
  const bound = await env.OAUTH_KV.get(key);
  if (bound === null) return false;
  await env.OAUTH_KV.delete(key);
  return bound === (await digest(url.search));
}

// ---------------------------------------------------------------------------
// Wrong-passphrase limit, per client IP, in a fixed window.
// ---------------------------------------------------------------------------

type FailureWindow = { count: number; resetAt: number };

function failureKey(ip: string): string {
  return `passphrase-failures:${ip}`;
}

async function failureWindow(env: Env, ip: string, now: number): Promise<FailureWindow | null> {
  const stored = await env.OAUTH_KV.get<FailureWindow>(failureKey(ip), "json");
  return stored && stored.resetAt > now ? stored : null;
}

async function recordFailure(env: Env, ip: string, now: number): Promise<void> {
  const current = (await failureWindow(env, ip, now)) ?? {
    count: 0,
    resetAt: now + PASSPHRASE_FAILURE_WINDOW_SECONDS,
  };
  const next = { count: current.count + 1, resetAt: current.resetAt };
  await env.OAUTH_KV.put(failureKey(ip), JSON.stringify(next), {
    expiration: Math.max(next.resetAt, now + KV_MIN_TTL_SECONDS),
  });
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

function approvalPage(
  url: URL,
  auth: AuthRequest,
  clientName: string,
  token: string,
  status = 200,
  notice?: string,
): Response {
  const action = `${url.pathname}${url.search}`;
  return htmlPage(
    "Approve MCP client",
    `<h1>Approve an MCP client</h1>
${notice ? `<p><strong>${escapeHtml(notice)}</strong></p>\n` : ""}<p><strong>${escapeHtml(clientName)}</strong> is asking to use this server's Tesla tools.</p>
<p>After approval it returns to: <code>${escapeHtml(auth.redirectUri)}</code></p>
<p>Only approve a connection you just started yourself.</p>
<form method="post" action="${escapeHtml(action)}">
<input type="hidden" name="csrf_token" value="${escapeHtml(token)}">
<label>Owner passphrase <input type="password" name="passphrase" autocomplete="current-password" required autofocus></label>
<button type="submit">Approve</button>
</form>`,
    status,
  );
}

export async function handleAuthorize(
  request: Request,
  env: Env,
  server: OAuthAuthorizationServer<Env>,
): Promise<Response> {
  if (request.method !== "GET" && request.method !== "POST") {
    return new Response("Method not allowed\n", { status: 405, headers: { Allow: "GET, POST" } });
  }
  const passphrase = env.OAUTH_ADMIN_PASSPHRASE;
  if (!passphrase) {
    return message(
      "Approval is not configured",
      "This server cannot approve MCP clients yet: the owner must set the OAUTH_ADMIN_PASSPHRASE secret (npx wrangler secret put OAUTH_ADMIN_PASSPHRASE).",
      503,
    );
  }
  const url = new URL(request.url);
  const oauth = server.getOAuthApi(env);

  let auth: AuthRequest;
  try {
    auth = await oauth.parseAuthRequest(request);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    // Redirect only to a validated URI that is still on the allowlist.
    if (error.redirectTo && error.redirectUri && redirectUriAllowed(error.redirectUri, env)) {
      return redirect(error.redirectTo);
    }
    return message("Invalid authorization request", error.description, 400);
  }
  if (!redirectUriAllowed(auth.redirectUri, env)) {
    return message("Invalid authorization request", "This redirect URI is not allowed on this server.", 400);
  }
  if (!auth.codeChallenge || auth.codeChallengeMethod !== "S256") {
    return redirect(
      authorizationErrorRedirect(auth, "invalid_request", "PKCE with code_challenge_method S256 is required."),
    );
  }
  const client = await oauth.lookupClient(auth.clientId);
  const clientName = client?.clientName?.trim() || "An unnamed client";

  if (request.method === "GET") return approvalPage(url, auth, clientName, await issueApprovalToken(env, url));

  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const now = Math.floor(Date.now() / 1000);
  const window = await failureWindow(env, ip, now);
  if (window && window.count >= PASSPHRASE_FAILURE_LIMIT) {
    return message("Too many attempts", "Too many wrong passphrases. Try again in 15 minutes.", 429, {
      "Retry-After": String(window.resetAt - now),
    });
  }

  const body = await readBoundedBody(request, MAX_FORM_BYTES);
  const form = body ? new URLSearchParams(new TextDecoder().decode(body)) : null;
  const token = form?.get("csrf_token") ?? "";
  if (!form || !(await consumeApprovalToken(env, url, token))) {
    return message(
      "Approval expired",
      "This approval form is missing its token, expired, or was already used. Start connecting again from your MCP client.",
      403,
    );
  }
  if (!(await secretsEqual(form.get("passphrase") ?? "", passphrase))) {
    await recordFailure(env, ip, now);
    return approvalPage(url, auth, clientName, await issueApprovalToken(env, url), 403, "Wrong passphrase.");
  }

  const { redirectTo } = await oauth.completeAuthorization({
    request: auth,
    userId: OWNER_ID,
    metadata: { approvedAt: new Date(now * 1000).toISOString() },
    scope: auth.scope,
    props: { ownerId: OWNER_ID },
  });
  return redirect(redirectTo);
}
