import { createExecutionContext, SELF } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { bytesToBase64, sha256 } from "../src/bytes";
import { PASSPHRASE_FAILURE_LIMIT } from "../src/oauth/authorize";
import { handleRequest } from "../src/routes";
import type { ToolResult } from "./helpers/mcp";

const BASE = "https://tesla-mcp.example";
const RESOURCE = `${BASE}/mcp`;
const CLAUDE = "https://claude.ai/api/mcp/auth_callback";
const PASSPHRASE = env.OAUTH_ADMIN_PASSPHRASE as string;
const ADMIN = { Authorization: `Bearer ${env.MCP_BEARER_TOKEN}` };
const INIT = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } },
});

const base64url = (bytes: Uint8Array) =>
  bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Each test gets its own client IP, so the passphrase limit never leaks
 * between tests. */
const uniqueIp = () => `198.51.100.${Math.floor(Math.random() * 250) + 1}-${crypto.randomUUID()}`;

async function pkce() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(await sha256(new TextEncoder().encode(verifier)));
  return { verifier, challenge };
}

function mcpPost(authorization?: string, origin = BASE): Request {
  return new Request(`${origin}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(authorization ? { Authorization: authorization } : {}),
    },
    body: INIT,
  });
}

async function register(redirectUris: unknown, name = "Test DCR client") {
  return SELF.fetch(`${BASE}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    }),
  });
}

async function publicClient(redirectUri = CLAUDE): Promise<string> {
  const response = await register([redirectUri]);
  expect(response.status).toBe(201);
  return ((await response.json()) as { client_id: string }).client_id;
}

function authorizeUrl(clientId: string, challenge: string | null, redirectUri = CLAUDE): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: "state-123",
    resource: RESOURCE,
  });
  if (challenge) {
    params.set("code_challenge", challenge);
    params.set("code_challenge_method", "S256");
  }
  return `${BASE}/authorize?${params}`;
}

function csrfFrom(html: string): string {
  const token = /name="csrf_token" value="([0-9a-f]{64})"/.exec(html)?.[1];
  if (!token) throw new Error("no csrf token on the page");
  return token;
}

async function approvalPage(url: string): Promise<string> {
  const page = await SELF.fetch(url, { redirect: "manual" });
  expect(page.status).toBe(200);
  return csrfFrom(await page.text());
}

function approve(url: string, fields: Record<string, string>, ip: string) {
  return SELF.fetch(url, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "CF-Connecting-IP": ip },
    body: new URLSearchParams(fields),
  });
}

/** Walk /authorize with the passphrase and return the authorization code. */
async function authorizationCode(clientId: string, challenge: string): Promise<string> {
  const url = authorizeUrl(clientId, challenge);
  const csrf_token = await approvalPage(url);
  const approved = await approve(url, { csrf_token, passphrase: PASSPHRASE }, uniqueIp());
  expect(approved.status).toBe(302);
  const location = new URL(approved.headers.get("Location") as string);
  expect(`${location.origin}${location.pathname}`).toBe(CLAUDE);
  expect(location.searchParams.get("state")).toBe("state-123");
  return location.searchParams.get("code") as string;
}

function token(fields: Record<string, string>, headers: Record<string, string> = {}) {
  return SELF.fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(fields),
  });
}

type Tokens = { access_token: string; refresh_token: string; token_type: string };

async function signIn(): Promise<{ clientId: string; tokens: Tokens }> {
  const clientId = await publicClient();
  const { verifier, challenge } = await pkce();
  const code = await authorizationCode(clientId, challenge);
  const issued = await token({
    grant_type: "authorization_code",
    code,
    redirect_uri: CLAUDE,
    client_id: clientId,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  expect(issued.status).toBe(200);
  return { clientId, tokens: (await issued.json()) as Tokens };
}

describe("OAuth discovery", () => {
  it("publishes authorization server metadata with CORS", async () => {
    const response = await SELF.fetch(`${BASE}/.well-known/oauth-authorization-server`, {
      headers: { Origin: "https://claude.ai" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toMatch(/^application\/json/);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const metadata = (await response.json()) as Record<string, unknown>;
    expect(metadata).toMatchObject({
      issuer: BASE,
      authorization_endpoint: `${BASE}/authorize`,
      token_endpoint: `${BASE}/token`,
      registration_endpoint: `${BASE}/register`,
      code_challenge_methods_supported: ["S256"],
    });
    expect(metadata.grant_types_supported).toEqual(expect.arrayContaining(["authorization_code", "refresh_token"]));
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(
      expect.arrayContaining(["none", "client_secret_post", "client_secret_basic"]),
    );
  });

  it("publishes protected resource metadata at both paths, for the request's host", async () => {
    for (const origin of [BASE, "https://other-host.example"]) {
      for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
        const response = await SELF.fetch(`${origin}${path}`);
        expect(response.status).toBe(200);
        expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
        expect(await response.json()).toMatchObject({ resource: `${origin}/mcp`, authorization_servers: [origin] });
      }
    }
  });

  it("answers CORS preflights before authentication", async () => {
    for (const path of ["/mcp", "/token", "/register", "/.well-known/oauth-authorization-server"]) {
      const response = await SELF.fetch(`${BASE}${path}`, {
        method: "OPTIONS",
        headers: {
          Origin: "https://claude.ai",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "authorization, content-type, mcp-session-id",
        },
      });
      expect(response.status, path).toBe(204);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
      const allowed = response.headers.get("Access-Control-Allow-Headers") ?? "";
      for (const header of ["Authorization", "Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version"]) {
        expect(allowed).toContain(header);
      }
      expect(response.headers.get("Access-Control-Expose-Headers")).toContain("WWW-Authenticate");
    }
  });

  it("points a 401 from /mcp at the protected resource metadata for the request's host", async () => {
    for (const origin of [BASE, "https://other-host.example"]) {
      for (const authorization of [undefined, "Bearer wrong", "Bearer owner:grant:secret"]) {
        const response = await SELF.fetch(mcpPost(authorization, origin));
        expect(response.status).toBe(401);
        expect(response.headers.get("WWW-Authenticate")).toContain(
          `resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
        );
        expect(response.headers.get("Access-Control-Expose-Headers")).toContain("WWW-Authenticate");
      }
    }
  });
});

describe("dynamic client registration", () => {
  it("registers clients whose redirect URIs are allowed", async () => {
    for (const uris of [
      [CLAUDE],
      ["https://claude.com/api/mcp/auth_callback"],
      ["http://localhost:6274/oauth/callback"],
      ["http://127.0.0.1:33418/callback", CLAUDE],
    ]) {
      const response = await register(uris);
      expect(response.status, uris.join()).toBe(201);
      const body = (await response.json()) as { client_id: string; redirect_uris: string[] };
      expect(body.client_id).toBeTruthy();
      expect(body.redirect_uris).toEqual(uris);
    }
  });

  it("rejects any other redirect URI", async () => {
    for (const uris of [
      ["https://evil.example/callback"],
      [CLAUDE, "https://evil.example/callback"],
      ["https://claude.ai/api/mcp/auth_callback/extra"],
      ["http://[::1]:8080/callback"],
    ]) {
      const response = await register(uris);
      expect(response.status, JSON.stringify(uris)).toBe(400);
      expect(await response.json(), JSON.stringify(uris)).toMatchObject({ error: "invalid_redirect_uri" });
    }
    // Malformed lists and remote http never reach the allowlist: the library refuses them first.
    for (const uris of [[], "https://claude.ai/api/mcp/auth_callback", ["http://localhost.evil.example/callback"]]) {
      const response = await register(uris);
      expect(response.status, JSON.stringify(uris)).toBe(400);
    }
  });

  it("accepts the extra redirect URIs the owner configured", async () => {
    const extra = "https://agent.example/oauth/callback";
    const request = (uris: string[]) =>
      new Request(`${BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_name: "extra", redirect_uris: uris, token_endpoint_auth_method: "none" }),
      });
    const configured = { ...env, OAUTH_EXTRA_REDIRECT_URIS: ` ${extra} , https://second.example/cb` };
    expect((await handleRequest(request([extra]), configured, createExecutionContext())).status).toBe(201);
    expect((await handleRequest(request([extra]), env, createExecutionContext())).status).toBe(400);
  });
});

describe("authorization code flow with PKCE", () => {
  it("issues tokens that work on /mcp, and rotates refresh tokens", async () => {
    const { clientId, tokens } = await signIn();
    expect(tokens.token_type.toLowerCase()).toBe("bearer");
    const mcp = await SELF.fetch(mcpPost(`Bearer ${tokens.access_token}`));
    expect(mcp.status).toBe(200);

    const refresh = (refresh_token: string) =>
      token({ grant_type: "refresh_token", refresh_token, client_id: clientId });
    const second = await refresh(tokens.refresh_token);
    expect(second.status).toBe(200);
    const rotated = (await second.json()) as Tokens;
    expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
    expect((await SELF.fetch(mcpPost(`Bearer ${rotated.access_token}`))).status).toBe(200);
    // Using the new refresh token retires the old one for good.
    expect((await refresh(rotated.refresh_token)).status).toBe(200);
    const reused = await refresh(tokens.refresh_token);
    expect(reused.status).toBe(400);
    expect(await reused.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("rejects the code with a wrong PKCE verifier", async () => {
    const clientId = await publicClient();
    const { challenge } = await pkce();
    const code = await authorizationCode(clientId, challenge);
    const response = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: CLAUDE,
      client_id: clientId,
      code_verifier: (await pkce()).verifier,
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("requires PKCE S256 even from a confidential client", async () => {
    const created = await SELF.fetch(`${BASE}/admin/clients`, {
      method: "POST",
      headers: { ...ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "no-pkce agent" }),
    });
    const { client_id } = (await created.json()) as { client_id: string };
    const response = await SELF.fetch(authorizeUrl(client_id, null), { redirect: "manual" });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("Location") as string);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("code")).toBeNull();
  });

  it("never stores tokens in plaintext", async () => {
    const { tokens } = await signIn();
    const listed = await env.OAUTH_KV.list();
    const values = await Promise.all(listed.keys.map((key) => env.OAUTH_KV.get(key.name)));
    const stored = JSON.stringify([listed.keys.map((key) => key.name), values]);
    expect(stored).not.toContain(tokens.access_token);
    expect(stored).not.toContain(tokens.refresh_token);
    expect(stored).not.toContain(tokens.access_token.split(":")[2]);
    expect(stored).not.toContain(PASSPHRASE);
  });
});

describe("/authorize approval", () => {
  it("shows the client name and redirect URI, escaped", async () => {
    const response = await register([CLAUDE], "<b>Claude</b>");
    const { client_id } = (await response.json()) as { client_id: string };
    const page = await SELF.fetch(authorizeUrl(client_id, (await pkce()).challenge));
    const html = await page.text();
    expect(html).toContain("&lt;b&gt;Claude&lt;/b&gt;");
    expect(html).not.toContain("<b>Claude</b>");
    expect(html).toContain(CLAUDE);
    expect(page.headers.get("X-Frame-Options")).toBe("DENY");
  });

  it("rejects a wrong passphrase and issues no code", async () => {
    const url = authorizeUrl(await publicClient(), (await pkce()).challenge);
    const response = await approve(url, { csrf_token: await approvalPage(url), passphrase: "wrong" }, uniqueIp());
    expect(response.status).toBe(403);
    expect(response.headers.get("Location")).toBeNull();
    expect(await response.text()).toContain("Wrong passphrase");
  });

  it("rejects a missing, foreign, or reused CSRF token even with the right passphrase", async () => {
    const url = authorizeUrl(await publicClient(), (await pkce()).challenge);
    const ip = uniqueIp();
    expect((await approve(url, { passphrase: PASSPHRASE }, ip)).status).toBe(403);
    expect((await approve(url, { csrf_token: "0".repeat(64), passphrase: PASSPHRASE }, ip)).status).toBe(403);
    // A token issued for another request does not carry over.
    const otherUrl = authorizeUrl(await publicClient(), (await pkce()).challenge);
    const foreign = await approvalPage(otherUrl);
    expect((await approve(url, { csrf_token: foreign, passphrase: PASSPHRASE }, ip)).status).toBe(403);
    const csrf_token = await approvalPage(url);
    expect((await approve(url, { csrf_token, passphrase: PASSPHRASE }, ip)).status).toBe(302);
    expect((await approve(url, { csrf_token, passphrase: PASSPHRASE }, ip)).status).toBe(403);
  });

  it(`locks out an IP after ${PASSPHRASE_FAILURE_LIMIT} wrong passphrases`, async () => {
    const url = authorizeUrl(await publicClient(), (await pkce()).challenge);
    const ip = uniqueIp();
    let csrf_token = await approvalPage(url);
    for (let attempt = 0; attempt < PASSPHRASE_FAILURE_LIMIT; attempt++) {
      const response = await approve(url, { csrf_token, passphrase: `wrong-${attempt}` }, ip);
      expect(response.status).toBe(403);
      csrf_token = csrfFrom(await response.text());
    }
    const locked = await approve(url, { csrf_token, passphrase: PASSPHRASE }, ip);
    expect(locked.status).toBe(429);
    expect(locked.headers.get("Retry-After")).toMatch(/^\d+$/);
    // Another IP is unaffected.
    const fresh = await approvalPage(url);
    expect((await approve(url, { csrf_token: fresh, passphrase: PASSPHRASE }, uniqueIp())).status).toBe(302);
  });

  it("refuses to approve anything while OAUTH_ADMIN_PASSPHRASE is unset", async () => {
    const url = authorizeUrl(await publicClient(), (await pkce()).challenge);
    for (const passphrase of [undefined, ""]) {
      const response = await handleRequest(
        new Request(url),
        { ...env, OAUTH_ADMIN_PASSPHRASE: passphrase },
        createExecutionContext(),
      );
      expect(response.status).toBe(503);
      expect(await response.text()).toContain("OAUTH_ADMIN_PASSPHRASE");
    }
  });

  it("renders unknown clients locally instead of redirecting", async () => {
    const response = await SELF.fetch(authorizeUrl("no-such-client", (await pkce()).challenge), {
      redirect: "manual",
    });
    expect(response.status).toBe(400);
    expect(response.headers.get("Location")).toBeNull();
  });
});

describe("static per-agent clients", () => {
  it("requires the static bearer token", async () => {
    const { tokens } = await signIn();
    const attempts: Record<string, string>[] = [
      {},
      { Authorization: "Bearer wrong" },
      { Authorization: `Bearer ${tokens.access_token}` },
    ];
    for (const headers of attempts) {
      expect((await SELF.fetch(`${BASE}/admin/clients`, { headers })).status).toBe(401);
    }
  });

  it("creates a client, shows its secret once, and revokes it with all its tokens", async () => {
    const created = await SELF.fetch(`${BASE}/admin/clients`, {
      method: "POST",
      headers: { ...ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "nightly-lock agent", redirect_uris: ["http://localhost:8976/callback"] }),
    });
    expect(created.status).toBe(201);
    const client = (await created.json()) as { client_id: string; client_secret: string; redirect_uris: string[] };
    expect(client.client_secret.length).toBeGreaterThan(20);
    expect(client.redirect_uris).toEqual(["http://localhost:8976/callback"]);

    const listed = await SELF.fetch(`${BASE}/admin/clients`, { headers: ADMIN });
    const raw = await listed.text();
    expect(raw).not.toContain(client.client_secret);
    expect(raw).not.toMatch(/"client_?secret"/i);
    expect((JSON.parse(raw) as { clients: { client_id: string }[] }).clients).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ client_id: client.client_id, client_name: "nightly-lock agent" }),
      ]),
    );

    // Sign in as the agent: PKCE plus its secret over client_secret_basic.
    const redirect = "http://localhost:8976/callback";
    const { verifier, challenge } = await pkce();
    const url = authorizeUrl(client.client_id, challenge, redirect);
    const approved = await approve(url, { csrf_token: await approvalPage(url), passphrase: PASSPHRASE }, uniqueIp());
    const code = new URL(approved.headers.get("Location") as string).searchParams.get("code") as string;
    const basic = `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`;
    const issued = await token(
      { grant_type: "authorization_code", code, redirect_uri: redirect, code_verifier: verifier },
      { Authorization: basic },
    );
    expect(issued.status).toBe(200);
    const tokens = (await issued.json()) as Tokens;
    expect((await SELF.fetch(mcpPost(`Bearer ${tokens.access_token}`))).status).toBe(200);

    const revoked = await SELF.fetch(`${BASE}/admin/clients/${client.client_id}`, { method: "DELETE", headers: ADMIN });
    expect(revoked.status).toBe(200);
    expect((await SELF.fetch(mcpPost(`Bearer ${tokens.access_token}`))).status).toBe(401);
    const refreshed = await token(
      { grant_type: "refresh_token", refresh_token: tokens.refresh_token },
      { Authorization: basic },
    );
    expect(refreshed.ok).toBe(false);
    expect(
      (await SELF.fetch(`${BASE}/admin/clients/${client.client_id}`, { method: "DELETE", headers: ADMIN })).status,
    ).toBe(404);
  });

  it("rejects redirect URIs off the allowlist", async () => {
    const response = await SELF.fetch(`${BASE}/admin/clients`, {
      method: "POST",
      headers: { ...ADMIN, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "bad", redirect_uris: ["https://evil.example/cb"] }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_redirect_uri" });
  });
});

describe("/mcp with OAuth tokens", () => {
  it("accepts both the static bearer token and an OAuth access token", async () => {
    expect((await SELF.fetch(mcpPost(`Bearer ${env.MCP_BEARER_TOKEN}`))).status).toBe(200);
    const { tokens } = await signIn();
    expect((await SELF.fetch(mcpPost(`Bearer ${tokens.access_token}`))).status).toBe(200);
    // A refresh token is not an access token.
    expect((await SELF.fetch(mcpPost(`Bearer ${tokens.refresh_token}`))).status).toBe(401);
  });

  it("still needs confirm: true for state-changing tools", async () => {
    const { tokens } = await signIn();
    const client = new Client({ name: "oauth-test", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(RESOURCE), {
      fetch: (url, init) => SELF.fetch(new Request(url, init)),
      requestInit: { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    });
    await client.connect(transport);
    for (const name of ["tesla_lock", "tesla_wake"]) {
      const result = (await client.callTool({ name, arguments: {} })) as ToolResult;
      expect(result.isError).toBe(true);
      expect(result.structuredContent?.error).toBe("confirmation_required");
    }
    await client.close();
  });
});
