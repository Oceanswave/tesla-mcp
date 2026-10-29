import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OwnerState } from "../src/owner/state";
import { decryptTokens, importTokenKey } from "../src/owner/tokens";
import { handleRequest } from "../src/routes";
import { accessTokenClaims } from "../src/tesla/oauth";
import { FakeTesla, uniqueName } from "./helpers/fake-tesla";
import type { ToolResult } from "./helpers/mcp";

afterEach(() => {
  vi.restoreAllMocks();
});

const BASE = "https://tesla-mcp.example";
/** OAUTH_REDIRECT_BASE (vitest.config.ts, with a trailing slash) + /callback:
 * another host than BASE, so nothing comes from the request. */
const REDIRECT_URI = "https://sign-in.example.net/callback";
const SCOPES = [
  "openid",
  "offline_access",
  "vehicle_device_data",
  "vehicle_cmds",
  "vehicle_location",
  "vehicle_charging_cmds",
  "user_data",
  "energy_device_data",
  "energy_cmds",
];

function base64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** An unsigned JWT-shaped access token, as Tesla's carries `sub` and `scp`. */
function accessToken(sub: string, scp: string[]): string {
  return `${base64url({ alg: "RS256", typ: "JWT" })}.${base64url({ sub, scp, nonce: crypto.randomUUID() })}.sig`;
}

/** A fake Tesla whose token endpoint issues JWT access tokens for `sub`
 * (per grant type when it is a function). */
function tesla(
  sub: string | ((grantType: string | null) => string) = "owner-account",
  scope: string | null = SCOPES.join(" "),
): FakeTesla {
  const fake = new FakeTesla();
  fake.tokenResponder = (form) => {
    const access = accessToken(typeof sub === "string" ? sub : sub(form.get("grant_type")), SCOPES);
    const refresh = `refresh-${crypto.randomUUID()}`;
    fake.issuedAccessTokens.push(access);
    fake.issuedRefreshTokens.push(refresh);
    return Response.json({
      access_token: access,
      refresh_token: refresh,
      expires_in: 28_800,
      token_type: "Bearer",
      ...(scope === null ? {} : { scope }),
    });
  };
  fake.install();
  return fake;
}

function browser(ownerId: string, overrides: Partial<typeof env> = {}) {
  const get = (path: string, method = "GET") =>
    handleRequest(new Request(`${BASE}${path}`, { method }), { ...env, ...overrides }, undefined, ownerId);
  return {
    get,
    /** GET /login and return the state from Tesla's authorize URL. */
    async login(): Promise<string> {
      const response = await get("/login");
      expect(response.status).toBe(302);
      return new URL(response.headers.get("Location") as string).searchParams.get("state") as string;
    },
  };
}

function owner(ownerId: string) {
  return env.OWNER.get(env.OWNER.idFromName(ownerId));
}

async function storedTokens(ownerId: string) {
  return runInDurableObject(owner(ownerId), async (_instance: OwnerState, state) => {
    const blob = state.storage.sql.exec<{ value: string }>("SELECT value FROM kv WHERE key = 'tokens'").toArray()[0];
    return blob ? decryptTokens(await importTokenKey(env.TOKEN_ENCRYPTION_KEY), blob.value) : null;
  });
}

describe("GET /login", () => {
  it("redirects to Tesla's authorize page with all nine scopes and a fresh state", async () => {
    const ownerId = uniqueName("login");
    const response = await browser(ownerId).get("/login");
    expect(response.status).toBe(302);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    const location = new URL(response.headers.get("Location") as string);
    expect(`${location.origin}${location.pathname}`).toBe("https://auth.tesla.com/oauth2/v3/authorize");
    const params = location.searchParams;
    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe("test-client-id");
    expect(params.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(params.get("scope")).toBe(SCOPES.join(" "));
    expect(params.get("scope")?.split(" ")).toHaveLength(9);
    expect(params.get("prompt_missing_scopes")).toBe("true");
    expect(params.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await browser(ownerId).login()).not.toBe(params.get("state"));
  });

  it("takes the redirect URI from OAUTH_REDIRECT_BASE whatever the request host", async () => {
    const ownerId = uniqueName("login");
    for (const host of ["https://tesla-mcp.example", "https://attacker.example", "http://localhost:8787"]) {
      const response = await handleRequest(new Request(`${host}/login`), env, undefined, ownerId);
      expect(new URL(response.headers.get("Location") as string).searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    }
    const custom = await browser(ownerId, { OAUTH_REDIRECT_BASE: " https://cars.example.net/base// " }).get("/login");
    expect(new URL(custom.headers.get("Location") as string).searchParams.get("redirect_uri")).toBe(
      "https://cars.example.net/base/callback",
    );
  });

  it("shows a configuration error when OAUTH_REDIRECT_BASE or the client id is unusable", async () => {
    const ownerId = uniqueName("login");
    for (const base of [
      "",
      "   ",
      "not a url",
      "javascript:alert(1)",
      "http://cars.example.net",
      "https://user:pass@cars.example.net",
      "https://cars.example.net/?next=x",
      "https://cars.example.net/#x",
    ]) {
      for (const path of ["/login", "/callback?code=abc&state=x"]) {
        const response = await browser(ownerId, { OAUTH_REDIRECT_BASE: base }).get(path);
        expect(response.status).toBe(503);
        expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
        expect(await response.text()).toContain("OAUTH_REDIRECT_BASE must be an https URL");
      }
    }
    const { OAUTH_REDIRECT_BASE: _omitted, ...missing } = env;
    const unset = await handleRequest(new Request(`${BASE}/login`), missing as typeof env, undefined, ownerId);
    expect(unset.status).toBe(503);
    expect((await browser(ownerId, { TESLA_CLIENT_ID: "" }).get("/login")).status).toBe(503);
    // HEAD never creates a sign-in.
    expect((await browser(ownerId).get("/login", "HEAD")).status).toBe(404);
  });
});

describe("GET /callback", () => {
  it("exchanges the code, replaces the stored tokens, and shows only the granted scopes", async () => {
    const fake = tesla();
    const ownerId = uniqueName("callback");
    // An earlier sign-in through the bootstrap token.
    expect(await owner(ownerId).listVehicles()).toMatchObject({ ok: true });
    const before = await storedTokens(ownerId);

    const flow = browser(ownerId);
    const state = await flow.login();
    const code = `code-${crypto.randomUUID()}`;
    const response = await flow.get(`/callback?code=${code}&state=${state}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const page = await response.text();
    expect(page).toContain(`Tesla sign-in updated, scopes: ${SCOPES.join(" ")}`);
    for (const secret of [code, state, ...fake.issuedAccessTokens, ...fake.issuedRefreshTokens]) {
      expect(page).not.toContain(secret);
    }

    const form = fake.tokenRequests.at(-1) as URLSearchParams;
    expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "audience"]);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe(code);
    expect(form.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(form.get("audience")).toBe(env.TESLA_FLEET_BASE_URL);

    const after = await storedTokens(ownerId);
    expect(after?.refreshToken).toBe(fake.issuedRefreshTokens.at(-1));
    expect(after?.refreshToken).not.toBe(before?.refreshToken);
    expect(after?.accessToken).toBe(fake.issuedAccessTokens.at(-1));

    const status = await owner(ownerId).authStatus();
    expect(status).toEqual({ authState: "ok", message: null, scopes: SCOPES });
    const audit = await owner(ownerId).auditRecent(5);
    expect(audit[0]).toMatchObject({ action: "browser_sign_in", outcome: "ok", detail: "replaced stored tokens" });
    expect(JSON.stringify(audit)).not.toContain(code);
  });

  it("falls back to the token's scp claim when Tesla's answer has no scope", async () => {
    tesla("owner-account", null);
    const flow = browser(uniqueName("callback"));
    const page = await (await flow.get(`/callback?code=abc&state=${await flow.login()}`)).text();
    expect(page).toContain(`scopes: ${SCOPES.join(" ")}`);
  });

  it("escapes and filters what Tesla returns as the scope", async () => {
    tesla("owner-account", 'openid <script>alert("x")</script> vehicle_cmds');
    const flow = browser(uniqueName("callback"));
    const page = await (await flow.get(`/callback?code=abc&state=${await flow.login()}`)).text();
    expect(page).not.toContain("<script>");
    expect(page).toContain("scopes: openid vehicle_cmds");
  });

  it("accepts each state exactly once", async () => {
    const fake = tesla();
    const flow = browser(uniqueName("callback"));
    const state = await flow.login();
    expect((await flow.get(`/callback?code=first&state=${state}`)).status).toBe(200);
    const replay = await flow.get(`/callback?code=second&state=${state}`);
    expect(replay.status).toBe(400);
    const page = await replay.text();
    expect(page).toMatch(/missing, expired, or already used/);
    expect(page).not.toContain("second");
    const codes = fake.tokenRequests.filter((form) => form.get("grant_type") === "authorization_code");
    expect(codes.map((form) => form.get("code"))).toEqual(["first"]);
  });

  it("rejects missing, unknown, malformed, and expired states without calling Tesla", async () => {
    const fake = tesla();
    const ownerId = uniqueName("callback");
    const flow = browser(ownerId);
    const other = await browser(uniqueName("callback")).login();
    for (const query of [
      "?code=abc",
      "",
      "?code=abc&state=",
      `?code=abc&state=${"A".repeat(43)}`,
      `?code=abc&state=${other}`,
      "?code=abc&state=%3Cscript%3E",
    ]) {
      const response = await flow.get(`/callback${query}`);
      expect(response.status, query).toBe(400);
      expect(await response.text()).not.toMatch(/abc|<script>/);
    }

    const state = await flow.login();
    await runInDurableObject(owner(ownerId), (instance: OwnerState) => {
      const start = Date.now();
      instance.clock = () => start + 10 * 60_000 + 1;
    });
    expect((await flow.get(`/callback?code=abc&state=${state}`)).status).toBe(400);
    expect(fake.tokenRequests).toHaveLength(0);
  });

  it("refuses a state from before OAUTH_REDIRECT_BASE changed, without calling Tesla", async () => {
    const fake = tesla();
    const ownerId = uniqueName("callback");
    const state = await browser(ownerId).login();
    const moved = browser(ownerId, { OAUTH_REDIRECT_BASE: "https://cars.example.net" });
    const response = await moved.get(`/callback?code=abc&state=${state}`);
    expect(response.status).toBe(400);
    expect(await response.text()).toMatch(/Start again at \/login/);
    expect(fake.tokenRequests).toHaveLength(0);
  });

  it("consumes the state when Tesla reports an error, without echoing it", async () => {
    const fake = tesla();
    const flow = browser(uniqueName("callback"));
    const state = await flow.login();
    const denied = await flow.get(`/callback?error=access_denied&error_description=%3Cb%3Eno%3C%2Fb%3E&state=${state}`);
    expect(denied.status).toBe(400);
    const page = await denied.text();
    expect(page).toMatch(/cancelled or refused/);
    expect(page).not.toMatch(/access_denied|<b>/);
    expect((await flow.get(`/callback?code=abc&state=${state}`)).status).toBe(400);
    expect(fake.tokenRequests).toHaveLength(0);
  });

  it("leaves the stored sign-in alone when Tesla refuses the code", async () => {
    const fake = tesla();
    const ownerId = uniqueName("callback");
    expect(await owner(ownerId).listVehicles()).toMatchObject({ ok: true });
    const before = await storedTokens(ownerId);
    fake.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    const flow = browser(ownerId);
    const response = await flow.get(`/callback?code=used-code&state=${await flow.login()}`);
    expect(response.status).toBe(502);
    expect(await response.text()).not.toContain("used-code");
    expect(await storedTokens(ownerId)).toEqual(before);
    // A refused code is not a refused refresh token.
    expect((await owner(ownerId).authStatus()).authState).toBe("ok");
  });

  it("refuses a different Tesla account once one is signed in", async () => {
    tesla("owner-account");
    const ownerId = uniqueName("callback");
    expect(await owner(ownerId).listVehicles()).toMatchObject({ ok: true });
    const before = await storedTokens(ownerId);
    vi.restoreAllMocks();
    tesla("someone-else");
    const flow = browser(ownerId);
    const response = await flow.get(`/callback?code=abc&state=${await flow.login()}`);
    expect(response.status).toBe(403);
    expect(await response.text()).toMatch(/different Tesla account/);
    expect(await storedTokens(ownerId)).toEqual(before);
    expect((await owner(ownerId).auditRecent(1))[0]).toMatchObject({ outcome: "denied", detail: "account_mismatch" });
  });

  it("signs in after reauth_required, and the bootstrap token never overrides it", async () => {
    const fake = tesla();
    fake.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    const ownerId = uniqueName("callback");
    // The bootstrap token was never seeded before Tesla rejected it.
    expect(await owner(ownerId).listVehicles()).toMatchObject({ ok: false, error: { code: "reauth_required" } });
    vi.restoreAllMocks();
    const healthy = tesla();
    const flow = browser(ownerId);
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(200);
    expect((await owner(ownerId).authStatus()).authState).toBe("ok");
    expect(await owner(ownerId).listVehicles()).toMatchObject({ ok: true });
    // The Fleet call used the browser sign-in's token: no refresh, no re-seed.
    expect(healthy.tokenRequests).toHaveLength(1);
    expect(healthy.fleetRequests.at(-1)?.authorization).toBe(`Bearer ${healthy.issuedAccessTokens[0]}`);
    // When it expires, the refresh uses the browser sign-in's refresh token.
    await runInDurableObject(owner(ownerId), async (instance: OwnerState) => {
      instance.clock = () => Date.now() + 8 * 3_600_000;
      await instance.getAccessToken();
    });
    expect(healthy.tokenRequests.at(-1)?.get("refresh_token")).toBe(healthy.issuedRefreshTokens[0]);
  });

  it("keeps the account pinned after a re-seed leaves no access token", async () => {
    const fake = tesla("owner-account");
    const ownerId = uniqueName("callback");
    expect(await owner(ownerId).listVehicles()).toMatchObject({ ok: true });
    // A new bootstrap value that Tesla rejects: stored tokens now hold no access token.
    fake.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    await runInDurableObject(owner(ownerId), async (instance: OwnerState) => {
      Object.assign(instance, { env: { ...env, TESLA_BOOTSTRAP_REFRESH_TOKEN: "rejected-bootstrap-token" } });
      await expect(instance.getAccessToken()).rejects.toThrow(/sign-in has expired/);
    });
    expect((await storedTokens(ownerId))?.accessToken).toBeNull();
    vi.restoreAllMocks();
    tesla("someone-else");
    const flow = browser(ownerId);
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(403);
    vi.restoreAllMocks();
    tesla("owner-account");
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(200);
    expect((await owner(ownerId).authStatus()).authState).toBe("ok");
  });

  it("tries a bootstrap token not used yet before the code, and pins to its account", async () => {
    const fake = tesla((grantType) => (grantType === "refresh_token" ? "owner-account" : "someone-else"));
    const ownerId = uniqueName("callback");
    const flow = browser(ownerId);
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(403);
    expect(fake.tokenRequests.map((form) => form.get("grant_type"))).toEqual(["refresh_token", "authorization_code"]);
    expect(fake.tokenRequests[0]?.get("refresh_token")).toBe(env.TESLA_BOOTSTRAP_REFRESH_TOKEN);
    // The bootstrap sign-in stays in place.
    expect((await storedTokens(ownerId))?.refreshToken).toBe(fake.issuedRefreshTokens[0]);
  });

  it("lets the first sign-in name the account on a server that never had one", async () => {
    tesla("first-account");
    const ownerId = uniqueName("callback");
    const flow = browser(ownerId);
    await runInDurableObject(owner(ownerId), (instance: OwnerState) => {
      Object.assign(instance, { env: { ...env, TESLA_BOOTSTRAP_REFRESH_TOKEN: "" } });
    });
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(200);
    vi.restoreAllMocks();
    tesla("second-account");
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(403);
  });

  it("sends client_secret when configured", async () => {
    const fake = tesla();
    const secret = `secret-${crypto.randomUUID()}`;
    await runInDurableObject(owner(uniqueName("callback")), async (instance: OwnerState) => {
      Object.assign(instance, { env: { ...env, TESLA_CLIENT_SECRET: secret } });
      const state = await instance.beginSignIn(REDIRECT_URI);
      expect(
        await instance.completeSignIn({ state, code: "abc", error: null, redirectUri: REDIRECT_URI }),
      ).toMatchObject({ ok: true });
    });
    expect(fake.tokenRequests.at(-1)?.get("grant_type")).toBe("authorization_code");
    expect(fake.tokenRequests.at(-1)?.get("client_secret")).toBe(secret);
  });

  it("keeps the MCP tools working on the new sign-in", async () => {
    const fake = tesla();
    const ownerId = uniqueName("callback");
    const flow = browser(ownerId);
    expect((await flow.get(`/callback?code=abc&state=${await flow.login()}`)).status).toBe(200);

    const client = new Client({ name: "tesla-mcp-test", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), {
      fetch: (url, init) =>
        handleRequest(new Request(url, init), env, {
          authenticate: async () => ({ ok: true, principal: { ownerId } }),
        }),
    });
    await client.connect(transport);
    const listed = (await client.callTool({ name: "tesla_vehicles_list", arguments: {} })) as ToolResult;
    expect(listed.structuredContent?.vehicles).toEqual([{ id: fake.vehicleId, name: "Test Car", state: "online" }]);
    expect(fake.fleetRequests.at(-1)?.authorization).toBe(`Bearer ${fake.issuedAccessTokens.at(-1)}`);
    const status = (await client.callTool({ name: "tesla_auth_status", arguments: {} })) as ToolResult;
    expect(status.structuredContent).toMatchObject({ authState: "ok", scopes: SCOPES });
    for (const token of fake.issuedAccessTokens) expect(JSON.stringify(status)).not.toContain(token);
    await client.close();
  });
});

describe("access token claims", () => {
  it("reads sub and scp, and nothing from tokens that are not JWTs", () => {
    expect(accessTokenClaims(accessToken("abc", ["openid", "vehicle_cmds"]))).toEqual({
      sub: "abc",
      scopes: ["openid", "vehicle_cmds"],
    });
    for (const token of [null, "", "opaque-token", "a.!!!.c", `a.${btoa("[1]")}.c`]) {
      expect(accessTokenClaims(token)).toEqual({ sub: null, scopes: null });
    }
  });
});
