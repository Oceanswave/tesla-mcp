import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OwnerState } from "../src/owner/state";
import { decryptTokens, encryptTokens, importTokenKey, TOKEN_AAD } from "../src/owner/tokens";
import { FakeTesla, uniqueName } from "./helpers/fake-tesla";

afterEach(() => {
  vi.restoreAllMocks();
});

function ownerStub() {
  return env.OWNER.get(env.OWNER.idFromName(uniqueName("tokens")));
}

function storedBlob(state: DurableObjectState): string | undefined {
  return state.storage.sql.exec<{ value: string }>("SELECT value FROM kv WHERE key = 'tokens'").toArray()[0]?.value;
}

describe("token encryption", () => {
  it("round-trips and binds ciphertexts to the AAD", async () => {
    const key = await importTokenKey(env.TOKEN_ENCRYPTION_KEY);
    const tokens = { accessToken: "a-token", refreshToken: "r-token", expiresAt: 123 };
    const blob = await encryptTokens(key, tokens);
    expect(blob).not.toContain("r-token");
    expect(await decryptTokens(key, blob)).toEqual(tokens);
    // Fresh IV per encryption.
    expect(await encryptTokens(key, tokens)).not.toBe(blob);
    await expect(decryptTokens(key, blob, `${TOKEN_AAD}:other`)).rejects.toThrow("token_crypto_ciphertext_invalid");
    const otherKey = await importTokenKey(btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))));
    await expect(decryptTokens(otherKey, blob)).rejects.toThrow("token_crypto_ciphertext_invalid");
  });

  it("refuses missing or wrong-length keys", async () => {
    await expect(importTokenKey(undefined)).rejects.toThrow("token_crypto_key_missing");
    await expect(importTokenKey(btoa("short"))).rejects.toThrow("token_crypto_key_invalid");
  });
});

describe("OwnerState Tesla tokens", () => {
  it("seeds once, refreshes single-flight, and persists the rotated refresh token first", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const stub = ownerStub();
    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      const tokens = await Promise.all(Array.from({ length: 8 }, () => instance.getAccessToken()));
      expect(tesla.tokenRequests).toHaveLength(1);
      expect(new Set(tokens)).toEqual(new Set([tesla.issuedAccessTokens[0]]));

      // Same fields the Python plugin sends; no client_secret when unset.
      const form = tesla.tokenRequests[0] as URLSearchParams;
      expect([...form.keys()]).toEqual(["grant_type", "refresh_token", "client_id", "audience"]);
      expect(form.get("grant_type")).toBe("refresh_token");
      expect(form.get("refresh_token")).toBe(env.TESLA_BOOTSTRAP_REFRESH_TOKEN);
      expect(form.get("client_id")).toBe("test-client-id");

      const blob = storedBlob(state) as string;
      const stored = await decryptTokens(await importTokenKey(env.TOKEN_ENCRYPTION_KEY), blob);
      expect(stored.refreshToken).toBe(tesla.issuedRefreshTokens[0]);
      expect(blob).not.toContain(stored.refreshToken);

      // Still valid: no new refresh.
      await instance.getAccessToken();
      expect(tesla.tokenRequests).toHaveLength(1);

      // Expiring within five minutes: refresh with the rotated token, and never
      // re-seed from the bootstrap token.
      instance.clock = () => stored.expiresAt - 4 * 60_000;
      await Promise.all([instance.getAccessToken(), instance.getAccessToken()]);
      expect(tesla.tokenRequests).toHaveLength(2);
      expect(tesla.tokenRequests[1]?.get("refresh_token")).toBe(tesla.issuedRefreshTokens[0]);
    });
  });

  it("seeds exactly once when cold-start callers race, and never restores the bootstrap token", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const stub = ownerStub();
    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      const tokens = await Promise.all([
        instance.getAccessToken(),
        instance.getAccessToken(true),
        instance.getAccessToken(),
        instance.getAccessToken(true),
        instance.getAccessToken(),
      ]);
      expect(new Set(tokens)).toEqual(new Set([tesla.issuedAccessTokens[0]]));
      expect(tesla.tokenRequests).toHaveLength(1);
      // Let any stray continuation finish before inspecting storage.
      await new Promise((resolve) => setTimeout(resolve, 20));
      const seeded = state.storage.sql
        .exec<{ n: number }>("SELECT COUNT(*) AS n FROM audit WHERE action = 'tokens_seeded'")
        .one().n;
      expect(seeded).toBe(1);
      const stored = await decryptTokens(await importTokenKey(env.TOKEN_ENCRYPTION_KEY), storedBlob(state) as string);
      expect(stored.refreshToken).toBe(tesla.issuedRefreshTokens[0]);
      expect(stored.accessToken).toBe(tesla.issuedAccessTokens[0]);
      // A forced refresh after the fact still uses the rotated token.
      await instance.getAccessToken(true);
      expect(tesla.tokenRequests[1]?.get("refresh_token")).toBe(tesla.issuedRefreshTokens[0]);
    });
  });

  it("stops at reauth_required on invalid_grant without retrying", async () => {
    const tesla = new FakeTesla();
    tesla.tokenResponder = () =>
      Response.json({ error: "invalid_grant", error_description: "refresh token revoked" }, { status: 400 });
    tesla.install();
    const stub = ownerStub();
    await runInDurableObject(stub, async (instance: OwnerState) => {
      await expect(instance.getAccessToken()).rejects.toThrow(/sign-in has expired/);
      await expect(instance.getAccessToken()).rejects.toThrow(/sign-in has expired/);
      await expect(instance.getAccessToken(true)).rejects.toThrow(/sign-in has expired/);
    });
    expect(tesla.tokenRequests).toHaveLength(1);
    const status = await stub.authStatus();
    expect(status.authState).toBe("reauth_required");
    const audit = await stub.auditRecent(10);
    expect(audit.some((row) => row.action === "token_refresh" && row.detail.startsWith("reauth_required"))).toBe(true);
    // A tool call fails fast with no Tesla traffic at all.
    const listed = await stub.listVehicles();
    expect(listed).toMatchObject({ ok: false, error: { code: "reauth_required" } });
    expect(tesla.fleetRequests).toHaveLength(0);
    expect(tesla.tokenRequests).toHaveLength(1);
  });

  it("signs in again after reauth_required once a new bootstrap token is set", async () => {
    const tesla = new FakeTesla();
    tesla.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    tesla.install();
    const stub = ownerStub();
    expect(await stub.listVehicles()).toMatchObject({ ok: false, error: { code: "reauth_required" } });
    const failed = await stub.listVehicles();
    expect(failed.ok ? "" : failed.error.message).toMatch(/wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN/);

    // The owner sets a new value: the very next request uses it.
    const healthy = new FakeTesla();
    vi.restoreAllMocks();
    healthy.install();
    await runInDurableObject(stub, async (instance: OwnerState) => {
      Object.assign(instance, { env: { ...env, TESLA_BOOTSTRAP_REFRESH_TOKEN: "new-refresh-token-after-reauth" } });
      await instance.getAccessToken();
    });
    expect(healthy.tokenRequests[0]?.get("refresh_token")).toBe("new-refresh-token-after-reauth");
    expect((await stub.authStatus()).authState).toBe("ok");
    const audit = await stub.auditRecent(10);
    expect(audit.find((row) => row.action === "tokens_seeded")?.detail).toBe("replaced rejected refresh token");
  });

  it("reports the sign-in state from storage alone", async () => {
    const tesla = new FakeTesla();
    tesla.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    tesla.install();
    const stub = ownerStub();
    await runInDurableObject(stub, async (instance: OwnerState) => {
      Object.assign(instance, { env: { ...env, TESLA_BOOTSTRAP_REFRESH_TOKEN: "" } });
      expect(await instance.authStatus()).toMatchObject({ authState: "not_configured" });
      Object.assign(instance, { env });
      // A bootstrap token not yet tried counts as ok: the next request uses it.
      expect(await instance.authStatus()).toEqual({ authState: "ok", message: null });
      await expect(instance.getAccessToken()).rejects.toThrow(/sign-in has expired/);
      expect(await instance.authStatus()).toMatchObject({ authState: "reauth_required" });
      // Setting a new value is reported as ok before any request uses it.
      Object.assign(instance, { env: { ...env, TESLA_BOOTSTRAP_REFRESH_TOKEN: "another-refresh-token" } });
      expect((await instance.authStatus()).authState).toBe("ok");
    });
    expect(tesla.tokenRequests).toHaveLength(1);
  });

  it("replaces stored tokens with a new bootstrap token even without a recorded reauth", async () => {
    // A Fleet 401 that survives a forced refresh reports reauth_required
    // without Tesla's sign-in service ever rejecting the refresh token.
    const tesla = new FakeTesla();
    tesla.fleetOverrides = [
      { path: /^\/api\/1\/vehicles$/, status: 401 },
      { path: /^\/api\/1\/vehicles$/, status: 401 },
    ];
    tesla.install();
    const stub = ownerStub();
    expect(await stub.listVehicles()).toMatchObject({ ok: false, error: { code: "reauth_required" } });

    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      // The same value as before is never seeded again.
      await instance.getAccessToken(true);
      expect(tesla.tokenRequests.at(-1)?.get("refresh_token")).toBe(tesla.issuedRefreshTokens.at(-2));

      Object.assign(instance, { env: { ...env, TESLA_BOOTSTRAP_REFRESH_TOKEN: "replacement-refresh-token" } });
      await instance.getAccessToken();
      expect(tesla.tokenRequests.at(-1)?.get("refresh_token")).toBe("replacement-refresh-token");
      const stored = await decryptTokens(await importTokenKey(env.TOKEN_ENCRYPTION_KEY), storedBlob(state) as string);
      expect(stored.refreshToken).toBe(tesla.issuedRefreshTokens.at(-1));
    });
    expect(await stub.listVehicles()).toMatchObject({ ok: true });
    const seeded = (await stub.auditRecent(20)).filter((row) => row.action === "tokens_seeded");
    expect(seeded.map((row) => row.detail)).toEqual(["replaced stored tokens", "initial seed"]);
  });

  it("forces exactly one refresh and one retry on a Fleet 401", async () => {
    const tesla = new FakeTesla();
    tesla.fleetOverrides = [{ path: /^\/api\/1\/vehicles$/, status: 401 }];
    tesla.install();
    const stub = ownerStub();
    const listed = await stub.listVehicles();
    expect(listed.ok).toBe(true);
    expect(tesla.tokenRequests).toHaveLength(2);
    const vehicleCalls = tesla.fleetRequests.filter((request) => request.path === "/api/1/vehicles");
    expect(vehicleCalls.map((call) => call.authorization)).toEqual([
      `Bearer ${tesla.issuedAccessTokens[0]}`,
      `Bearer ${tesla.issuedAccessTokens[1]}`,
    ]);

    // A second 401 after the forced refresh is final, not a loop.
    const again = new FakeTesla();
    again.fleetOverrides = [
      { path: /^\/api\/1\/vehicles$/, status: 401 },
      { path: /^\/api\/1\/vehicles$/, status: 401 },
    ];
    vi.restoreAllMocks();
    again.install();
    const other = ownerStub();
    expect(await other.listVehicles()).toMatchObject({ ok: false, error: { code: "reauth_required" } });
    expect(again.fleetRequests).toHaveLength(2);
    expect(again.tokenRequests).toHaveLength(2);
  });
});
