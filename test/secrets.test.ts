import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OwnerState } from "../src/owner/state";
import { FakeTesla, uniqueName } from "./helpers/fake-tesla";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("secrets stay out of audit rows and errors", () => {
  it("never records tokens, keys, or raw responses", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("secrets")));
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.sleep = async () => {};
    });
    expect(await stub.lock({})).toMatchObject({ ok: true });
    await stub.recordAudit({
      source: "tool",
      action: "lock",
      vehicleId: null,
      outcome: "error",
      detail: `unexpected ${tesla.issuedAccessTokens[0]} eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc`,
    });
    const failing = new FakeTesla();
    failing.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 401 });
    vi.restoreAllMocks();
    failing.install();
    const other = env.OWNER.get(env.OWNER.idFromName(uniqueName("secrets")));
    const failure = await other.lock({});

    const secrets = [
      env.TESLA_BOOTSTRAP_REFRESH_TOKEN,
      env.MCP_BEARER_TOKEN,
      env.TOKEN_ENCRYPTION_KEY,
      env.TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64,
      ...tesla.issuedAccessTokens,
      ...tesla.issuedRefreshTokens,
    ].filter((value): value is string => Boolean(value));
    const exposed = JSON.stringify([
      await stub.auditRecent(100),
      await other.auditRecent(100),
      await stub.authStatus(),
      await other.authStatus(),
      failure,
    ]);
    expect(exposed).toContain("[redacted]");
    for (const secret of secrets) expect(exposed).not.toContain(secret);
    expect(exposed).not.toContain(tesla.vin);
  });
});
