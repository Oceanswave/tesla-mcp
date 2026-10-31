import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type NotifyEnv, type NotifyEvent, notifyAudit } from "../src/owner/notify";
import type { OwnerState } from "../src/owner/state";
import type { FetchFn } from "../src/tesla/http";
import { FakeTesla, uniqueName } from "./helpers/fake-tesla";
import { connect, type ToolResult } from "./helpers/mcp";

// An unroutable host: a missed mock can never reach a real webhook.
const NOTIFY_URL = "https://notify.example.test/hook/private-path";
const NOTIFY_AUTH = `Bearer ${crypto.randomUUID()}`;

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const event = (overrides: Partial<NotifyEvent> = {}): NotifyEvent => ({
  id: 42,
  ts: "2026-10-31T12:00:00.000Z",
  action: "wake",
  source: "tool",
  vehicleId: "1234567890123",
  outcome: "ok",
  detail: "state online",
  dangerous: false,
  ...overrides,
});

const configured = (overrides: Partial<NotifyEnv> = {}): NotifyEnv => ({
  NOTIFY_URL,
  NOTIFY_AUTH,
  NOTIFY_DRY_RUN: "false",
  ...overrides,
});

/** A webhook answering each POST in turn; the last answer repeats. */
function endpoint(...answers: (number | Error)[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchFn: FetchFn = async (input, init) => {
    calls.push({ url: String(input), init: init ?? {} });
    const answer = answers[Math.min(calls.length, answers.length) - 1] ?? 204;
    if (answer instanceof Error) throw answer;
    return new Response(answer === 204 ? null : "body", { status: answer });
  };
  const header = (index: number, name: string) => new Headers(calls[index]?.init.headers).get(name);
  return { calls, fetchFn, header };
}

describe("notifyAudit", () => {
  it("posts exactly the documented payload", async () => {
    const { calls, fetchFn } = endpoint(204);
    await notifyAudit(configured(), fetchFn, event());
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(NOTIFY_URL);
    expect(calls[0]?.init.method).toBe("POST");
    expect(JSON.parse(String(calls[0]?.init.body))).toStrictEqual({
      source: "tesla-mcp",
      event: "command",
      id: "42",
      ts: "2026-10-31T12:00:00.000Z",
      action: "wake",
      caller: "tool",
      outcome: "ok",
      detail: "state online",
      vehicle: "…0123",
      dangerous: false,
    });
  });

  it("sends the auth, content type, and idempotency headers", async () => {
    const { fetchFn, header } = endpoint(204);
    await notifyAudit(configured(), fetchFn, event());
    expect(header(0, "Authorization")).toBe(NOTIFY_AUTH);
    expect(header(0, "Content-Type")).toBe("application/json");
    expect(header(0, "Idempotency-Key")).toBe("tesla-42");
  });

  it("bounds each attempt with an abort signal and never follows a redirect", async () => {
    const { calls, fetchFn } = endpoint(204);
    await notifyAudit(configured(), fetchFn, event());
    expect(calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
    expect(calls[0]?.init.redirect).toBe("manual");
  });

  it("sends null for a row with no vehicle", async () => {
    const { calls, fetchFn } = endpoint(204);
    await notifyAudit(configured(), fetchFn, event({ vehicleId: null }));
    expect(JSON.parse(String(calls[0]?.init.body)).vehicle).toBeNull();
  });

  it("keeps full ids out of the detail", async () => {
    const { calls, fetchFn } = endpoint(204);
    const site = "1689874563214";
    const vin = "5YJ3E1EA7KF000316";
    await notifyAudit(configured(), fetchFn, event({ detail: `site ${site}` }));
    await notifyAudit(configured(), fetchFn, event({ detail: `rejected ${vin}` }));
    expect(JSON.parse(String(calls[0]?.init.body)).detail).toBe("site …3214");
    expect(JSON.parse(String(calls[1]?.init.body)).detail).toBe("rejected …0316");
  });

  it("leaves short status codes in the detail alone", async () => {
    const { calls, fetchFn } = endpoint(204);
    await notifyAudit(configured(), fetchFn, event({ detail: "reauth_required 401 attempts=4 http_503" }));
    expect(JSON.parse(String(calls[0]?.init.body)).detail).toBe("reauth_required 401 attempts=4 http_503");
  });

  describe("dry run", () => {
    it("logs the payload without posting, and without the URL or auth", async () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      const { calls, fetchFn } = endpoint(204);
      await notifyAudit(configured({ NOTIFY_DRY_RUN: "true" }), fetchFn, event());
      expect(calls).toHaveLength(0);
      const logged = JSON.stringify(log.mock.calls);
      expect(logged).toContain("tesla-mcp");
      expect(logged).toContain("…0123");
      expect(logged).not.toContain(NOTIFY_URL);
      expect(logged).not.toContain(NOTIFY_AUTH);
    });

    it("logs even with no URL set", async () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      const { calls, fetchFn } = endpoint(204);
      await notifyAudit({ NOTIFY_DRY_RUN: "true" }, fetchFn, event());
      expect(calls).toHaveLength(0);
      expect(log).toHaveBeenCalledOnce();
    });

    it("honors the filters", async () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      await notifyAudit(configured({ NOTIFY_DRY_RUN: "true", NOTIFY_ACTIONS: "lock" }), endpoint().fetchFn, event());
      expect(log).not.toHaveBeenCalled();
    });

    it('is off for anything but exactly "true"', async () => {
      const { calls, fetchFn } = endpoint(204);
      await notifyAudit(configured({ NOTIFY_DRY_RUN: "TRUE" }), fetchFn, event());
      expect(calls).toHaveLength(1);
    });
  });

  describe("configuration", () => {
    it("does nothing when the URL is unset or blank", async () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      const { calls, fetchFn } = endpoint(204);
      await notifyAudit({ NOTIFY_DRY_RUN: "false", NOTIFY_AUTH }, fetchFn, event());
      await notifyAudit(configured({ NOTIFY_URL: "" }), fetchFn, event());
      await notifyAudit(configured({ NOTIFY_URL: "  " }), fetchFn, event());
      expect(calls).toHaveLength(0);
      expect(log).not.toHaveBeenCalled();
    });

    it("fails closed when the auth value is missing", async () => {
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      const { calls, fetchFn } = endpoint(204);
      await notifyAudit(configured({ NOTIFY_AUTH: "" }), fetchFn, event());
      expect(calls).toHaveLength(0);
      expect(error).toHaveBeenCalledOnce();
    });
  });

  describe("filters", () => {
    const sent = async (overrides: Partial<NotifyEnv>, row: NotifyEvent) => {
      const { calls, fetchFn } = endpoint(204);
      await notifyAudit(configured(overrides), fetchFn, row);
      return calls.length;
    };

    it("sends every audited row by default", async () => {
      expect(await sent({}, event({ action: "tokens_seeded", source: "system" }))).toBe(1);
      expect(await sent({ NOTIFY_ACTIONS: "", NOTIFY_OUTCOMES: " , " }, event({ outcome: "error" }))).toBe(1);
    });

    it("limits by NOTIFY_ACTIONS, trimming each name", async () => {
      expect(await sent({ NOTIFY_ACTIONS: "lock, wake" }, event({ action: "wake" }))).toBe(1);
      expect(await sent({ NOTIFY_ACTIONS: "lock, wake" }, event({ action: "honk_horn" }))).toBe(0);
    });

    it("limits by NOTIFY_OUTCOMES, trimming each name", async () => {
      expect(await sent({ NOTIFY_OUTCOMES: "error, denied" }, event({ outcome: "error" }))).toBe(1);
      expect(await sent({ NOTIFY_OUTCOMES: "error, denied" }, event({ outcome: "ok" }))).toBe(0);
    });

    it("needs both filters to pass", async () => {
      const filters = { NOTIFY_ACTIONS: "lock", NOTIFY_OUTCOMES: "error" };
      expect(await sent(filters, event({ action: "lock", outcome: "ok" }))).toBe(0);
      expect(await sent(filters, event({ action: "wake", outcome: "error" }))).toBe(0);
      expect(await sent(filters, event({ action: "lock", outcome: "error" }))).toBe(1);
    });

    it("always sends a denied row, whatever the filters say", async () => {
      const filters = { NOTIFY_ACTIONS: "lock", NOTIFY_OUTCOMES: "ok" };
      expect(await sent(filters, event({ action: "door_unlock", outcome: "denied", dangerous: true }))).toBe(1);
    });
  });

  describe("delivery", () => {
    const attempts = async (...answers: (number | Error)[]) => {
      vi.spyOn(console, "error").mockImplementation(() => {});
      const { calls, fetchFn } = endpoint(...answers);
      await notifyAudit(configured(), fetchFn, event());
      return calls.length;
    };

    it("does not retry a success", async () => {
      expect(await attempts(200)).toBe(1);
    });

    it("retries a 503 once and stops when that succeeds", async () => {
      expect(await attempts(503, 200)).toBe(2);
    });

    it("retries a 5xx exactly once", async () => {
      expect(await attempts(503, 503, 503)).toBe(2);
    });

    it("never retries a 504", async () => {
      expect(await attempts(504)).toBe(1);
    });

    it("does not retry a 504 that follows a 503", async () => {
      expect(await attempts(503, 504, 200)).toBe(2);
    });

    it.each([400, 401, 403, 404, 429])("never retries a %i", async (status) => {
      expect(await attempts(status)).toBe(1);
    });

    it("never retries a redirect", async () => {
      expect(await attempts(302)).toBe(1);
    });

    it("retries a network error once", async () => {
      expect(await attempts(new TypeError("Network connection lost"), new TypeError("again"), 200)).toBe(2);
    });

    it("aborts a hung request at 5s and retries it exactly once", async () => {
      vi.useFakeTimers();
      // Fake timers do not reach the runtime's AbortSignal.timeout, so rebuild it on setTimeout.
      const timeouts = vi.spyOn(AbortSignal, "timeout").mockImplementation((ms) => {
        const controller = new AbortController();
        setTimeout(() => controller.abort(new DOMException("timed out", "TimeoutError")), ms);
        return controller.signal;
      });
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      let started = 0;
      const stalled: FetchFn = (_input, init) => {
        started++;
        return new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
        });
      };

      const finished = notifyAudit(configured(), stalled, event());
      await vi.advanceTimersByTimeAsync(4_999);
      expect(started).toBe(1);
      expect(error).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1);
      expect(started).toBe(2);
      expect(error).toHaveBeenCalledOnce();

      await vi.advanceTimersByTimeAsync(4_999);
      expect(error).toHaveBeenCalledOnce();

      await vi.advanceTimersByTimeAsync(1);
      await finished;
      expect(started).toBe(2);
      expect(timeouts.mock.calls).toEqual([[5_000], [5_000]]);
      expect(error.mock.calls).toEqual([
        ["[tesla-mcp] notify attempt 1 failed for audit 42: TimeoutError"],
        ["[tesla-mcp] notify attempt 2 failed for audit 42: TimeoutError"],
      ]);
    });

    it("repeats the same idempotency key on the retry", async () => {
      const { fetchFn, header } = endpoint(503, 200);
      await notifyAudit(configured(), fetchFn, event());
      expect(header(0, "Idempotency-Key")).toBe("tesla-42");
      expect(header(1, "Idempotency-Key")).toBe("tesla-42");
    });

    it("never logs the URL or auth value, even when the error names them", async () => {
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      const { fetchFn } = endpoint(new TypeError(`failed ${NOTIFY_URL} with ${NOTIFY_AUTH}`));
      await expect(notifyAudit(configured(), fetchFn, event())).resolves.toBeUndefined();
      expect(error).toHaveBeenCalled();
      const logged = JSON.stringify(error.mock.calls);
      expect(logged).not.toContain("notify.example.test");
      expect(logged).not.toContain(NOTIFY_AUTH);
    });
  });
});

type Post = { payload: Record<string, unknown>; raw: string; idempotencyKey: string | null };

/** The fake Tesla behind every URL but the webhook, which `answer` handles. */
function installWebhook(tesla: FakeTesla, answer: () => Promise<Response> | Response = () => new Response(null)) {
  const posts: Post[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const request = new Request(input as RequestInfo, init as RequestInit);
    if (request.url !== NOTIFY_URL) return tesla.handle(request);
    const raw = await request.text();
    posts.push({ payload: JSON.parse(raw), raw, idempotencyKey: request.headers.get("Idempotency-Key") });
    return answer();
  });
  return posts;
}

const notifyVars = (overrides: Partial<typeof env> = {}) => ({
  ...env,
  NOTIFY_URL,
  NOTIFY_AUTH,
  ...overrides,
});

async function ownerWith(vars: Partial<NotifyEnv> = {}) {
  const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("notify")));
  await runInDurableObject(stub, (instance: OwnerState) => {
    instance.sleep = async () => {};
    Object.assign(instance, { env: notifyVars(vars) });
  });
  return stub;
}

/** A background send lands after the command returns. */
const delivered = (posts: Post[], count: number) =>
  vi.waitFor(() => {
    if (posts.length < count) throw new Error(`waiting for ${count} posts, have ${posts.length}`);
  });

describe("OwnerState notifications", () => {
  it("notifies once for a command, with the audit row's id", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith({ NOTIFY_ACTIONS: "wake" });
    expect(await owner.wake({})).toMatchObject({ ok: true });
    await delivered(posts, 1);
    expect(posts).toHaveLength(1);
    const [row] = await owner.auditRecent(1);
    expect(posts[0]?.payload).toMatchObject({
      event: "command",
      action: "wake",
      caller: "tool",
      outcome: "ok",
      ts: row?.ts,
      detail: row?.detail,
      vehicle: `…${tesla.vehicleId.slice(-4)}`,
      dangerous: false,
    });
    const id = String(posts[0]?.payload.id);
    expect(id).toMatch(/^\d+$/);
    expect(posts[0]?.idempotencyKey).toBe(`tesla-${id}`);
  });

  it("gives each audit row its own id", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith({ NOTIFY_ACTIONS: "wake" });
    await owner.wake({});
    await owner.wake({});
    await delivered(posts, 2);
    expect(new Set(posts.map((post) => post.payload.id)).size).toBe(2);
  });

  it("reports system rows with their source as the caller", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith({ NOTIFY_ACTIONS: "tokens_seeded" });
    await owner.listVehicles();
    await delivered(posts, 1);
    expect(posts[0]?.payload).toMatchObject({ action: "tokens_seeded", caller: "system", vehicle: null });
  });

  it("stays silent on reads", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith();
    // The first call seeds the tokens, a system event of its own.
    await owner.listVehicles();
    await delivered(posts, 1);
    posts.length = 0;

    await owner.listVehicles();
    await owner.vehicleStatus();
    await owner.auditRecent();
    await owner.authStatus();
    await owner.fleetEndpoint("vehicle_data");
    await owner.fleetEndpoint("products");
    // A command after the reads: had any read sent one, it would come first.
    await owner.wake({});
    await delivered(posts, 1);
    expect(posts.map((post) => post.payload.action)).toEqual(["wake"]);
  });

  it("sends nothing secret and no full id", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith();
    await owner.lock({});
    await owner.recordAudit({
      source: "tool",
      action: "lock",
      vehicleId: tesla.vehicleId,
      outcome: "error",
      detail: `unexpected ${tesla.issuedAccessTokens[0]}`,
    });
    await delivered(posts, 3);
    const sent = posts.map((post) => post.raw).join("\n");
    expect(sent).toContain("[redacted]");
    const secrets = [
      env.TESLA_BOOTSTRAP_REFRESH_TOKEN,
      env.MCP_BEARER_TOKEN,
      env.TOKEN_ENCRYPTION_KEY,
      env.TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64,
      NOTIFY_URL,
      NOTIFY_AUTH,
      tesla.vin,
      tesla.vehicleId,
      ...tesla.issuedAccessTokens,
      ...tesla.issuedRefreshTokens,
    ].filter((value): value is string => Boolean(value));
    for (const secret of secrets) expect(sent).not.toContain(secret);
  });

  it("does not fail a command when the send fails", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla, () => {
      throw new TypeError("connection refused");
    });
    const owner = await ownerWith({ NOTIFY_ACTIONS: "wake" });
    expect(await owner.wake({})).toMatchObject({ ok: true });
    await delivered(posts, 2);
    expect((await owner.auditRecent(1))[0]).toMatchObject({ action: "wake", outcome: "ok" });
  });

  it("does not hold up a command while the send is slow", async () => {
    const tesla = new FakeTesla();
    let answered = false;
    const posts = installWebhook(tesla, async () => {
      await new Promise((resolve) => setTimeout(resolve, 250));
      answered = true;
      return new Response(null);
    });
    const owner = await ownerWith({ NOTIFY_ACTIONS: "wake" });
    expect(await owner.wake({})).toMatchObject({ ok: true });
    expect(answered).toBe(false);
    await delivered(posts, 1);
  });

  it("always notifies of a refused dangerous command", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith({ NOTIFY_ACTIONS: "lock", NOTIFY_OUTCOMES: "ok" });
    await owner.signedVehicleCommand({ command: "door_unlock" });
    await owner.signedVehicleCommand({ command: "set_sentry_mode", params: { on: false } });
    await owner.fleetEndpoint("share_invite_create");
    await delivered(posts, 3);
    expect(posts.map((post) => post.payload)).toMatchObject([
      { action: "door_unlock", outcome: "denied", dangerous: true, detail: "dangerous_disabled" },
      { action: "set_sentry_mode", outcome: "denied", dangerous: true, detail: "dangerous_disabled" },
      { action: "share_invite_create", outcome: "denied", dangerous: true, detail: "dangerous_disabled" },
    ]);
  });

  it("tells Sentry Mode on from off by its parameters", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const owner = await ownerWith({ NOTIFY_ACTIONS: "set_sentry_mode" });
    await owner.signedVehicleCommand({ command: "set_sentry_mode", params: { on: true } });
    await delivered(posts, 1);
    expect(posts[0]?.payload).toMatchObject({ outcome: "ok", dangerous: false });
  });

  it("flags a dangerous command the car ran", async () => {
    const tesla = new FakeTesla();
    tesla.car.locked = true;
    const posts = installWebhook(tesla);
    const owner = await ownerWith({ NOTIFY_ACTIONS: "door_unlock" });
    await runInDurableObject(owner, (instance: OwnerState) => {
      Object.assign(instance, {
        env: notifyVars({ NOTIFY_ACTIONS: "door_unlock", DANGEROUS_COMMANDS_ENABLED: "true" }),
      });
    });
    expect(await owner.signedVehicleCommand({ command: "door_unlock" })).toMatchObject({ ok: true });
    await delivered(posts, 1);
    expect(posts[0]?.payload).toMatchObject({ action: "door_unlock", outcome: "ok", dangerous: true });
  });

  it("flags a dangerous tool called without confirmation, past the filters", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const { client, owner } = await connect({ DANGEROUS_COMMANDS_ENABLED: "true" });
    await runInDurableObject(owner, (instance: OwnerState) => {
      Object.assign(instance, { env: notifyVars({ NOTIFY_ACTIONS: "lock", NOTIFY_OUTCOMES: "ok" }) });
    });
    const refused = (await client.callTool({ name: "tesla_unlock", arguments: {} })) as ToolResult;
    expect(refused.structuredContent).toMatchObject({ error: "confirmation_required" });
    await client.callTool({ name: "tesla_honk_horn", arguments: {} });
    await delivered(posts, 2);
    expect(posts.map((post) => post.payload)).toMatchObject([
      { action: "door_unlock", outcome: "denied", dangerous: true, detail: "confirm_required" },
      { action: "honk_horn", outcome: "denied", dangerous: false, detail: "confirm_required" },
    ]);
    await client.close();
  });

  it("flags a dangerous tool's dry run", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const { client, owner } = await connect({ DANGEROUS_COMMANDS_ENABLED: "true" });
    await runInDurableObject(owner, (instance: OwnerState) => {
      Object.assign(instance, { env: notifyVars() });
    });
    await client.callTool({ name: "tesla_unlock", arguments: { confirm: true, dryRun: true } });
    await delivered(posts, 1);
    expect(posts[0]?.payload).toMatchObject({ action: "door_unlock", detail: "dry_run", dangerous: true });
    await client.close();
  });

  it("does not post with no URL configured", async () => {
    const tesla = new FakeTesla();
    const posts = installWebhook(tesla);
    const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("notify")));
    expect(await stub.wake({})).toMatchObject({ ok: true });
    expect(posts).toHaveLength(0);
  });
});
