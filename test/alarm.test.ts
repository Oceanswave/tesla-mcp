import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OwnerState } from "../src/owner/state";
import { FakeTesla, uniqueName } from "./helpers/fake-tesla";

afterEach(() => {
  vi.restoreAllMocks();
});

// Fake clock in the future so a real alarm never fires on its own mid-test.
// 2030-06-15 22:00 EDT = 2030-06-16T02:00Z.
const BEFORE = Date.parse("2030-06-16T01:00:00Z");
const RUN_AT = Date.parse("2030-06-16T02:00:00Z");
const NEXT_DAY = Date.parse("2030-06-17T02:00:00Z");

async function setup(tesla: FakeTesla) {
  tesla.install();
  const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("alarm")));
  await runInDurableObject(stub, (instance: OwnerState) => {
    instance.clock = () => BEFORE;
    instance.sleep = async () => {};
  });
  await runInDurableObject(env.TESLA_VCP.get(env.TESLA_VCP.idFromName(tesla.vin)), (instance) => {
    instance.sleep = async () => {};
  });
  expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
  // Idempotent: a second call (the next cron tick) changes nothing.
  expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
  await runInDurableObject(stub, async (instance: OwnerState, state) => {
    expect(await state.storage.getAlarm()).toBe(RUN_AT);
    instance.clock = () => RUN_AT + 5_000;
  });
  return stub;
}

async function alarmAt(stub: DurableObjectStub<OwnerState>): Promise<number | null> {
  return runInDurableObject(stub, (_instance: OwnerState, state) => state.storage.getAlarm());
}

describe("nightly lock alarm", () => {
  it("wakes an offline car, waits for online, locks, and schedules tomorrow", async () => {
    const tesla = new FakeTesla();
    tesla.state = "offline";
    tesla.pollsUntilOnline = 2;
    const stub = await setup(tesla);
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    expect(tesla.car.locked).toBe(true);
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/wake_up"))).toHaveLength(1);
    const [row] = await stub.auditRecent(1);
    expect(row).toMatchObject({ source: "alarm", action: "lock", outcome: "ok", vehicleId: tesla.vehicleId });
    expect(row?.detail).toMatch(/^locked_after_wake attempts=1 woke$/);
    const status = await stub.nightlyLockStatus();
    expect(status.lastRun).toMatchObject({
      localDate: "2030-06-15",
      outcome: "ok",
      detail: "lock command succeeded after waking",
    });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("treats an already locked car as success", async () => {
    const tesla = new FakeTesla();
    tesla.car.locked = true;
    tesla.car.behaviors = [{ kind: "vcsec_error", information: 1 }];
    const stub = await setup(tesla);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ outcome: "ok", detail: "already_locked" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("gives up after four attempts, audits the error, and still schedules tomorrow", async () => {
    const tesla = new FakeTesla();
    tesla.state = "asleep";
    tesla.pollsUntilOnline = Number.POSITIVE_INFINITY;
    const stub = await setup(tesla);
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    expect(tesla.car.locked).toBe(false);
    // Four lock attempts; each handshake retries a 408 three times, as the
    // Python plugin does for a VCSEC that is still booting.
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/signed_command"))).toHaveLength(12);
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/wake_up"))).toHaveLength(4);
    const [row] = await stub.auditRecent(1);
    expect(row).toMatchObject({ source: "alarm", action: "lock", outcome: "error" });
    expect(row?.detail).toMatch(/attempts=4 woke$/);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ outcome: "error", detail: "command_failed" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("never runs twice for the same local date", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.commands).toBe(1);
    // A duplicate delivery for the same night (re-armed for tonight) is a no-op.
    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      state.storage.sql.exec("UPDATE kv SET value = ? WHERE key = 'scheduled_for'", String(RUN_AT));
      await instance.alarm();
    });
    expect(tesla.car.commands).toBe(1);
    expect((await stub.auditRecent(10)).filter((row) => row.action === "lock")).toHaveLength(1);
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("keeps tonight's run when the cron fires at 22:00:30 before the alarm", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => RUN_AT + 30_000;
    });
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
    expect(await alarmAt(stub)).toBe(RUN_AT);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.locked).toBe(true);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-15", outcome: "ok" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
    // Once handled, the next cron tick moves on to tomorrow.
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(NEXT_DAY).toISOString() });
  });

  it("runs a late alarm within three hours, even after a cron tick", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => RUN_AT + 2 * 60 * 60_000;
    });
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.locked).toBe(true);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-15", outcome: "ok" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("audits a run more than three hours late as missed and schedules tomorrow", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => RUN_AT + 3 * 60 * 60_000 + 60_000;
    });
    // The cron keeps the overdue run so the alarm can record it as missed.
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.commands).toBe(0);
    expect(tesla.fleetRequests).toHaveLength(0);
    const [row] = await stub.auditRecent(1);
    expect(row).toMatchObject({ source: "alarm", action: "nightly_lock", outcome: "error", detail: "missed" });
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-15", outcome: "error" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("resumes a run interrupted during wake polling and locks tonight exactly once", async () => {
    const tesla = new FakeTesla();
    tesla.state = "offline";
    tesla.pollsUntilOnline = 2;
    const stub = await setup(tesla);
    // Simulate an eviction mid-run: the alarm fails while polling for online.
    await runInDurableObject(stub, async (instance: OwnerState) => {
      instance.sleep = async () => {
        throw new Error("simulated eviction");
      };
      await expect(instance.alarm()).rejects.toThrow("simulated eviction");
    });
    expect(tesla.car.commands).toBe(0);
    // A cron tick while the run is pending keeps tonight's alarm armed.
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => RUN_AT + 15 * 60_000;
      instance.sleep = async () => {};
    });
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
    expect(await alarmAt(stub)).toBe(RUN_AT);

    // The retried alarm resumes the pending run.
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.locked).toBe(true);
    expect(tesla.car.commands).toBe(1);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-15", outcome: "ok" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
    const rows = await stub.auditRecent(10);
    expect(rows.some((row) => row.action === "nightly_lock" && row.detail === "resumed run=2")).toBe(true);

    // The finished night never runs again.
    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      state.storage.sql.exec("UPDATE kv SET value = ? WHERE key = 'scheduled_for'", String(RUN_AT));
      await instance.alarm();
    });
    expect(tesla.car.commands).toBe(1);
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("ignores a second delivery while the run is still in flight", async () => {
    const tesla = new FakeTesla();
    tesla.state = "offline";
    tesla.pollsUntilOnline = 1;
    const stub = await setup(tesla);
    await runInDurableObject(stub, async (instance: OwnerState) => {
      let entered!: () => void;
      const polling = new Promise<void>((resolve) => {
        entered = resolve;
      });
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let first = true;
      instance.sleep = async () => {
        if (!first) return;
        first = false;
        entered();
        await gate;
      };
      const running = instance.alarm();
      await polling;
      // The cron tick and a duplicate delivery during the run change nothing.
      expect(await instance.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
      await instance.alarm();
      release();
      await running;
    });
    expect(tesla.car.commands).toBe(1);
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/wake_up"))).toHaveLength(1);
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("caps resumes at three per night and then schedules tomorrow", async () => {
    const tesla = new FakeTesla();
    tesla.state = "offline";
    tesla.pollsUntilOnline = Number.POSITIVE_INFINITY;
    const stub = await setup(tesla);
    await runInDurableObject(stub, async (instance: OwnerState) => {
      instance.sleep = async () => {
        throw new Error("simulated eviction");
      };
      for (let run = 0; run < 4; run++) {
        await expect(instance.alarm()).rejects.toThrow("simulated eviction");
      }
      // The fifth delivery gives up without calling Tesla.
      await instance.alarm();
    });
    expect(tesla.car.commands).toBe(0);
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/wake_up"))).toHaveLength(4);
    const [row] = await stub.auditRecent(1);
    expect(row).toMatchObject({ action: "nightly_lock", outcome: "error", detail: "abandoned runs=4" });
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-15", outcome: "error" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      state.storage.sql.exec("UPDATE kv SET value = ? WHERE key = 'scheduled_for'", String(RUN_AT));
      await instance.alarm();
    });
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/wake_up"))).toHaveLength(4);
  });

  it("audits an interrupted run as missed once it is more than three hours late", async () => {
    const tesla = new FakeTesla();
    tesla.state = "offline";
    const stub = await setup(tesla);
    await runInDurableObject(stub, async (instance: OwnerState) => {
      instance.sleep = async () => {
        throw new Error("simulated eviction");
      };
      await expect(instance.alarm()).rejects.toThrow("simulated eviction");
      instance.clock = () => RUN_AT + 3 * 60 * 60_000 + 60_000;
    });
    const before = tesla.fleetRequests.length;
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(RUN_AT).toISOString() });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.fleetRequests).toHaveLength(before);
    const [row] = await stub.auditRecent(1);
    expect(row).toMatchObject({ action: "nightly_lock", outcome: "error", detail: "missed after interruption" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("confirms an acknowledged-only reply from the car's lock state before calling it done", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "ack" }];
    const stub = await setup(tesla);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.commands).toBe(1);
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/vehicle_data"))).toBe(true);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-15", outcome: "ok" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("checks the lock state before resending when it resumes an interrupted run", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    // The interrupted run locked the car but never recorded the outcome.
    tesla.car.locked = true;
    await runInDurableObject(stub, (_instance: OwnerState, state) => {
      state.storage.sql.exec(
        "INSERT INTO kv (key, value) VALUES ('nightly_run', ?)",
        JSON.stringify({
          localDate: "2030-06-15",
          status: "pending",
          attempts: 1,
          startedAt: new Date(RUN_AT).toISOString(),
        }),
      );
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.commands).toBe(0);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ outcome: "ok", detail: "already_locked" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
  });

  it("after an outage, runs tonight's lock instead of skipping to tomorrow", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    // Yesterday's alarm is only delivered tonight at 22:30.
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => NEXT_DAY + 30 * 60_000;
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.commands).toBe(0);
    expect((await stub.auditRecent(1))[0]).toMatchObject({ action: "nightly_lock", detail: "missed" });
    // Tonight's run is armed (already due) rather than tomorrow's.
    expect(await alarmAt(stub)).toBe(NEXT_DAY);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(tesla.car.locked).toBe(true);
    expect((await stub.nightlyLockStatus()).lastRun).toMatchObject({ localDate: "2030-06-16", outcome: "ok" });
    expect(await alarmAt(stub)).toBe(NEXT_DAY + 86_400_000);
  });

  it("does not lock right away when first deployed after tonight's lock time", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("late-deploy")));
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => RUN_AT + 30 * 60_000;
    });
    expect(await stub.ensureAlarm()).toEqual({ nextRun: new Date(NEXT_DAY).toISOString() });
    expect(tesla.requests).toHaveLength(0);
  });

  it("reports the armed alarm, not a computed time, in the status", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("status")));
    await runInDurableObject(stub, (instance: OwnerState) => {
      instance.clock = () => BEFORE;
    });
    // Freshly deployed: nothing is armed until the cron calls ensureAlarm.
    expect((await stub.nightlyLockStatus()).nextRun).toBeNull();
    await stub.ensureAlarm();
    expect((await stub.nightlyLockStatus()).nextRun).toEqual({
      at: new Date(RUN_AT).toISOString(),
      local: "2030-06-15 22:00 America/New_York",
    });
  });

  it("respects NIGHTLY_LOCK_ENABLED", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const stub = env.OWNER.get(env.OWNER.idFromName(uniqueName("disabled")));
    await runInDurableObject(stub, async (instance: OwnerState, state) => {
      instance.clock = () => BEFORE;
      Object.assign(instance, { env: { ...env, NIGHTLY_LOCK_ENABLED: "false" } });
      await state.storage.setAlarm(RUN_AT);
      expect(await instance.ensureAlarm()).toEqual({ nextRun: null });
      expect(await state.storage.getAlarm()).toBeNull();
      await instance.alarm();
      expect((await instance.nightlyLockStatus()).enabled).toBe(false);
    });
    expect(tesla.requests).toHaveLength(0);
  });
});

describe("secrets stay out of audit rows and errors", () => {
  it("never records tokens, keys, or raw responses", async () => {
    const tesla = new FakeTesla();
    const stub = await setup(tesla);
    await runDurableObjectAlarm(stub);
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
      await stub.nightlyLockStatus(),
      failure,
    ]);
    expect(exposed).toContain("[redacted]");
    for (const secret of secrets) expect(exposed).not.toContain(secret);
    expect(exposed).not.toContain(tesla.vin);
  });
});
