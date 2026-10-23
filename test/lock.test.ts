import { describe, expect, it } from "vitest";
import { type LockDeps, lockWithRetry, NIGHTLY_LOCK_POLICY } from "../src/owner/lock";
import type { SignedCommandResult, VcpErrorCode } from "../src/tesla/vcp/session";

const ok: SignedCommandResult = { ok: true };
// Mirrors the session: only vehicle_unavailable (408, exhausted transient
// faults) is reported as retryable.
const fail = (code: VcpErrorCode, retryable = code === "vehicle_unavailable"): SignedCommandResult => ({
  ok: false,
  error: { code, retryable, stage: `test_${code}` },
});

function deps(options: {
  states: (string | null)[];
  locks: SignedCommandResult[];
  locked?: boolean | null | (boolean | null)[];
}) {
  const calls = { wake: 0, lock: 0, state: 0, isLocked: 0, slept: 0 };
  const d: LockDeps = {
    getState: async () => {
      calls.state++;
      return options.states.length > 1 ? (options.states.shift() ?? null) : (options.states[0] ?? null);
    },
    wake: async () => {
      calls.wake++;
    },
    sendLock: async () => {
      calls.lock++;
      return options.locks.shift() ?? fail("vehicle_unavailable");
    },
    isLocked: async () => {
      calls.isLocked++;
      if (Array.isArray(options.locked)) return options.locked.shift() ?? null;
      return options.locked ?? null;
    },
    sleep: async (milliseconds) => {
      calls.slept += milliseconds;
    },
  };
  return { d, calls };
}

describe("lockWithRetry", () => {
  it("locks an online car with one command", async () => {
    const { d, calls } = deps({ states: ["online"], locks: [ok] });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toEqual({
      ok: true,
      detail: "locked",
      attempts: 1,
      woke: false,
    });
    expect(calls.wake).toBe(0);
  });

  it("wakes an asleep car, waits for online, then locks", async () => {
    const { d, calls } = deps({ states: ["asleep", "asleep", "online"], locks: [ok] });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toEqual({
      ok: true,
      detail: "locked_after_wake",
      attempts: 1,
      woke: true,
    });
    expect(calls.wake).toBe(1);
  });

  it("wakes and retries when the lock reports the car unavailable", async () => {
    const { d, calls } = deps({ states: ["online"], locks: [fail("vehicle_unavailable"), ok] });
    const outcome = await lockWithRetry(d, NIGHTLY_LOCK_POLICY);
    expect(outcome).toMatchObject({ ok: true, detail: "locked_after_wake", attempts: 2 });
    expect(calls.wake).toBe(1);
  });

  it("treats an already locked car as success", async () => {
    const { d } = deps({ states: ["online"], locks: [fail("command_rejected")], locked: true });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({ ok: true, detail: "already_locked" });
  });

  it("stops after four attempts and bounds each wake wait", async () => {
    const { d, calls } = deps({ states: ["asleep"], locks: [] });
    const outcome = await lockWithRetry(d, NIGHTLY_LOCK_POLICY);
    expect(outcome).toMatchObject({ ok: false, attempts: 4, woke: true });
    expect(calls.lock).toBe(4);
    // One wake before the first attempt and one between each attempt.
    expect(calls.wake).toBe(4);
    expect(calls.slept).toBe(4 * NIGHTLY_LOCK_POLICY.wakeTimeoutMs);
  });

  it("stops when the session reports a failure as not retryable", async () => {
    for (const code of ["session_unavailable", "service_unavailable", "command_rejected"] as const) {
      const { d, calls } = deps({ states: ["online"], locks: [fail(code, false), ok], locked: false });
      expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({ ok: false, code, attempts: 1 });
      expect(calls.lock).toBe(1);
    }
  });

  it("retries a retryable failure that is not vehicle_unavailable", async () => {
    const { d, calls } = deps({ states: ["online"], locks: [fail("session_unavailable", true), ok] });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({ ok: true, detail: "locked", attempts: 2 });
    expect(calls.lock).toBe(2);
    expect(calls.wake).toBe(0);
  });

  it("never resends after an unknown outcome while the lock state stays unknown", async () => {
    const { d, calls } = deps({ states: ["online"], locks: [fail("status_unknown"), ok], locked: null });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({
      ok: false,
      code: "status_unknown",
      attempts: 1,
    });
    expect(calls.lock).toBe(1);
    // The first check plus three bounded re-polls.
    expect(calls.isLocked).toBe(4);
    expect(calls.slept).toBe(2_000 + 4_000 + 8_000);
  });

  it("counts an unknown outcome as success once a later poll shows the car locked", async () => {
    const { d, calls } = deps({ states: ["online"], locks: [fail("status_unknown")], locked: [null, null, true] });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({ ok: true, detail: "locked", attempts: 1 });
    expect(calls.lock).toBe(1);
    expect(calls.isLocked).toBe(3);
  });

  it("resends after an unknown outcome only when the car reports itself unlocked", async () => {
    const { d, calls } = deps({ states: ["online"], locks: [fail("status_unknown"), ok], locked: [false] });
    expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({ ok: true, detail: "locked", attempts: 2 });
    expect(calls.lock).toBe(2);
  });

  it("does not retry faults a retry cannot fix", async () => {
    for (const code of ["pairing_required", "unauthorized", "remote_access_required", "rate_limited"] as const) {
      const { d, calls } = deps({ states: ["online"], locks: [fail(code)] });
      expect(await lockWithRetry(d, NIGHTLY_LOCK_POLICY)).toMatchObject({ ok: false, code, attempts: 1 });
      expect(calls.lock).toBe(1);
    }
  });
});
