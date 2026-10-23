// Lock with wake-and-retry. Pure orchestration over injected Tesla calls so the
// retry policy is testable without a network or real time.

import type { SignedCommandResult, VcpErrorCode } from "../tesla/vcp/session";

export type LockDeps = {
  /** Fleet vehicle state: "online", "asleep", "offline", or null if unknown. */
  getState(): Promise<string | null>;
  wake(): Promise<void>;
  sendLock(): Promise<SignedCommandResult>;
  /** vehicle_state.locked when the car is online; null when unavailable. */
  isLocked(): Promise<boolean | null>;
  sleep(milliseconds: number): Promise<void>;
};

export type LockPolicy = {
  /** Total signed lock attempts, including the first. */
  maxAttempts: number;
  /** How long to poll for "online" after each wake_up. */
  wakeTimeoutMs: number;
};

export const NIGHTLY_LOCK_POLICY: LockPolicy = { maxAttempts: 4, wakeTimeoutMs: 90_000 };
// MCP clients time out long tool calls; keep an interactive lock shorter.
export const INTERACTIVE_LOCK_POLICY: LockPolicy = { maxAttempts: 2, wakeTimeoutMs: 45_000 };

export type LockOutcome =
  | {
      ok: true;
      detail: "locked" | "locked_after_wake" | "already_locked";
      attempts: number;
      woke: boolean;
    }
  | { ok: false; code: VcpErrorCode | "wake_timeout"; detail: string; attempts: number; woke: boolean };

/** Faults a retry cannot fix; stop immediately instead of hammering Tesla. */
const FATAL = new Set<VcpErrorCode>([
  "unconfigured",
  "invalid_request",
  "pairing_required",
  "unauthorized",
  "forbidden",
  "remote_access_required",
  "rate_limited",
]);

// Poll backoff after wake_up, in milliseconds (repeats the last value).
const WAKE_POLL_DELAYS = [2_000, 3_000, 5_000, 8_000, 10_000];
const RETRY_DELAY_MS = 3_000;
// Extra lock-state polls after an unknown outcome, before giving up without
// resending (bounded: about 14 seconds in total).
const STATUS_POLL_DELAYS = [2_000, 4_000, 8_000];

async function wakeAndWait(deps: LockDeps, timeoutMs: number): Promise<boolean> {
  await deps.wake();
  let waited = 0;
  for (let poll = 0; waited < timeoutMs; poll++) {
    const delay = Math.min(WAKE_POLL_DELAYS[Math.min(poll, WAKE_POLL_DELAYS.length - 1)] as number, timeoutMs - waited);
    await deps.sleep(delay);
    waited += delay;
    if ((await deps.getState()) === "online") return true;
  }
  return false;
}

/** Ask the car whether it is locked, polling again while the answer is unknown. */
async function pollLocked(deps: LockDeps): Promise<boolean | null> {
  let locked = await deps.isLocked();
  for (const delay of STATUS_POLL_DELAYS) {
    if (locked !== null) break;
    await deps.sleep(delay);
    locked = await deps.isLocked();
  }
  return locked;
}

export async function lockWithRetry(deps: LockDeps, policy: LockPolicy): Promise<LockOutcome> {
  let woke = false;
  let lastCode: VcpErrorCode | "wake_timeout" = "vehicle_unavailable";
  let lastDetail = "not_attempted";

  if ((await deps.getState()) !== "online") {
    woke = true;
    if (!(await wakeAndWait(deps, policy.wakeTimeoutMs))) {
      lastCode = "wake_timeout";
      lastDetail = "vehicle did not come online after wake";
    }
  }

  for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
    const result = await deps.sendLock();
    if (result.ok) {
      return { ok: true, detail: woke ? "locked_after_wake" : "locked", attempts: attempt, woke };
    }
    const { code, stage } = result.error;
    lastCode = code;
    lastDetail = stage;
    if (FATAL.has(code)) return { ok: false, code, detail: stage, attempts: attempt, woke };

    if (code === "status_unknown") {
      // The response was lost, so the lock may have run. Never resend while
      // the outcome is still unknown; only a car that reports itself unlocked
      // gets another attempt.
      const locked = await pollLocked(deps);
      if (locked === true) {
        return { ok: true, detail: woke ? "locked_after_wake" : "locked", attempts: attempt, woke };
      }
      if (locked === null) return { ok: false, code, detail: stage, attempts: attempt, woke };
    } else {
      if (code === "command_rejected" && (await deps.isLocked()) === true) {
        // The car refuses to lock because it already is.
        return { ok: true, detail: "already_locked", attempts: attempt, woke };
      }
      if (!result.error.retryable) return { ok: false, code, detail: stage, attempts: attempt, woke };
    }
    if (attempt === policy.maxAttempts) break;

    if (code === "vehicle_unavailable") {
      woke = true;
      if (!(await wakeAndWait(deps, policy.wakeTimeoutMs))) {
        lastCode = "wake_timeout";
        lastDetail = "vehicle did not come online after wake";
      }
    } else {
      await deps.sleep(RETRY_DELAY_MS);
    }
  }
  return { ok: false, code: lastCode, detail: lastDetail, attempts: policy.maxAttempts, woke };
}
