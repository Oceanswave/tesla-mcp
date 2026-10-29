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
  /** Wall clock in milliseconds; bounds the whole flow, including the time
   * Tesla takes to answer, not just the sleeps between calls. */
  now(): number;
};

export type LockPolicy = {
  /** Total signed lock attempts, including the first. */
  maxAttempts: number;
  /** How long to poll for "online" after each wake_up. */
  wakeTimeoutMs: number;
  /** No new wake, poll, or lock attempt starts after this much wall-clock
   * time. A call already in flight can still finish after it. */
  budgetMs: number;
};

// One policy for every lock, whoever calls it. Seven minutes bounds a single
// tool call: a caller that waits on tesla_lock (a person, an assistant, or a
// scheduled routine) gets an answer, and one more signed command already in
// flight (handshake and command retries can take about five minutes when every
// Tesla call times out) plus the lock-state check after it can still finish.
export const LOCK_POLICY: LockPolicy = { maxAttempts: 4, wakeTimeoutMs: 90_000, budgetMs: 7 * 60_000 };

export type LockOptions = {
  /** After Tesla accepts the lock, read vehicle_state.locked back. A car that
   * still reports unlocked gets another attempt. */
  confirmLocked?: boolean;
};

export type LockFailureCode = VcpErrorCode | "wake_timeout" | "still_unlocked";

export type LockOutcome =
  | {
      ok: true;
      detail: "locked" | "locked_after_wake" | "already_locked";
      attempts: number;
      woke: boolean;
      /** True when the car itself reported locked, not just Tesla's reply. */
      confirmed: boolean;
    }
  | { ok: false; code: LockFailureCode; detail: string; attempts: number; woke: boolean };

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

async function wakeAndWait(deps: LockDeps, timeoutMs: number, deadline: number): Promise<boolean> {
  const start = deps.now();
  await deps.wake();
  // Count both the sleeps and the clock, so slow polls end the wait too.
  let slept = 0;
  const elapsed = () => Math.max(slept, deps.now() - start);
  for (let poll = 0; elapsed() < timeoutMs && deps.now() < deadline; poll++) {
    const delay = Math.min(
      WAKE_POLL_DELAYS[Math.min(poll, WAKE_POLL_DELAYS.length - 1)] as number,
      timeoutMs - elapsed(),
      Math.max(0, deadline - deps.now()),
    );
    await deps.sleep(delay);
    slept += delay;
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

/** Read the lock state back after Tesla accepted a lock. The state can lag
 * the command by a moment, so poll a few times until it reads locked. Never
 * throws: the lock already went through, only the confirmation is missing. */
async function readBackLocked(deps: LockDeps): Promise<boolean | null> {
  const read = () => deps.isLocked().catch(() => null);
  let locked = await read();
  for (const delay of STATUS_POLL_DELAYS) {
    if (locked === true) break;
    await deps.sleep(delay);
    locked = await read();
  }
  return locked;
}

export async function lockWithRetry(
  deps: LockDeps,
  policy: LockPolicy,
  options: LockOptions = {},
): Promise<LockOutcome> {
  const deadline = deps.now() + policy.budgetMs;
  let woke = false;
  let lastCode: LockFailureCode = "vehicle_unavailable";
  let lastDetail = "not_attempted";

  if ((await deps.getState()) !== "online") {
    woke = true;
    if (!(await wakeAndWait(deps, policy.wakeTimeoutMs, deadline))) {
      lastCode = "wake_timeout";
      lastDetail = "vehicle did not come online after wake";
    }
  }
  // The first attempt always runs; later ones only start within the budget.
  for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
    if (attempt > 1 && deps.now() >= deadline) {
      return { ok: false, code: lastCode, detail: `${lastDetail} time_budget_exhausted`, attempts: attempt - 1, woke };
    }
    const result = await deps.sendLock();
    const locked = woke ? "locked_after_wake" : "locked";
    let code: LockFailureCode;
    if (result.ok) {
      const state = options.confirmLocked ? await readBackLocked(deps) : null;
      if (state !== false) return { ok: true, detail: locked, attempts: attempt, woke, confirmed: state === true };
      // Tesla accepted the command but the car still reports unlocked.
      code = "still_unlocked";
      lastCode = code;
      lastDetail = "unlocked_after_lock";
    } else {
      const { stage } = result.error;
      code = result.error.code;
      lastCode = code;
      lastDetail = stage;
      if (FATAL.has(result.error.code)) return { ok: false, code, detail: stage, attempts: attempt, woke };

      if (code === "status_unknown") {
        // The response was lost, so the lock may have run. Never resend while
        // the outcome is still unknown; only a car that reports itself
        // unlocked gets another attempt.
        const state = await pollLocked(deps);
        if (state === true) return { ok: true, detail: locked, attempts: attempt, woke, confirmed: true };
        if (state === null) return { ok: false, code, detail: stage, attempts: attempt, woke };
      } else {
        if (code === "command_rejected" && (await deps.isLocked()) === true) {
          // The car refuses to lock because it already is.
          return { ok: true, detail: "already_locked", attempts: attempt, woke, confirmed: true };
        }
        if (!result.error.retryable) return { ok: false, code, detail: stage, attempts: attempt, woke };
      }
    }
    if (attempt === policy.maxAttempts) break;
    if (deps.now() >= deadline) {
      return { ok: false, code: lastCode, detail: `${lastDetail} time_budget_exhausted`, attempts: attempt, woke };
    }

    if (code === "vehicle_unavailable") {
      woke = true;
      if (!(await wakeAndWait(deps, policy.wakeTimeoutMs, deadline))) {
        lastCode = "wake_timeout";
        lastDetail = "vehicle did not come online after wake";
      }
    } else {
      await deps.sleep(RETRY_DELAY_MS);
    }
  }
  return { ok: false, code: lastCode, detail: lastDetail, attempts: policy.maxAttempts, woke };
}
