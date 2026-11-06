// Per-command webhook: one POST for each audit row, sent in the background.
// A failed or slow send must never affect the command that caused it, so
// notifyAudit never rejects. The URL and auth value are secrets: log lines
// carry fixed codes only, never an error's own message, which can name the URL.

import type { Env } from "../env";
import { type FetchFn, fetchUpstream } from "../tesla/http";
import type { AuditOutcome, AuditSource } from "./state";

const SEND_TIMEOUT_MS = 5_000;
const MAX_ATTEMPTS = 2;

export type NotifyEnv = Partial<
  Pick<Env, "NOTIFY_URL" | "NOTIFY_AUTH" | "NOTIFY_DRY_RUN" | "NOTIFY_ACTIONS" | "NOTIFY_OUTCOMES">
>;

/** One stored audit row, plus whether it was a dangerous command. */
export type NotifyEvent = {
  id: number;
  ts: string;
  action: string;
  source: AuditSource;
  vehicleId: string | null;
  outcome: AuditOutcome;
  detail: string;
  dangerous: boolean;
};

function allowed(list: string | undefined, value: string): boolean {
  const names = (list ?? "")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  return names.length === 0 || names.includes(value);
}

/** A refusal always gets through: the filters narrow routine traffic, and
 * must not be able to hide someone being turned away. */
function selected(env: NotifyEnv, event: NotifyEvent): boolean {
  if (event.outcome === "denied") return true;
  return allowed(env.NOTIFY_ACTIONS, event.action) && allowed(env.NOTIFY_OUTCOMES, event.outcome);
}

const lastFour = (id: string) => `…${id.slice(-4)}`;

/** Audit details can carry an energy site id, and a car's reason text is not
 * ours: neither may leave as a full VIN or Fleet id. */
const maskIds = (detail: string) => detail.replace(/\b[A-HJ-NPR-Z0-9]{17}\b|\d{5,}/g, lastFour);

function payload(event: NotifyEvent): string {
  return JSON.stringify({
    source: "tesla-mcp",
    event: "command",
    id: String(event.id),
    ts: event.ts,
    action: event.action,
    caller: event.source,
    outcome: event.outcome,
    detail: maskIds(event.detail),
    vehicle: event.vehicleId === null ? null : lastFour(event.vehicleId),
    dangerous: event.dangerous,
  });
}

type SendFailure = { reason: string; retry: boolean };

async function send(fetchFn: FetchFn, url: string, init: RequestInit): Promise<SendFailure | null> {
  let response: Response;
  try {
    response = await fetchUpstream(fetchFn, url, init, SEND_TIMEOUT_MS);
  } catch (error) {
    return { reason: error instanceof Error ? error.name : "unknown", retry: true };
  }
  await response.body?.cancel().catch(() => {});
  if (response.ok) return null;
  // A 504 may have been processed behind the gateway; a 4xx will not change.
  return { reason: `http_${response.status}`, retry: response.status >= 500 && response.status !== 504 };
}

export async function notifyAudit(env: NotifyEnv, fetchFn: FetchFn, event: NotifyEvent): Promise<void> {
  try {
    if (!selected(env, event)) return;
    const body = payload(event);
    if (env.NOTIFY_DRY_RUN === "true") {
      console.log(`[tesla-mcp] notify dry run: ${body}`);
      return;
    }
    const url = env.NOTIFY_URL?.trim();
    if (!url) return;
    const authorization = env.NOTIFY_AUTH?.trim();
    if (!authorization) {
      console.error("[tesla-mcp] notify skipped: NOTIFY_AUTH is not set");
      return;
    }
    const init: RequestInit = {
      method: "POST",
      headers: {
        Authorization: authorization,
        "Content-Type": "application/json",
        "Idempotency-Key": `tesla-${event.id}`,
      },
      body,
    };
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const failure = await send(fetchFn, url, init);
      if (!failure) return;
      console.error(`[tesla-mcp] notify attempt ${attempt} failed for audit ${event.id}: ${failure.reason}`);
      if (!failure.retry) return;
    }
  } catch {
    console.error(`[tesla-mcp] notify failed for audit ${event.id}`);
  }
}
