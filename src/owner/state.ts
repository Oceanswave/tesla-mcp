// OwnerState: one Durable Object per owner. Holds the encrypted Tesla tokens,
// the audit log, the nightly-lock alarm, and the serialized vehicle-command
// lane. Everything that talks to Tesla on the owner's behalf goes through here.

import { DurableObject } from "cloudflare:workers";
import { bytesToHex, sha256 } from "../bytes";
import type { Env } from "../env";
import { FleetClient, FleetError, summarizeVehicleData, type VehicleSummary } from "../tesla/fleet";
import { defaultFetch, type FetchFn, fetchUpstream, readBoundedText } from "../tesla/http";
import type { SignedCommandResult } from "../tesla/vcp/session";
import { INTERACTIVE_LOCK_POLICY, type LockOutcome, type LockPolicy, lockWithRetry, NIGHTLY_LOCK_POLICY } from "./lock";
import { computeNextRun, localDateString, localParts, parseLocalTime, validTimeZone } from "./schedule";
import { decryptTokens, encryptTokens, importTokenKey, type StoredTokens } from "./tokens";

const REFRESH_MARGIN_MS = 5 * 60_000;
const TOKEN_TIMEOUT_MS = 15_000;
const MAX_TOKEN_BODY_BYTES = 32_768;
const AUDIT_KEEP_ROWS = 1000;
const VEHICLE_CACHE_MS = 5 * 60_000;
/** A nightly alarm that fires this late (platform outage) is skipped rather
 * than locking the car at an unexpected hour. */
const MISSED_WINDOW_MS = 3 * 60 * 60_000;

export type LockSuccess = Extract<LockOutcome, { ok: true }> & { vehicleId: string };

export type AuditSource = "tool" | "alarm" | "system";
export type AuditOutcome = "ok" | "error" | "denied";

export type AuditRow = {
  ts: string;
  source: AuditSource;
  action: string;
  vehicleId: string | null;
  outcome: AuditOutcome;
  detail: string;
};

export type OwnerErrorCode =
  | "not_configured"
  | "reauth_required"
  | "token_refresh_failed"
  | "no_vehicles"
  | "vehicle_id_required"
  | "vehicle_not_found"
  | "vehicle_asleep"
  | "tesla_unavailable"
  | "rate_limited"
  | "command_failed";

export type OwnerResult<T> = { ok: true; data: T } | { ok: false; error: { code: OwnerErrorCode; message: string } };

class OwnerError extends Error {
  constructor(
    readonly code: OwnerErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "OwnerError";
  }
}

/** Audit details are short, internally generated codes. Defense in depth:
 * collapse control characters and redact anything token-shaped. */
export function redactDetail(detail: string): string {
  return detail
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/[A-Za-z0-9._~+/=-]{24,}/g, "[redacted]")
    .slice(0, 200);
}

async function fingerprint(value: string): Promise<string> {
  return bytesToHex(await sha256(new TextEncoder().encode(`tesla-mcp:seed:v1:${value}`))).slice(0, 32);
}

type NightlyConfig =
  | { enabled: false; time: string; timeZone: string; error: string | null }
  | { enabled: true; time: string; timeZone: string; error: null };

export type NightlyLockStatus = {
  enabled: boolean;
  configError: string | null;
  time: string;
  timeZone: string;
  localNow: string;
  nextRun: { at: string; local: string } | null;
  lastRun: { at: string; localDate: string; outcome: AuditOutcome; detail: string } | null;
  authState: "ok" | "reauth_required";
};

export class OwnerState extends DurableObject<Env> {
  /** Injection points for tests. Production uses the real clock and timers. */
  clock: () => number = () => Date.now();
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));
  fetchFn: FetchFn = defaultFetch;

  private refreshing: Promise<string> | null = null;
  private tokenGeneration = 0;
  private lane: Promise<unknown> = Promise.resolve();
  private vehicleCache: { at: number; vehicles: VehicleSummary[] } | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        source TEXT NOT NULL,
        action TEXT NOT NULL,
        vehicle_id TEXT,
        outcome TEXT NOT NULL,
        detail TEXT NOT NULL
      )`);
    });
  }

  // ---------------------------------------------------------------------------
  // Storage helpers
  // ---------------------------------------------------------------------------

  private kvGet(key: string): string | null {
    const row = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM kv WHERE key = ?", key).toArray()[0];
    return row?.value ?? null;
  }

  private kvSet(key: string, value: string): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      key,
      value,
    );
  }

  private kvDelete(key: string): void {
    this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
  }

  async recordAudit(entry: Omit<AuditRow, "ts">): Promise<void> {
    this.audit(entry);
  }

  private audit(entry: Omit<AuditRow, "ts">): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO audit (ts, source, action, vehicle_id, outcome, detail) VALUES (?, ?, ?, ?, ?, ?)",
      new Date(this.clock()).toISOString(),
      entry.source,
      entry.action.slice(0, 64),
      entry.vehicleId,
      entry.outcome,
      redactDetail(entry.detail),
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?)",
      AUDIT_KEEP_ROWS,
    );
  }

  async auditRecent(limit = 20): Promise<AuditRow[]> {
    const bounded = Math.max(1, Math.min(100, Math.floor(limit)));
    return this.ctx.storage.sql
      .exec<{
        ts: string;
        source: AuditSource;
        action: string;
        vehicle_id: string | null;
        outcome: AuditOutcome;
        detail: string;
      }>("SELECT ts, source, action, vehicle_id, outcome, detail FROM audit ORDER BY id DESC LIMIT ?", bounded)
      .toArray()
      .map((row) => ({
        ts: row.ts,
        source: row.source,
        action: row.action,
        vehicleId: row.vehicle_id,
        outcome: row.outcome,
        detail: row.detail,
      }));
  }

  // ---------------------------------------------------------------------------
  // Tesla tokens
  // ---------------------------------------------------------------------------

  private async tokenKey(): Promise<CryptoKey> {
    try {
      return await importTokenKey(this.env.TOKEN_ENCRYPTION_KEY);
    } catch {
      throw new OwnerError("not_configured", "Token encryption is not configured.");
    }
  }

  private async saveTokens(tokens: StoredTokens): Promise<void> {
    this.kvSet("tokens", await encryptTokens(await this.tokenKey(), tokens));
    this.tokenGeneration++;
  }

  /** Load stored tokens, seeding from TESLA_BOOTSTRAP_REFRESH_TOKEN only when
   * nothing is stored yet, or when Tesla rejected the stored refresh token and
   * the owner has since provided a different bootstrap token. */
  private async loadTokens(): Promise<StoredTokens> {
    const key = await this.tokenKey();
    const blob = this.kvGet("tokens");
    const bootstrap = this.env.TESLA_BOOTSTRAP_REFRESH_TOKEN?.trim();
    const reauth = this.kvGet("auth_state") === "reauth_required";
    if (bootstrap && (!blob || reauth)) {
      const seed = await fingerprint(bootstrap);
      if (this.kvGet("seed_fingerprint") !== seed) {
        await this.saveTokens({ accessToken: null, refreshToken: bootstrap, expiresAt: 0 });
        this.kvSet("seed_fingerprint", seed);
        this.kvDelete("auth_state");
        this.audit({
          source: "system",
          action: "tokens_seeded",
          vehicleId: null,
          outcome: "ok",
          detail: reauth ? "replaced rejected refresh token" : "initial seed",
        });
        return { accessToken: null, refreshToken: bootstrap, expiresAt: 0 };
      }
    }
    if (reauth) {
      throw new OwnerError(
        "reauth_required",
        "Tesla sign-in has expired. The owner needs to provide a new refresh token.",
      );
    }
    if (!blob) throw new OwnerError("not_configured", "No Tesla account is connected yet.");
    try {
      return await decryptTokens(key, blob);
    } catch {
      throw new OwnerError("not_configured", "Stored Tesla tokens could not be decrypted.");
    }
  }

  /** A valid access token, refreshing when missing or expiring within five
   * minutes. Concurrent callers share one in-flight refresh. `force` is used
   * once after a Fleet 401 with a token that looked valid. */
  async getAccessToken(force = false): Promise<string> {
    if (this.refreshing) return this.refreshing;
    const generation = this.tokenGeneration;
    const tokens = await this.loadTokens();
    if (this.refreshing) return this.refreshing;
    // A refresh finished while we were loading: what we loaded may hold the
    // rotated-away refresh token. Re-read instead of refreshing with it.
    if (generation !== this.tokenGeneration) return this.getAccessToken(false);
    if (!force && tokens.accessToken && tokens.expiresAt - REFRESH_MARGIN_MS > this.clock()) {
      return tokens.accessToken;
    }
    this.refreshing = this.refresh(tokens).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async refresh(tokens: StoredTokens): Promise<string> {
    const clientId = this.env.TESLA_CLIENT_ID;
    if (!clientId) throw new OwnerError("not_configured", "TESLA_CLIENT_ID is not configured.");
    // Same form the owner's Python plugin sends (client.refresh_access_token).
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refreshToken,
      client_id: clientId,
      audience: this.env.TESLA_FLEET_BASE_URL,
    });
    if (this.env.TESLA_CLIENT_SECRET) form.set("client_secret", this.env.TESLA_CLIENT_SECRET);

    let response: Response;
    try {
      response = await fetchUpstream(
        this.fetchFn,
        this.env.TESLA_AUTH_TOKEN_URL,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
          },
          body: form.toString(),
        },
        TOKEN_TIMEOUT_MS,
      );
    } catch {
      this.audit({ source: "system", action: "token_refresh", vehicleId: null, outcome: "error", detail: "transport" });
      throw new OwnerError("token_refresh_failed", "Tesla sign-in service is unreachable. Try again shortly.");
    }

    let body: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(await readBoundedText(response, MAX_TOKEN_BODY_BYTES)) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        body = parsed as Record<string, unknown>;
      }
    } catch {
      body = {};
    }
    const errorCode = typeof body.error === "string" ? body.error : "";
    if (
      response.status === 401 ||
      errorCode === "invalid_grant" ||
      errorCode === "login_required" ||
      errorCode === "unauthorized_client"
    ) {
      // Stop here: retrying a rejected refresh token only gets the client
      // rate limited. A new bootstrap token clears this state.
      this.kvSet("auth_state", "reauth_required");
      this.audit({
        source: "system",
        action: "token_refresh",
        vehicleId: null,
        outcome: "error",
        detail: `reauth_required ${response.status} ${errorCode.slice(0, 32)}`,
      });
      throw new OwnerError(
        "reauth_required",
        "Tesla sign-in has expired. The owner needs to provide a new refresh token.",
      );
    }
    const accessToken = body.access_token;
    if (response.status !== 200 || typeof accessToken !== "string" || !accessToken) {
      this.audit({
        source: "system",
        action: "token_refresh",
        vehicleId: null,
        outcome: "error",
        detail: `http_${response.status}`,
      });
      throw new OwnerError("token_refresh_failed", "Tesla sign-in service returned an error. Try again shortly.");
    }
    const rotated = typeof body.refresh_token === "string" && body.refresh_token ? body.refresh_token : null;
    const expiresIn = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : 900;
    // Tesla rotates refresh tokens and invalidates the old one: persist the
    // new pair before anyone can use the access token.
    await this.saveTokens({
      accessToken,
      refreshToken: rotated ?? tokens.refreshToken,
      expiresAt: this.clock() + Math.min(expiresIn, 30 * 86_400) * 1000,
    });
    return accessToken;
  }

  private fleet(): FleetClient {
    return new FleetClient(this.env.TESLA_FLEET_BASE_URL, this.fetchFn);
  }

  /** Run a Fleet call; on 401 force exactly one refresh and retry once. */
  private async withToken<T>(call: (accessToken: string) => Promise<T>): Promise<T> {
    try {
      return await call(await this.getAccessToken());
    } catch (error) {
      if (!(error instanceof FleetError) || error.code !== "unauthorized") throw error;
    }
    try {
      return await call(await this.getAccessToken(true));
    } catch (error) {
      if (error instanceof FleetError && error.code === "unauthorized") {
        throw new OwnerError("reauth_required", "Tesla rejected the account token. The owner needs to sign in again.");
      }
      throw error;
    }
  }

  private async signedLock(vin: string): Promise<SignedCommandResult> {
    const stub = this.env.TESLA_VCP.get(this.env.TESLA_VCP.idFromName(vin));
    const send = async (accessToken: string) => stub.signedCommand({ vin, accessToken, command: "door_lock" });
    const first = await send(await this.getAccessToken());
    if (first.ok || first.error.code !== "unauthorized") return first;
    return send(await this.getAccessToken(true));
  }

  // ---------------------------------------------------------------------------
  // Vehicles
  // ---------------------------------------------------------------------------

  private async vehicles(fresh = false): Promise<VehicleSummary[]> {
    if (!fresh && this.vehicleCache && this.clock() - this.vehicleCache.at < VEHICLE_CACHE_MS) {
      return this.vehicleCache.vehicles;
    }
    const vehicles = await this.withToken((token) => this.fleet().listVehicles(token));
    this.vehicleCache = { at: this.clock(), vehicles };
    return vehicles;
  }

  private async resolveVehicle(vehicleId: string | undefined): Promise<VehicleSummary> {
    const requested = vehicleId ?? (this.env.TESLA_VEHICLE_ID?.trim() || undefined);
    const vehicles = await this.vehicles();
    if (requested) {
      const match = vehicles.find((vehicle) => vehicle.id === requested);
      if (!match) throw new OwnerError("vehicle_not_found", "That vehicle is not on this Tesla account.");
      return match;
    }
    if (vehicles.length === 1) return vehicles[0] as VehicleSummary;
    if (!vehicles.length) throw new OwnerError("no_vehicles", "This Tesla account has no vehicles.");
    throw new OwnerError(
      "vehicle_id_required",
      `This account has ${vehicles.length} vehicles. Say which one: ${vehicles
        .map((vehicle) => `${vehicle.displayName ?? "unnamed"} (id ${vehicle.id})`)
        .join(", ")}.`,
    );
  }

  /** Serialize vehicle commands: one wake/lock at a time per owner. */
  private inLane<T>(task: () => Promise<T>): Promise<T> {
    const run = this.lane.then(task);
    this.lane = run.catch(() => undefined);
    return run;
  }

  private failure(error: unknown): { ok: false; error: { code: OwnerErrorCode; message: string } } {
    if (error instanceof OwnerError) return { ok: false, error: { code: error.code, message: error.message } };
    if (error instanceof FleetError) {
      if (error.code === "rate_limited") {
        return {
          ok: false,
          error: { code: "rate_limited", message: "Tesla is rate limiting requests. Try again in a few minutes." },
        };
      }
      if (error.code === "vehicle_unavailable") {
        return { ok: false, error: { code: "vehicle_asleep", message: "The car is asleep or offline." } };
      }
      if (error.code === "not_found") {
        return {
          ok: false,
          error: { code: "vehicle_not_found", message: "That vehicle is not on this Tesla account." },
        };
      }
    }
    return {
      ok: false,
      error: { code: "tesla_unavailable", message: "Tesla's service did not respond as expected. Try again shortly." },
    };
  }

  private errorDetail(error: unknown): string {
    if (error instanceof OwnerError || error instanceof FleetError)
      return error instanceof OwnerError ? error.code : error.message;
    return "internal_error";
  }

  async listVehicles(): Promise<OwnerResult<VehicleSummary[]>> {
    try {
      return { ok: true, data: await this.vehicles(true) };
    } catch (error) {
      return this.failure(error);
    }
  }

  async vehicleStatus(vehicleId?: string): Promise<
    OwnerResult<{
      vehicle: { id: string; displayName: string | null };
      state: string;
      status: ReturnType<typeof summarizeVehicleData> | null;
    }>
  > {
    try {
      const vehicle = await this.resolveVehicle(vehicleId);
      const current = await this.withToken((token) => this.fleet().getVehicle(token, vehicle.id));
      let status: ReturnType<typeof summarizeVehicleData> | null = null;
      let state = current.state;
      if (state === "online") {
        try {
          status = summarizeVehicleData(await this.withToken((token) => this.fleet().vehicleData(token, vehicle.id)));
        } catch (error) {
          // Fell asleep between the two calls: report it, never wake.
          if (!(error instanceof FleetError) || error.code !== "vehicle_unavailable") throw error;
          state = "asleep";
        }
      }
      return { ok: true, data: { vehicle: { id: vehicle.id, displayName: vehicle.displayName }, state, status } };
    } catch (error) {
      return this.failure(error);
    }
  }

  async wake(input: { vehicleId?: string }): Promise<OwnerResult<{ vehicleId: string; state: string }>> {
    return this.inLane(async () => {
      let vehicleId: string | null = input.vehicleId ?? null;
      try {
        const vehicle = await this.resolveVehicle(input.vehicleId);
        vehicleId = vehicle.id;
        const result = await this.withToken((token) => this.fleet().wakeUp(token, vehicle.id));
        this.audit({ source: "tool", action: "wake", vehicleId, outcome: "ok", detail: `state ${result.state}` });
        return { ok: true as const, data: { vehicleId: vehicle.id, state: result.state } };
      } catch (error) {
        this.audit({ source: "tool", action: "wake", vehicleId, outcome: "error", detail: this.errorDetail(error) });
        return this.failure(error);
      }
    });
  }

  async lock(input: { vehicleId?: string }): Promise<OwnerResult<LockSuccess>> {
    return this.inLane(() => this.lockFlow("tool", input.vehicleId, INTERACTIVE_LOCK_POLICY));
  }

  private async lockFlow(
    source: AuditSource,
    vehicleId: string | undefined,
    policy: LockPolicy,
  ): Promise<OwnerResult<LockSuccess>> {
    let resolvedId: string | null = vehicleId ?? null;
    try {
      const vehicle = await this.resolveVehicle(vehicleId);
      resolvedId = vehicle.id;
      const fleet = this.fleet();
      const outcome = await lockWithRetry(
        {
          getState: async () => {
            try {
              return (await this.withToken((token) => fleet.getVehicle(token, vehicle.id))).state;
            } catch (error) {
              if (
                error instanceof FleetError &&
                (error.code === "upstream_error" ||
                  error.code === "vehicle_unavailable" ||
                  error.code === "bad_response")
              ) {
                return null;
              }
              throw error;
            }
          },
          wake: async () => {
            try {
              await this.withToken((token) => fleet.wakeUp(token, vehicle.id));
            } catch (error) {
              // A failed wake_up just means "not online yet"; polling decides.
              if (
                !(error instanceof FleetError) ||
                error.code === "unauthorized" ||
                error.code === "forbidden" ||
                error.code === "rate_limited"
              )
                throw error;
            }
          },
          sendLock: () => this.signedLock(vehicle.vin),
          isLocked: async () => {
            try {
              return summarizeVehicleData(await this.withToken((token) => fleet.vehicleData(token, vehicle.id))).locked;
            } catch (error) {
              if (error instanceof FleetError && error.code !== "unauthorized") return null;
              throw error;
            }
          },
          sleep: (milliseconds) => this.sleep(milliseconds),
        },
        policy,
      );
      const detail = `${outcome.ok ? outcome.detail : `${outcome.code} ${outcome.detail}`} attempts=${outcome.attempts}${outcome.woke ? " woke" : ""}`;
      this.audit({ source, action: "lock", vehicleId: vehicle.id, outcome: outcome.ok ? "ok" : "error", detail });
      if (outcome.ok) return { ok: true, data: { ...outcome, vehicleId: vehicle.id } };
      return { ok: false, error: { code: "command_failed", message: lockFailureMessage(outcome) } };
    } catch (error) {
      this.audit({ source, action: "lock", vehicleId: resolvedId, outcome: "error", detail: this.errorDetail(error) });
      return this.failure(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Nightly lock
  // ---------------------------------------------------------------------------

  private nightlyConfig(): NightlyConfig {
    const time = this.env.NIGHTLY_LOCK_TIME;
    const timeZone = this.env.NIGHTLY_LOCK_TIMEZONE;
    if (this.env.NIGHTLY_LOCK_ENABLED !== "true") return { enabled: false, time, timeZone, error: null };
    if (!parseLocalTime(time)) return { enabled: false, time, timeZone, error: "NIGHTLY_LOCK_TIME must be HH:MM" };
    if (!validTimeZone(timeZone)) {
      return { enabled: false, time, timeZone, error: "NIGHTLY_LOCK_TIMEZONE is not a valid IANA time zone" };
    }
    return { enabled: true, time, timeZone, error: null };
  }

  /** Idempotent: set the alarm to the next nightly run unless it already is.
   * Called by the cron trigger every 15 minutes and after each run. */
  async ensureAlarm(): Promise<{ nextRun: string | null }> {
    const config = this.nightlyConfig();
    if (!config.enabled) {
      await this.ctx.storage.deleteAlarm();
      this.kvDelete("scheduled_for");
      return { nextRun: null };
    }
    const next = computeNextRun(new Date(this.clock()), config.time, config.timeZone).getTime();
    if ((await this.ctx.storage.getAlarm()) !== next) {
      await this.ctx.storage.setAlarm(next);
    }
    this.kvSet("scheduled_for", String(next));
    return { nextRun: new Date(next).toISOString() };
  }

  override async alarm(): Promise<void> {
    const config = this.nightlyConfig();
    if (!config.enabled) {
      this.kvDelete("scheduled_for");
      return;
    }
    const now = this.clock();
    const scheduledFor = Number(this.kvGet("scheduled_for") ?? Number.NaN);
    const target = Number.isFinite(scheduledFor) ? scheduledFor : now;
    if (now < target - 60_000) {
      // Stale alarm from an older schedule; re-arm for the real time.
      await this.ensureAlarm();
      return;
    }
    const runDate = localDateString(target, config.timeZone);
    if (this.kvGet("last_run_local_date") === runDate) {
      await this.ensureAlarm();
      return;
    }
    // Claim the date before running so a duplicate or retried alarm can never
    // lock twice for the same night.
    this.kvSet("last_run_local_date", runDate);
    try {
      if (now - target > MISSED_WINDOW_MS) {
        this.recordLastRun(runDate, "error", "skipped: alarm fired too late");
        this.audit({
          source: "alarm",
          action: "nightly_lock",
          vehicleId: null,
          outcome: "error",
          detail: "missed_window",
        });
        return;
      }
      const result = await this.inLane(() => this.lockFlow("alarm", undefined, NIGHTLY_LOCK_POLICY));
      if (result.ok) {
        this.recordLastRun(
          runDate,
          "ok",
          result.data.detail === "locked_after_wake" ? "lock command succeeded after waking" : result.data.detail,
        );
      } else {
        this.recordLastRun(runDate, "error", result.error.code);
      }
    } catch {
      this.recordLastRun(runDate, "error", "internal_error");
    } finally {
      await this.ensureAlarm();
    }
  }

  private recordLastRun(localDate: string, outcome: AuditOutcome, detail: string): void {
    this.kvSet(
      "last_run",
      JSON.stringify({ at: new Date(this.clock()).toISOString(), localDate, outcome, detail: redactDetail(detail) }),
    );
  }

  async nightlyLockStatus(): Promise<NightlyLockStatus> {
    const config = this.nightlyConfig();
    const now = this.clock();
    const scheduled = Number(this.kvGet("scheduled_for") ?? Number.NaN);
    let nextRun: NightlyLockStatus["nextRun"] = null;
    let localNow = new Date(now).toISOString();
    if (config.enabled) {
      const next =
        Number.isFinite(scheduled) && scheduled > now
          ? scheduled
          : computeNextRun(new Date(now), config.time, config.timeZone).getTime();
      nextRun = { at: new Date(next).toISOString(), local: formatLocal(next, config.timeZone) };
      localNow = formatLocal(now, config.timeZone);
    }
    const lastRaw = this.kvGet("last_run");
    return {
      enabled: config.enabled,
      configError: config.error,
      time: config.time,
      timeZone: config.timeZone,
      localNow,
      nextRun,
      lastRun: lastRaw ? (JSON.parse(lastRaw) as NightlyLockStatus["lastRun"]) : null,
      authState: this.kvGet("auth_state") === "reauth_required" ? "reauth_required" : "ok",
    };
  }
}

function formatLocal(instant: number, timeZone: string): string {
  const p = localParts(instant, timeZone);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${p.year}-${pad(p.month)}-${pad(p.day)} ${pad(p.hour)}:${pad(p.minute)} ${timeZone}`;
}

function lockFailureMessage(outcome: Extract<LockOutcome, { ok: false }>): string {
  switch (outcome.code) {
    case "pairing_required":
      return "The car does not recognize this app's key. Pair the virtual key in the Tesla app, then try again.";
    case "remote_access_required":
      return "Mobile access is turned off in the car. Turn it on, then try again.";
    case "unauthorized":
    case "forbidden":
      return "Tesla rejected the account's permission to send commands.";
    case "rate_limited":
      return "Tesla is rate limiting commands. Try again in a few minutes.";
    case "unconfigured":
      return "Signed commands are not configured on this server.";
    case "vehicle_unavailable":
    case "wake_timeout":
      return `The car did not respond after ${outcome.attempts} tries. It may be out of coverage.`;
    case "status_unknown":
      return "Tesla did not confirm the lock. Check the car before trying again.";
    default:
      return `The lock did not go through after ${outcome.attempts} tries.`;
  }
}
