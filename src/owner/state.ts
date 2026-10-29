// OwnerState: one Durable Object per owner. Holds the encrypted Tesla tokens,
// the audit log, and the serialized vehicle-command lane. Everything that
// talks to Tesla on the owner's behalf goes through here.

import { DurableObject } from "cloudflare:workers";
import { bytesToHex, sha256 } from "../bytes";
import type { Env } from "../env";
import { FleetClient, FleetError, summarizeVehicleData, type VehicleSummary } from "../tesla/fleet";
import { defaultFetch, type FetchFn, fetchUpstream, readBoundedText } from "../tesla/http";
import type { SignedCommandResult } from "../tesla/vcp/session";
import { LOCK_POLICY, type LockFailureCode, type LockOutcome, lockWithRetry } from "./lock";
import { decryptTokens, encryptTokens, importTokenKey, type StoredTokens } from "./tokens";

const REFRESH_MARGIN_MS = 5 * 60_000;
const TOKEN_TIMEOUT_MS = 15_000;
const MAX_TOKEN_BODY_BYTES = 32_768;
const AUDIT_KEEP_ROWS = 1000;
const VEHICLE_CACHE_MS = 5 * 60_000;

/** The one-step fix for a rejected Tesla sign-in, shown to callers. */
const REAUTH_MESSAGE =
  "Tesla sign-in has expired or was revoked. Get a new Tesla refresh token and set it with " +
  "`npx wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN`; the next request uses it.";
const NOT_CONNECTED_MESSAGE = "No Tesla account is connected yet.";

export type LockSuccess = Extract<LockOutcome, { ok: true }> & { vehicleId: string };

export type AuditSource = "tool" | "system";
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

/** `reason` names the specific lock failure (pairing_required, wake_timeout,
 * still_unlocked, ...) so a caller can act on it without parsing prose. */
export type OwnerFailure = { code: OwnerErrorCode; message: string; reason?: LockFailureCode };

export type OwnerResult<T> = { ok: true; data: T } | { ok: false; error: OwnerFailure };

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

/** "ok": Tesla has not rejected the current sign-in. "reauth_required": it
 * did; set a new bootstrap refresh token. "not_configured": no account yet. */
export type AuthState = "ok" | "reauth_required" | "not_configured";

export type AuthStatus = { authState: AuthState; message: string | null };

export class OwnerState extends DurableObject<Env> {
  /** Injection points for tests. Production uses the real clock and timers. */
  clock: () => number = () => Date.now();
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));
  fetchFn: FetchFn = defaultFetch;

  private tokenFlight: Promise<string> | null = null;
  private refreshCount = 0;
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
      // Left behind by the removed built-in nightly lock: its alarm and keys.
      await ctx.storage.deleteAlarm();
      ctx.storage.sql.exec("DELETE FROM kv WHERE key IN ('nightly_run', 'last_run', 'scheduled_for')");
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

  /** Load stored tokens. A TESLA_BOOTSTRAP_REFRESH_TOKEN value that has not
   * been seeded before replaces whatever is stored, whatever the auth state:
   * setting a new value is how the owner signs in again. The same value is
   * never seeded twice, so the rotated tokens Tesla issues are kept. Runs only
   * inside the token flight (see getAccessToken). */
  private async loadTokens(): Promise<StoredTokens> {
    const key = await this.tokenKey();
    const blob = this.kvGet("tokens");
    const bootstrap = this.env.TESLA_BOOTSTRAP_REFRESH_TOKEN?.trim();
    const reauth = this.kvGet("auth_state") === "reauth_required";
    if (bootstrap) {
      const seed = await fingerprint(bootstrap);
      if (this.kvGet("seed_fingerprint") !== seed) {
        const seeded: StoredTokens = { accessToken: null, refreshToken: bootstrap, expiresAt: 0 };
        const encrypted = await encryptTokens(key, seeded);
        // Compare-and-set across the await above: if another flight changed
        // the token state meanwhile, start over from what is stored now.
        if (this.kvGet("tokens") !== blob || this.kvGet("seed_fingerprint") === seed) {
          return this.loadTokens();
        }
        this.kvSet("tokens", encrypted);
        this.kvSet("seed_fingerprint", seed);
        this.kvDelete("auth_state");
        this.audit({
          source: "system",
          action: "tokens_seeded",
          vehicleId: null,
          outcome: "ok",
          detail: !blob ? "initial seed" : reauth ? "replaced rejected refresh token" : "replaced stored tokens",
        });
        return seeded;
      }
    }
    if (reauth) throw new OwnerError("reauth_required", REAUTH_MESSAGE);
    if (!blob) throw new OwnerError("not_configured", NOT_CONNECTED_MESSAGE);
    try {
      return await decryptTokens(key, blob);
    } catch {
      throw new OwnerError("not_configured", "Stored Tesla tokens could not be decrypted.");
    }
  }

  /** A valid access token, refreshing when missing or expiring within five
   * minutes. One in-flight promise covers load, seed, and refresh, so token
   * storage only ever changes inside it; concurrent callers share it. `force`
   * is used once after a Fleet 401 with a token that looked valid: a forced
   * caller waits out the current flight and is satisfied by any refresh that
   * completed since it asked. */
  async getAccessToken(force = false): Promise<string> {
    const refreshesAtCall = this.refreshCount;
    while (this.tokenFlight) {
      if (!force) return this.tokenFlight;
      await this.tokenFlight.catch(() => undefined);
      if (this.refreshCount !== refreshesAtCall) force = false;
    }
    const flight: Promise<string> = this.acquireToken(force).finally(() => {
      if (this.tokenFlight === flight) this.tokenFlight = null;
    });
    this.tokenFlight = flight;
    return flight;
  }

  private async acquireToken(force: boolean): Promise<string> {
    const tokens = await this.loadTokens();
    if (!force && tokens.accessToken && tokens.expiresAt - REFRESH_MARGIN_MS > this.clock()) {
      return tokens.accessToken;
    }
    return this.refresh(tokens);
  }

  private async refresh(tokens: StoredTokens): Promise<string> {
    const clientId = this.env.TESLA_CLIENT_ID;
    if (!clientId) throw new OwnerError("not_configured", "TESLA_CLIENT_ID is not configured.");
    // Same form hermes-tescmd-plugin sends (client.refresh_access_token).
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
      console.error(`[tesla-mcp] reauth_required: Tesla rejected the refresh token (http ${response.status})`);
      throw new OwnerError("reauth_required", REAUTH_MESSAGE);
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
    const encrypted = await encryptTokens(await this.tokenKey(), {
      accessToken,
      refreshToken: rotated ?? tokens.refreshToken,
      expiresAt: this.clock() + Math.min(expiresIn, 30 * 86_400) * 1000,
    });
    this.kvSet("tokens", encrypted);
    this.refreshCount++;
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
        console.error("[tesla-mcp] reauth_required: Fleet API rejected a freshly refreshed token");
        throw new OwnerError("reauth_required", REAUTH_MESSAGE);
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

  private failure(error: unknown): { ok: false; error: OwnerFailure } {
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

  /** Lock the car: wake it if needed, poll until online, retry, and read the
   * lock state back. The same policy serves every caller. */
  async lock(input: { vehicleId?: string }): Promise<OwnerResult<LockSuccess>> {
    return this.inLane(() => this.lockFlow(input.vehicleId));
  }

  private async lockFlow(vehicleId: string | undefined): Promise<OwnerResult<LockSuccess>> {
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
          now: () => this.clock(),
        },
        LOCK_POLICY,
        { confirmLocked: true },
      );
      const detail = `${outcome.ok ? outcome.detail : `${outcome.code} ${outcome.detail}`} attempts=${outcome.attempts}${outcome.woke ? " woke" : ""}${outcome.ok && outcome.confirmed ? " confirmed" : ""}`;
      this.audit({
        source: "tool",
        action: "lock",
        vehicleId: vehicle.id,
        outcome: outcome.ok ? "ok" : "error",
        detail,
      });
      if (outcome.ok) return { ok: true, data: { ...outcome, vehicleId: vehicle.id } };
      // A signed command Tesla still refuses after a forced token refresh
      // means the account's sign-in is no longer accepted.
      const code: OwnerErrorCode = outcome.code === "unauthorized" ? "reauth_required" : "command_failed";
      const message = code === "reauth_required" ? REAUTH_MESSAGE : lockFailureMessage(outcome);
      return { ok: false, error: { code, message, reason: outcome.code } };
    } catch (error) {
      this.audit({
        source: "tool",
        action: "lock",
        vehicleId: resolvedId,
        outcome: "error",
        detail: this.errorDetail(error),
      });
      return this.failure(error);
    }
  }

  // ---------------------------------------------------------------------------
  // Sign-in state
  // ---------------------------------------------------------------------------

  /** Sign-in state from storage alone: never calls Tesla or wakes a car. A
   * bootstrap token that has not been seeded yet counts as "ok", because the
   * next request signs in with it (see loadTokens). */
  async authStatus(): Promise<AuthStatus> {
    const bootstrap = this.env.TESLA_BOOTSTRAP_REFRESH_TOKEN?.trim();
    const newBootstrap = bootstrap ? this.kvGet("seed_fingerprint") !== (await fingerprint(bootstrap)) : false;
    if (newBootstrap) return { authState: "ok", message: null };
    if (this.kvGet("auth_state") === "reauth_required")
      return { authState: "reauth_required", message: REAUTH_MESSAGE };
    if (!this.kvGet("tokens")) return { authState: "not_configured", message: NOT_CONNECTED_MESSAGE };
    return { authState: "ok", message: null };
  }
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
    case "still_unlocked":
      return "Tesla accepted the lock, but the car still reports unlocked. A door, trunk, or frunk may be open.";
    default:
      return `The lock did not go through after ${outcome.attempts} tries.`;
  }
}
