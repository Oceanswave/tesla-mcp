// OwnerState: one Durable Object per owner. Holds the encrypted Tesla tokens,
// the audit log, and the serialized vehicle-command lane. Everything that
// talks to Tesla on the owner's behalf goes through here.

import { DurableObject } from "cloudflare:workers";
import { bytesToHex, sha256 } from "../bytes";
import type { Env } from "../env";
import { type DangerousAction, dangerousCommandsEnabled, dangerousSignedCommand } from "../mcp/dangerous";
import {
  describeScopes,
  EndpointParamError,
  endpointScopes,
  FLEET_ENDPOINTS,
  type FleetEndpointName,
  isFleetEndpointName,
  type ScopeRequirement,
  signedCommandScopes,
} from "../tesla/endpoints";
import { FleetClient, FleetError, summarizeVehicleData, type VehicleSummary } from "../tesla/fleet";
import { defaultFetch, type FetchFn, fetchUpstream, readBoundedText } from "../tesla/http";
import { accessTokenClaims, newSignInState, SIGN_IN_STATE_PATTERN, SIGN_IN_STATE_TTL_MS } from "../tesla/oauth";
import type { CommandParams } from "../tesla/vcp/payloads";
import { isSignedCommandName, type SignedCommandName } from "../tesla/vcp/protocol";
import type { SignedCommandResult, VcpErrorCode } from "../tesla/vcp/session";
import { LOCK_POLICY, type LockFailureCode, type LockOutcome, lockWithRetry } from "./lock";
import { decryptTokens, encryptTokens, importTokenKey, type StoredTokens } from "./tokens";

const REFRESH_MARGIN_MS = 5 * 60_000;
const TOKEN_TIMEOUT_MS = 15_000;
const MAX_TOKEN_BODY_BYTES = 32_768;
const AUDIT_KEEP_ROWS = 1000;
const VEHICLE_CACHE_MS = 5 * 60_000;
const ID_PATTERN = /^\d{1,20}$/;
/** Anyone can open /login: pending sign-ins beyond this many drop the oldest. */
const MAX_PENDING_SIGN_INS = 100;

/** The one-step fix for a rejected Tesla sign-in, shown to callers. */
const REAUTH_MESSAGE =
  "Tesla sign-in has expired or was revoked. Sign in again by opening /login on this server in a browser, " +
  "or get a new Tesla refresh token and set it with " +
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
  | "forbidden"
  | "invalid_request"
  | "not_supported"
  | "dangerous_disabled"
  | "no_energy_sites"
  | "energy_site_id_required"
  | "energy_site_not_found"
  | "not_found"
  | "command_failed";

/** `reason` names the specific failure (pairing_required, wake_timeout,
 * still_unlocked, command_rejected, ...) so a caller can act on it without
 * parsing prose. `carReason` is the car's own short reason, when it gave one
 * (for example is_charging or already_set). */
export type OwnerFailure = {
  code: OwnerErrorCode;
  message: string;
  reason?: LockFailureCode | VcpErrorCode;
  carReason?: string;
};

export type EnergySiteSummary = { energySiteId: string; name: string | null; resourceType: string | null };

export type EndpointInput = {
  vehicleId?: string;
  energySiteId?: string;
  params?: Readonly<Record<string, unknown>>;
};

/** `data` is Tesla's parsed JSON `response`, passed through as is. */
export type EndpointSuccess = { data: unknown; vehicleId?: string; energySiteId?: string };

export type OwnerResult<T> = { ok: true; data: T } | { ok: false; error: OwnerFailure };

/** The audit log records Fleet vehicle ids only: a VIN a caller passed is
 * left out until it resolves to an id. */
function auditableVehicleId(value: string | undefined): string | null {
  return value && ID_PATTERN.test(value) ? value : null;
}

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

/** `scopes` are the ones granted to the stored access token (its `scp`
 * claim), when the state is ok and the token is readable. */
export type AuthStatus = { authState: AuthState; message: string | null; scopes: string[] | null };

/** What /callback shows. Failure reasons are fixed codes, never Tesla text. */
export type SignInResult =
  | { ok: true; scope: string }
  | { ok: false; reason: "invalid_state" | "denied" | "not_configured" | "exchange_failed" | "account_mismatch" };

type IssuedTokens = { accessToken: string; refreshToken: string | null; expiresIn: number };

/** The tokens in a 200 answer from Tesla's token endpoint, or null. */
function issuedTokens(body: Record<string, unknown>): IssuedTokens | null {
  const accessToken = body.access_token;
  if (typeof accessToken !== "string" || !accessToken) return null;
  return {
    accessToken,
    refreshToken: typeof body.refresh_token === "string" && body.refresh_token ? body.refresh_token : null,
    expiresIn: typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : 900,
  };
}

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
  private siteCache: { at: number; sites: EnergySiteSummary[] } | null = null;

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
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS sign_in_state (
        state TEXT PRIMARY KEY,
        redirect_uri TEXT NOT NULL,
        expires_at INTEGER NOT NULL
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

  /** POST one grant to Tesla's token endpoint. The client fields follow the
   * grant's own fields (same form hermes-tescmd-plugin sends for a refresh);
   * client_secret only when configured. */
  private async tokenRequest(
    action: string,
    grant: Record<string, string>,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const clientId = this.env.TESLA_CLIENT_ID;
    if (!clientId) throw new OwnerError("not_configured", "TESLA_CLIENT_ID is not configured.");
    const form = new URLSearchParams({ ...grant, client_id: clientId, audience: this.env.TESLA_FLEET_BASE_URL });
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
      this.audit({ source: "system", action, vehicleId: null, outcome: "error", detail: "transport" });
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
    return { status: response.status, body };
  }

  /** Tesla rotates refresh tokens and invalidates the old one: persist the
   * new pair before anyone can use the access token. Also records the
   * account (`sub`) the tokens belong to, which browser sign-in is pinned to
   * and which outlives a re-seed. Runs only inside the token flight. */
  private async storeTokens(issued: IssuedTokens, previousRefreshToken: string | null): Promise<void> {
    const refreshToken = issued.refreshToken ?? previousRefreshToken;
    if (!refreshToken) throw new OwnerError("token_refresh_failed", "Tesla did not issue a refresh token.");
    const encrypted = await encryptTokens(await this.tokenKey(), {
      accessToken: issued.accessToken,
      refreshToken,
      expiresAt: this.clock() + Math.min(issued.expiresIn, 30 * 86_400) * 1000,
    });
    this.kvSet("tokens", encrypted);
    const account = accessTokenClaims(issued.accessToken).sub;
    if (account) this.kvSet("account_sub", account);
    this.refreshCount++;
  }

  private async refresh(tokens: StoredTokens): Promise<string> {
    const { status, body } = await this.tokenRequest("token_refresh", {
      grant_type: "refresh_token",
      refresh_token: tokens.refreshToken,
    });
    const errorCode = typeof body.error === "string" ? body.error : "";
    if (
      status === 401 ||
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
        detail: `reauth_required ${status} ${errorCode.slice(0, 32)}`,
      });
      console.error(`[tesla-mcp] reauth_required: Tesla rejected the refresh token (http ${status})`);
      throw new OwnerError("reauth_required", REAUTH_MESSAGE);
    }
    const issued = status === 200 ? issuedTokens(body) : null;
    if (!issued) {
      this.audit({
        source: "system",
        action: "token_refresh",
        vehicleId: null,
        outcome: "error",
        detail: `http_${status}`,
      });
      throw new OwnerError("token_refresh_failed", "Tesla sign-in service returned an error. Try again shortly.");
    }
    await this.storeTokens(issued, tokens.refreshToken);
    return issued.accessToken;
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

  private async signed(vin: string, command: SignedCommandName, params?: CommandParams): Promise<SignedCommandResult> {
    const stub = this.env.TESLA_VCP.get(this.env.TESLA_VCP.idFromName(vin));
    const send = async (accessToken: string) =>
      stub.signedCommand({ vin, accessToken, command, ...(params ? { params } : {}) });
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

  /** An explicit vehicle (id or VIN) wins; then DEFAULT_VIN (also an id or
   * VIN); then the account's only vehicle. Every choice must be on the
   * account, and an ambiguous request names the vehicles to choose from. */
  private async resolveVehicle(vehicleId: string | undefined): Promise<VehicleSummary> {
    const explicit = vehicleId?.trim() || undefined;
    const configured = this.env.DEFAULT_VIN?.trim() || undefined;
    const vehicles = await this.vehicles();
    const choices = () =>
      vehicles
        .map((vehicle) => `${vehicle.displayName ?? "unnamed"} (id ${vehicle.id}, VIN ${vehicle.vin})`)
        .join(", ");
    const find = (wanted: string) =>
      vehicles.find((vehicle) => vehicle.id === wanted || vehicle.vin === wanted.toUpperCase());
    if (explicit) {
      const match = find(explicit);
      if (!match) {
        throw new OwnerError(
          "vehicle_not_found",
          `That vehicle is not on this Tesla account.${vehicles.length ? ` Vehicles: ${choices()}.` : ""}`,
        );
      }
      return match;
    }
    if (configured) {
      const match = find(configured);
      if (!match) {
        throw new OwnerError(
          "vehicle_not_found",
          `DEFAULT_VIN is set to ${configured}, which is not on this Tesla account.${
            vehicles.length ? ` Vehicles: ${choices()}.` : ""
          } Fix DEFAULT_VIN in wrangler.jsonc or pass vehicle_id.`,
        );
      }
      return match;
    }
    if (vehicles.length === 1) return vehicles[0] as VehicleSummary;
    if (!vehicles.length) throw new OwnerError("no_vehicles", "This Tesla account has no vehicles.");
    throw new OwnerError(
      "vehicle_id_required",
      `This account has ${vehicles.length} vehicles and DEFAULT_VIN is not set. Pass vehicle_id (an id or VIN): ${choices()}.`,
    );
  }

  /** Serialize vehicle commands: one wake/lock at a time per owner. */
  private inLane<T>(task: () => Promise<T>): Promise<T> {
    const run = this.lane.then(task);
    this.lane = run.catch(() => undefined);
    return run;
  }

  private failure(error: unknown, scopes?: ScopeRequirement): { ok: false; error: OwnerFailure } {
    if (error instanceof OwnerError) return { ok: false, error: { code: error.code, message: error.message } };
    if (error instanceof EndpointParamError) {
      return { ok: false, error: { code: "invalid_request", message: `The ${error.param} value is not valid.` } };
    }
    if (error instanceof FleetError) {
      if (error.code === "forbidden") return { ok: false, error: forbidden(scopes) };
      if (error.code === "invalid_request") {
        return {
          ok: false,
          error: {
            code: "invalid_request",
            message: "Tesla rejected the request as invalid for this account or product.",
          },
        };
      }
      if (error.code === "not_supported") {
        return {
          ok: false,
          error: { code: "not_supported", message: "Tesla says this is not available for this vehicle or product." },
        };
      }
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
    if (error instanceof EndpointParamError) return error.message;
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
      vehicle: { id: string; vin: string; displayName: string | null };
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
      return {
        ok: true,
        data: {
          vehicle: { id: vehicle.id, vin: vehicle.vin, displayName: vehicle.displayName },
          state,
          status,
        },
      };
    } catch (error) {
      return this.failure(error);
    }
  }

  async wake(input: { vehicleId?: string }): Promise<OwnerResult<{ vehicleId: string; state: string }>> {
    return this.inLane(async () => {
      let vehicleId: string | null = auditableVehicleId(input.vehicleId);
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
    let resolvedId: string | null = auditableVehicleId(vehicleId);
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
          sendLock: () => this.signed(vehicle.vin, "door_lock"),
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
  // Energy sites
  // ---------------------------------------------------------------------------

  private async energySites(fresh = false): Promise<EnergySiteSummary[]> {
    if (!fresh && this.siteCache && this.clock() - this.siteCache.at < VEHICLE_CACHE_MS) return this.siteCache.sites;
    const products = await this.withToken((token) =>
      this.fleet().call(token, FLEET_ENDPOINTS.products.build({ params: {} })),
    );
    if (!Array.isArray(products)) throw new FleetError("bad_response", null);
    const sites = products.flatMap((product): EnergySiteSummary[] => {
      const record = product && typeof product === "object" ? (product as Record<string, unknown>) : null;
      const id = record?.energy_site_id;
      if (typeof id !== "string" || !ID_PATTERN.test(id)) return [];
      const text = (value: unknown) => (typeof value === "string" && value.length <= 128 ? value : null);
      return [{ energySiteId: id, name: text(record?.site_name), resourceType: text(record?.resource_type) }];
    });
    this.siteCache = { at: this.clock(), sites };
    return sites;
  }

  /** Like resolveVehicle: an explicit id must be on the account; with none,
   * the account's only energy site is used. */
  private async resolveEnergySite(energySiteId: string | undefined): Promise<EnergySiteSummary> {
    const sites = await this.energySites();
    if (energySiteId) {
      const match = sites.find((site) => site.energySiteId === energySiteId);
      if (!match) throw new OwnerError("energy_site_not_found", "That energy site is not on this Tesla account.");
      return match;
    }
    if (sites.length === 1) return sites[0] as EnergySiteSummary;
    if (!sites.length) throw new OwnerError("no_energy_sites", "This Tesla account has no energy products.");
    throw new OwnerError(
      "energy_site_id_required",
      `This account has ${sites.length} energy sites. Say which one: ${sites
        .map((site) => `${site.name ?? "unnamed"} (id ${site.energySiteId})`)
        .join(", ")}.`,
    );
  }

  // ---------------------------------------------------------------------------
  // Allowlisted Fleet endpoints and signed commands
  // ---------------------------------------------------------------------------

  private refuseDangerous(action: DangerousAction | undefined): void {
    if (action && !dangerousCommandsEnabled(this.env)) {
      throw new OwnerError(
        "dangerous_disabled",
        `This server does not send ${action.replaceAll("_", " ")} commands (DANGEROUS_COMMANDS_ENABLED is not "true").`,
      );
    }
  }

  /** Call one endpoint from FLEET_ENDPOINTS. Reads never wake the car (Fleet
   * answers 408 while it sleeps). Changes run in the command lane and are
   * audited. */
  async fleetEndpoint(name: FleetEndpointName, input: EndpointInput = {}): Promise<OwnerResult<EndpointSuccess>> {
    if (!isFleetEndpointName(name)) {
      return { ok: false, error: { code: "invalid_request", message: "Unknown endpoint." } };
    }
    const endpoint: (typeof FLEET_ENDPOINTS)[FleetEndpointName] = FLEET_ENDPOINTS[name];
    const params = input.params ?? {};
    const scopes = endpointScopes(name, params);
    const run = async (): Promise<OwnerResult<EndpointSuccess>> => {
      let vehicleId: string | null = auditableVehicleId(input.vehicleId);
      let energySiteId: string | null = input.energySiteId ?? null;
      try {
        this.refuseDangerous("dangerousAction" in endpoint ? endpoint.dangerousAction : undefined);
        let vin: string | undefined;
        if (endpoint.target === "vehicle") {
          const vehicle = await this.resolveVehicle(input.vehicleId);
          vehicleId = vehicle.id;
          vin = vehicle.vin;
        } else if (endpoint.target === "energy_site") {
          energySiteId = (await this.resolveEnergySite(input.energySiteId)).energySiteId;
        }
        const request = endpoint.build({
          vehicleId: vehicleId ?? undefined,
          vin,
          energySiteId: energySiteId ?? undefined,
          params,
        });
        const data = await this.withToken((token) => this.fleet().call(token, request));
        if ("vehicleCommand" in endpoint) {
          const response = data && typeof data === "object" ? (data as Record<string, unknown>) : {};
          if (response.result !== true) {
            const carReason = sanitizeCarReason(response.reason);
            this.audit({ source: "tool", action: name, vehicleId, outcome: "error", detail: `rejected ${carReason}` });
            return {
              ok: false,
              error: {
                code: "command_failed",
                reason: "command_rejected",
                carReason,
                message: `The car refused the command (${carReason}).`,
              },
            };
          }
        }
        if (endpoint.mutates) {
          this.audit({
            source: "tool",
            action: name,
            vehicleId,
            outcome: "ok",
            detail: energySiteId ? `site ${energySiteId}` : "ok",
          });
        }
        return {
          ok: true,
          data: {
            data,
            ...(vehicleId ? { vehicleId } : {}),
            ...(energySiteId ? { energySiteId } : {}),
          },
        };
      } catch (error) {
        // A timeout, a 5xx, or an unreadable 200 can all come after Tesla
        // acted on the request: for a change, the outcome is unknown, and the
        // caller must check before repeating it (as for signed commands).
        const unknownOutcome =
          endpoint.mutates &&
          error instanceof FleetError &&
          (error.code === "bad_response" ||
            (error.code === "upstream_error" && (error.status === null || error.status >= 500)));
        if (endpoint.mutates) {
          this.audit({
            source: "tool",
            action: name,
            vehicleId,
            outcome: "error",
            detail: unknownOutcome ? `status_unknown ${this.errorDetail(error)}` : this.errorDetail(error),
          });
        }
        if (unknownOutcome) {
          return {
            ok: false,
            error: {
              code: "command_failed",
              reason: "status_unknown",
              message: "Tesla did not confirm the change. Check its current state before trying again.",
            },
          };
        }
        // The vehicle or site was already resolved against the account, so a
        // 404 here is about the thing asked for (an expired invite, hardware
        // the site lacks), not about which vehicle it is.
        if (error instanceof FleetError && error.code === "not_found") {
          return {
            ok: false,
            error: {
              code: "not_found",
              message:
                "Tesla found nothing for this request (for example an expired invite, or hardware this product lacks).",
            },
          };
        }
        if (endpoint.target !== "vehicle" && error instanceof FleetError && error.code === "vehicle_unavailable") {
          return {
            ok: false,
            error: { code: "tesla_unavailable", message: "The energy site did not respond. It may be offline." },
          };
        }
        return this.failure(error, scopes);
      }
    };
    return endpoint.mutates ? this.inLane(run) : run();
  }

  /** Send one signed command from SIGNED_COMMANDS. Never wakes the car: an
   * asleep car fails with vehicle_asleep, and the caller decides whether to
   * wake it. Lock has its own wake-and-retry flow (lock()). */
  async signedVehicleCommand(input: {
    command: SignedCommandName;
    params?: CommandParams;
    vehicleId?: string;
  }): Promise<OwnerResult<{ vehicleId: string }>> {
    const { command } = input;
    if (!isSignedCommandName(command)) {
      return { ok: false, error: { code: "invalid_request", message: "Unknown command." } };
    }
    const params = input.params ?? {};
    return this.inLane(async () => {
      let vehicleId: string | null = auditableVehicleId(input.vehicleId);
      try {
        this.refuseDangerous(dangerousSignedCommand(command, params));
        const vehicle = await this.resolveVehicle(input.vehicleId);
        vehicleId = vehicle.id;
        const sent = await this.signed(vehicle.vin, command, params);
        if (sent.ok) {
          this.audit({ source: "tool", action: command, vehicleId, outcome: "ok", detail: "signed" });
          return { ok: true as const, data: { vehicleId: vehicle.id } };
        }
        const { code, stage, reason } = sent.error;
        this.audit({
          source: "tool",
          action: command,
          vehicleId,
          outcome: "error",
          detail: `${code} ${stage}${reason ? ` ${reason}` : ""}`,
        });
        return { ok: false as const, error: signedFailure(code, stage, reason, signedCommandScopes(command)) };
      } catch (error) {
        this.audit({ source: "tool", action: command, vehicleId, outcome: "error", detail: this.errorDetail(error) });
        return this.failure(error, signedCommandScopes(command));
      }
    });
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
    if (newBootstrap) return { authState: "ok", message: null, scopes: null };
    if (this.kvGet("auth_state") === "reauth_required")
      return { authState: "reauth_required", message: REAUTH_MESSAGE, scopes: null };
    if (!this.kvGet("tokens")) return { authState: "not_configured", message: NOT_CONNECTED_MESSAGE, scopes: null };
    return { authState: "ok", message: null, scopes: (await this.storedClaims()).scopes };
  }

  /** Claims of the stored access token; nulls when there is none. */
  private async storedClaims(): Promise<ReturnType<typeof accessTokenClaims>> {
    const blob = this.kvGet("tokens");
    try {
      return accessTokenClaims(blob ? (await decryptTokens(await this.tokenKey(), blob)).accessToken : null);
    } catch {
      return accessTokenClaims(null);
    }
  }

  // ---------------------------------------------------------------------------
  // Browser sign-in (/login and /callback)
  // ---------------------------------------------------------------------------

  /** Start a browser sign-in: a single-use state value, valid for ten
   * minutes, bound to the redirect URI /login sends to Tesla. */
  async beginSignIn(redirectUri: string): Promise<string> {
    const state = newSignInState();
    const now = this.clock();
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM sign_in_state WHERE expires_at <= ?", now);
    sql.exec(
      "DELETE FROM sign_in_state WHERE state NOT IN (SELECT state FROM sign_in_state ORDER BY expires_at DESC LIMIT ?)",
      MAX_PENDING_SIGN_INS - 1,
    );
    sql.exec(
      "INSERT INTO sign_in_state (state, redirect_uri, expires_at) VALUES (?, ?, ?)",
      state,
      redirectUri,
      now + SIGN_IN_STATE_TTL_MS,
    );
    return state;
  }

  /** Finish a browser sign-in. The state is consumed first, whatever happens
   * next. The code is exchanged with `redirectUri`, which must still be the
   * one /login stored with the state (Tesla rejects any other), and the new tokens replace the stored ones through the token flight, as a
   * refresh does. /login is public, so once any token has named the account
   * (its `sub`), only that Tesla account can sign in. A bootstrap value not
   * tried yet is tried first: it is the owner's, and may name the account. */
  async completeSignIn(input: {
    state: string;
    code: string | null;
    error: string | null;
    redirectUri: string;
  }): Promise<SignInResult> {
    const pending = SIGN_IN_STATE_PATTERN.test(input.state)
      ? this.ctx.storage.sql
          .exec<{ redirect_uri: string; expires_at: number }>(
            "DELETE FROM sign_in_state WHERE state = ? RETURNING redirect_uri, expires_at",
            input.state,
          )
          .toArray()[0]
      : undefined;
    // Not audited: anyone can reach /callback, and the audit log is capped.
    if (!pending || pending.expires_at <= this.clock() || pending.redirect_uri !== input.redirectUri) {
      return { ok: false, reason: "invalid_state" };
    }
    if (input.error || !input.code) return { ok: false, reason: "denied" };
    try {
      await this.tokenKey();
      const bootstrap = this.env.TESLA_BOOTSTRAP_REFRESH_TOKEN?.trim();
      if (bootstrap && this.kvGet("seed_fingerprint") !== (await fingerprint(bootstrap))) {
        // Seeds and refreshes; a rejected value ends in reauth_required, as on any request.
        await this.getAccessToken().catch(() => undefined);
      }
      const { status, body } = await this.tokenRequest("browser_sign_in", {
        grant_type: "authorization_code",
        code: input.code,
        redirect_uri: input.redirectUri,
      });
      const issued = status === 200 ? issuedTokens(body) : null;
      if (!issued?.refreshToken) {
        const errorCode = typeof body.error === "string" ? body.error : "";
        console.error(`[tesla-mcp] browser sign-in: Tesla refused the code (http ${status} ${errorCode.slice(0, 32)})`);
        return { ok: false, reason: "exchange_failed" };
      }
      const claims = accessTokenClaims(issued.accessToken);
      const current = this.kvGet("account_sub") ?? (await this.storedClaims()).sub;
      if (current && current !== claims.sub) {
        this.audit({
          source: "system",
          action: "browser_sign_in",
          vehicleId: null,
          outcome: "denied",
          detail: "account_mismatch",
        });
        return { ok: false, reason: "account_mismatch" };
      }
      while (this.tokenFlight) await this.tokenFlight.catch(() => undefined);
      const flight: Promise<string> = this.adoptSignIn(issued).finally(() => {
        if (this.tokenFlight === flight) this.tokenFlight = null;
      });
      this.tokenFlight = flight;
      await flight;
      const scope = typeof body.scope === "string" ? body.scope : (claims.scopes ?? []).join(" ");
      return { ok: true, scope: sanitizeScope(scope) };
    } catch (error) {
      if (error instanceof OwnerError && error.code === "not_configured")
        return { ok: false, reason: "not_configured" };
      return { ok: false, reason: "exchange_failed" };
    }
  }

  /** Runs as the token flight. The bootstrap value in place was tried before
   * the exchange, so it never overrides this sign-in; a new value does. */
  private async adoptSignIn(issued: IssuedTokens): Promise<string> {
    const replaced = this.kvGet("tokens") !== null;
    await this.storeTokens(issued, null);
    this.kvDelete("auth_state");
    this.vehicleCache = null;
    this.siteCache = null;
    this.audit({
      source: "system",
      action: "browser_sign_in",
      vehicleId: null,
      outcome: "ok",
      detail: replaced ? "replaced stored tokens" : "initial sign-in",
    });
    return issued.accessToken;
  }
}

/** Scope names only: Tesla's scope string, never anything else it sent. */
function sanitizeScope(scope: string): string {
  return scope
    .split(/\s+/)
    .filter((name) => /^[A-Za-z0-9_.:-]{1,64}$/.test(name))
    .slice(0, 32)
    .join(" ");
}

function forbidden(scopes: ScopeRequirement | undefined): OwnerFailure {
  return {
    code: "forbidden",
    message: scopes
      ? `Tesla refused this request. The app's sign-in needs the ${describeScopes(scopes)} scope; ` +
        "sign in again with it, or check that this account may use this vehicle or product."
      : "Tesla refused this request for this account.",
  };
}

/** The car's own reason ("is_charging", "already_set"), when short and
 * printable. */
function sanitizeCarReason(value: unknown): string {
  return typeof value === "string" && /^[A-Za-z0-9 _.,:'()/-]{1,80}$/.test(value) ? value : "unspecified";
}

function signedFailure(
  code: VcpErrorCode,
  stage: string,
  carReason: string | undefined,
  scopes: ScopeRequirement,
): OwnerFailure {
  // The car answered, but stayed busy (WAIT/BUSY) through every retry; it
  // reported that it did not run the command.
  if (code === "vehicle_unavailable" && stage.endsWith("_exhausted")) {
    return {
      code: "tesla_unavailable",
      reason: code,
      message: "The car stayed busy and did not run the command. Try again shortly.",
    };
  }
  switch (code) {
    case "unauthorized":
      return { code: "reauth_required", reason: code, message: REAUTH_MESSAGE };
    case "forbidden":
      return { ...forbidden(scopes), reason: code };
    case "rate_limited":
      return {
        code: "rate_limited",
        reason: code,
        message: "Tesla is rate limiting commands. Try again in a few minutes.",
      };
    case "vehicle_unavailable":
      return {
        code: "vehicle_asleep",
        reason: code,
        message: "The car is asleep or offline. Wake it with tesla_wake, then try again.",
      };
    case "unconfigured":
      return { code: "not_configured", reason: code, message: "Signed commands are not configured on this server." };
    case "invalid_request":
      return { code: "invalid_request", reason: code, message: "The command's parameters are not valid." };
    case "pairing_required":
      return {
        code: "command_failed",
        reason: code,
        message: "The car does not recognize this app's key. Pair the virtual key in the Tesla app, then try again.",
      };
    case "remote_access_required":
      return {
        code: "command_failed",
        reason: code,
        message: "Mobile access is turned off in the car. Turn it on, then try again.",
      };
    case "command_rejected":
      return {
        code: "command_failed",
        reason: code,
        ...(carReason ? { carReason } : {}),
        message: carReason ? `The car refused the command (${carReason}).` : "The car refused the command.",
      };
    case "status_unknown":
      return {
        code: "command_failed",
        reason: code,
        message: "Tesla did not confirm the command ran. Check the car's status before trying again.",
      };
    default:
      return {
        code: "tesla_unavailable",
        reason: code,
        message: "Tesla's service did not respond as expected. Try again shortly.",
      };
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
