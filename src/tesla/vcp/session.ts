// Per-VIN Tesla Vehicle Command Protocol sessions, keyed by (VIN, domain).
//
// A Durable Object gives every VIN one serialized command stream, so the
// anti-replay counter cannot race across Worker isolates. Session keys and key
// material are memory-only: this class never reads or writes DO storage.

import { DurableObject } from "cloudflare:workers";
import { bytesFromBase64, bytesToBase64, constantTimeEqual, random16 } from "../../bytes";
import type { Env } from "../../env";
import { defaultFetch, type FetchFn, fetchUpstream, readBoundedText } from "../http";
import {
  decryptAesGcmResponse,
  deriveSessionInfoKey,
  deriveSessionKey,
  deriveSigningKey,
  hmacSha256,
  importVcpPrivateKey,
  sha256Digest,
  type VcpKeyMaterial,
} from "./crypto";
import {
  buildSessionInfoRequest,
  buildSignedCommand,
  DOMAIN_VEHICLE_SECURITY,
  encodeCommandMetadata,
  encodeResponseMetadata,
  encodeSessionInfoMetadata,
  isSignedCommandName,
  MESSAGE_FAULT,
  OPERATION_STATUS,
  parseRoutableResponse,
  parseSessionInfo,
  parseVcsecResult,
  type RoutableResponse,
  responseRequestHash,
  SIGNED_COMMANDS,
  type SignedCommandName,
  VCSEC_INFORMATION,
  type VcpDomain,
  validVIN,
} from "./protocol";

const SESSION_TTL_MS = 5 * 60_000;
const COMMAND_TTL_SECONDS = 15;
const UPSTREAM_TIMEOUT_MS = 30_000;
const MAX_UPSTREAM_BODY_BYTES = 65_536;
const MAX_HANDSHAKE_ATTEMPTS = 3;
// WAIT and BUSY/TIMEOUT/INTERNAL faults mean "not executed, try again". Cap
// attempts so one request cannot loop while a vehicle subsystem stays busy.
const MAX_COMMAND_ATTEMPTS = 3;
const COMMAND_RETRY_INTERVAL_MS = 1_000;
const USER_AGENT = "tesla-mcp/0.1 (+https://github.com/Oceanswave/tesla-mcp)";

const KEY_FAULTS = new Set<number>([MESSAGE_FAULT.UNKNOWN_KEY_ID, MESSAGE_FAULT.INACTIVE_KEY]);
const STALE_SESSION_FAULTS = new Set<number>([
  MESSAGE_FAULT.INVALID_SIGNATURE,
  MESSAGE_FAULT.INVALID_TOKEN_OR_COUNTER,
  MESSAGE_FAULT.INCORRECT_EPOCH,
  MESSAGE_FAULT.TIME_EXPIRED,
  MESSAGE_FAULT.TIME_TO_LIVE_TOO_LONG,
]);
const TRANSIENT_FAULTS = new Set<number>([MESSAGE_FAULT.BUSY, MESSAGE_FAULT.TIMEOUT, MESSAGE_FAULT.INTERNAL]);
const DEFINITIVE_REJECTIONS = new Set<number>([
  MESSAGE_FAULT.INVALID_COMMAND,
  MESSAGE_FAULT.DECODING,
  MESSAGE_FAULT.BAD_PARAMETER,
]);
const PRIVILEGE_FAULTS = new Set<number>([
  MESSAGE_FAULT.INSUFFICIENT_PRIVILEGES,
  MESSAGE_FAULT.COMMAND_REQUIRES_ACCOUNT_CREDENTIALS,
]);
const REMOTE_ACCESS_FAULTS = new Set<number>([
  MESSAGE_FAULT.REMOTE_ACCESS_DISABLED,
  MESSAGE_FAULT.REMOTE_SERVICE_ACCESS_DISABLED,
]);
const VCSEC_STALE_INFORMATION = new Set<number>([
  VCSEC_INFORMATION.FAULT_INVALID_TOKEN,
  VCSEC_INFORMATION.FAULT_TOKEN_AND_COUNTER_INVALID,
  VCSEC_INFORMATION.FAULT_INCORRECT_EPOCH,
  VCSEC_INFORMATION.FAULT_TIME_EXPIRED,
]);

export type VcpErrorCode =
  | "unconfigured"
  | "invalid_request"
  | "pairing_required"
  | "unauthorized"
  | "forbidden"
  | "remote_access_required"
  | "vehicle_unavailable"
  | "rate_limited"
  | "session_unavailable"
  | "command_rejected"
  | "status_unknown"
  | "service_unavailable";

export class VcpError extends Error {
  constructor(
    readonly code: VcpErrorCode,
    readonly retryable = false,
    /** Sanitized protocol stage for logs and audit. Never contains a VIN,
     * token, key, or payload. */
    readonly stage?: string,
  ) {
    super(`tesla_vcp_${code}`);
    this.name = "VcpError";
  }
}

export type SignedCommandRequest = {
  vin: string;
  accessToken: string;
  command: SignedCommandName;
};

export type SignedCommandResult =
  | { ok: true }
  | { ok: false; error: { code: VcpErrorCode; retryable: boolean; stage: string } };

type Session = {
  responseEncryptionKey: Uint8Array;
  signingKey: Uint8Array;
  epoch: Uint8Array;
  counter: number;
  timeZeroMs: number;
  createdAtMs: number;
};

export type VcpCoreOptions = {
  fleetBaseUrl: string;
  privateKeyPkcs8Base64: string;
  publicKeyPem: string;
  fetchFn?: FetchFn;
  sleep?: (milliseconds: number) => Promise<void>;
  now?: () => number;
  randomBytes16?: () => Uint8Array;
};

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function upstreamError(status: number): VcpError {
  const stage = `upstream_http_${status}`;
  if (status === 401) return new VcpError("unauthorized", false, stage);
  if (status === 403) return new VcpError("forbidden", false, stage);
  // Fleet answers 408 when the vehicle (or the addressed subsystem) did not
  // respond: asleep, offline, or still booting after a wake.
  if (status === 408) return new VcpError("vehicle_unavailable", true, stage);
  if (status === 422) return new VcpError("pairing_required", false, stage);
  if (status === 429) return new VcpError("rate_limited", true, stage);
  return new VcpError("service_unavailable", status >= 500, stage);
}

export function validFleetBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new VcpError("unconfigured", false, "fleet_base_url");
  }
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash) {
    throw new VcpError("unconfigured", false, "fleet_base_url");
  }
  return url.origin;
}

/** Testable protocol core. A TeslaVcpSession DO owns exactly one instance. */
export class TeslaVcpCore {
  private readonly fleetBaseUrl: string;
  private readonly fetchFn: FetchFn;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly now: () => number;
  private readonly randomBytes16: () => Uint8Array;
  private readonly privateKeyPkcs8Base64: string;
  private readonly publicKeyPem: string;
  private keyMaterialPromise: Promise<VcpKeyMaterial> | null = null;
  private readonly sessions = new Map<VcpDomain, Session>();
  private vin: string | null = null;
  private readonly routingAddress: Uint8Array;

  constructor(options: VcpCoreOptions) {
    this.fleetBaseUrl = validFleetBaseUrl(options.fleetBaseUrl);
    this.fetchFn = options.fetchFn ?? defaultFetch;
    this.sleep = options.sleep ?? delay;
    this.now = options.now ?? Date.now;
    this.randomBytes16 = options.randomBytes16 ?? random16;
    this.privateKeyPkcs8Base64 = options.privateKeyPkcs8Base64;
    this.publicKeyPem = options.publicKeyPem;
    this.routingAddress = this.checkedRandom16();
  }

  /** Import the key and prove it matches the published public key. */
  async ready(): Promise<void> {
    await this.keyMaterial();
  }

  async command(request: SignedCommandRequest): Promise<void> {
    if (
      !validVIN(request.vin) ||
      (this.vin !== null && this.vin !== request.vin) ||
      !isSignedCommandName(request.command) ||
      typeof request.accessToken !== "string" ||
      request.accessToken.length < 16 ||
      request.accessToken.length > 8_192 ||
      /[\s\u0000-\u001f\u007f]/.test(request.accessToken)
    ) {
      throw new VcpError("invalid_request", false, "request_validation");
    }
    this.vin = request.vin;
    await this.sendSigned(request.accessToken, request.command, false, 1);
  }

  private checkedRandom16(): Uint8Array {
    const bytes = this.randomBytes16();
    if (bytes.byteLength !== 16) throw new VcpError("unconfigured", false, "random");
    return bytes.slice();
  }

  private keyMaterial(): Promise<VcpKeyMaterial> {
    if (!this.keyMaterialPromise) {
      this.keyMaterialPromise = importVcpPrivateKey(this.privateKeyPkcs8Base64, this.publicKeyPem).catch(() => {
        this.keyMaterialPromise = null;
        throw new VcpError("unconfigured", false, "key_import");
      });
    }
    return this.keyMaterialPromise;
  }

  private async sendSigned(
    accessToken: string,
    command: SignedCommandName,
    sessionRetryUsed: boolean,
    attempt: number,
  ): Promise<void> {
    const vin = this.vin;
    if (!vin) throw new VcpError("invalid_request", false, "missing_vin");
    const spec = SIGNED_COMMANDS[command];
    const domain = spec.domain;
    const session = await this.getSession(vin, accessToken, domain);
    if (session.counter >= 0xffff_ffff) {
      this.sessions.delete(domain);
      if (sessionRetryUsed) throw new VcpError("session_unavailable", false, "counter_exhausted");
      return this.sendSigned(accessToken, command, true, attempt);
    }

    session.counter += 1;
    const expiresAt = Math.floor((this.now() + COMMAND_TTL_SECONDS * 1_000 - session.timeZeroMs) / 1_000);
    if (expiresAt < 0 || expiresAt > 0xffff_ffff) {
      this.sessions.delete(domain);
      throw new VcpError("session_unavailable", false, "expiry_range");
    }
    const payload = spec.payload();
    const metadata = encodeCommandMetadata({
      vin,
      epoch: session.epoch,
      expiresAt,
      counter: session.counter,
      domain,
      flags: spec.flags,
    });
    const tag = await hmacSha256(session.signingKey, metadata, new Uint8Array([0xff]), payload);
    const uuid = this.checkedRandom16();
    const key = await this.keyMaterial();
    const envelope = buildSignedCommand({
      publicKey: key.publicKey,
      routingAddress: this.routingAddress,
      uuid,
      payload,
      epoch: session.epoch,
      counter: session.counter,
      expiresAt,
      tag,
      domain,
      flags: spec.flags,
    });

    let encodedResponse: Uint8Array;
    try {
      encodedResponse = await this.postSignedCommand(vin, accessToken, envelope);
    } catch (error) {
      // These HTTP answers prove Fleet did not forward the command.
      if (
        error instanceof VcpError &&
        (error.code === "unauthorized" ||
          error.code === "forbidden" ||
          error.code === "pairing_required" ||
          error.code === "rate_limited" ||
          error.code === "vehicle_unavailable")
      ) {
        throw error;
      }
      // Network failures, timeouts, 5xx, and malformed bodies can occur after
      // Tesla accepted the POST. The delivery outcome is unknown.
      throw new VcpError(
        "status_unknown",
        false,
        error instanceof VcpError && error.stage ? error.stage : "command_transport",
      );
    }

    let response: ReturnType<typeof parseRoutableResponse>;
    try {
      response = parseRoutableResponse(encodedResponse);
    } catch {
      throw new VcpError("status_unknown", false, "command_response_decode");
    }
    if (!this.correlated(response, uuid, domain)) {
      throw new VcpError("status_unknown", false, "command_response_correlation");
    }

    let responsePayload = response.payload ?? new Uint8Array();
    if (response.hasResponseEncryptionData) {
      // Authenticate every field Tesla binds into AES-GCM before trusting
      // either the application payload or its protocol fault.
      try {
        if (
          !response.responseNonce ||
          response.responseCounter === null ||
          !response.responseTag ||
          response.fromDomain !== domain
        ) {
          throw new Error("incomplete encrypted response");
        }
        const additionalData = await sha256Digest(
          encodeResponseMetadata({
            vin,
            domain: response.fromDomain,
            counter: response.responseCounter,
            flags: response.flags,
            requestHash: responseRequestHash(domain, tag),
            fault: response.fault,
          }),
          new Uint8Array([0xff]),
        );
        responsePayload = await decryptAesGcmResponse(
          session.responseEncryptionKey,
          response.responseNonce,
          responsePayload,
          response.responseTag,
          additionalData,
        );
      } catch {
        throw new VcpError("status_unknown", false, "command_response_authentication");
      }
    }

    if (response.fault === MESSAGE_FAULT.NONE) {
      if (response.operationStatus === OPERATION_STATUS.WAIT) {
        return this.retryUnexecuted(accessToken, command, sessionRetryUsed, attempt, "operation_wait");
      }
      if (response.operationStatus !== OPERATION_STATUS.OK) {
        throw new VcpError("command_rejected", false, `operation_status_${response.operationStatus}`);
      }
      // Only VCSEC commands exist today; an infotainment command would decode
      // a CarServer.Response here instead.
      const result = parseVcsecResult(responsePayload);
      if (result.status === "ok") {
        // A plaintext completion without a request UUID is matched only by a
        // routing address this client reuses, so it could be a stale reply.
        // An encrypted one is bound to this request by its AES-GCM request
        // hash. Otherwise the caller checks the car before calling it done.
        if (!response.requestUuid?.byteLength && !response.hasResponseEncryptionData) {
          throw new VcpError("status_unknown", false, "vcsec_uncorrelated_completion");
        }
        return;
      }
      if (result.status === "acknowledged") {
        // Received but not confirmed as executed; the caller checks the car.
        throw new VcpError("status_unknown", false, "vcsec_acknowledged");
      }
      if (result.status === "wait") {
        return this.retryUnexecuted(accessToken, command, sessionRetryUsed, attempt, "vcsec_wait");
      }
      if (result.status === "unknown") {
        throw new VcpError("status_unknown", false, "vcsec_response_decode");
      }
      if (result.information === VCSEC_INFORMATION.FAULT_NOT_ON_WHITELIST) {
        this.sessions.delete(domain);
        throw new VcpError("pairing_required", false, "vcsec_not_on_whitelist");
      }
      if (VCSEC_STALE_INFORMATION.has(result.information)) {
        this.sessions.delete(domain);
        if (sessionRetryUsed) {
          throw new VcpError("session_unavailable", false, `vcsec_information_${result.information}`);
        }
        return this.sendSigned(accessToken, command, true, attempt);
      }
      throw new VcpError(
        "command_rejected",
        false,
        result.genericError ? `vcsec_generic_error_${result.genericError}` : `vcsec_information_${result.information}`,
      );
    }
    const stage = `fault_${response.fault}`;
    if (response.fault === MESSAGE_FAULT.RESPONSE_MTU_EXCEEDED) {
      // "Request received, response too large": the command may have run.
      throw new VcpError("status_unknown", false, stage);
    }
    if (KEY_FAULTS.has(response.fault)) {
      this.sessions.delete(domain);
      throw new VcpError("pairing_required", false, stage);
    }
    if (STALE_SESSION_FAULTS.has(response.fault)) {
      this.sessions.delete(domain);
      if (sessionRetryUsed) throw new VcpError("session_unavailable", false, stage);
      return this.sendSigned(accessToken, command, true, attempt);
    }
    if (DEFINITIVE_REJECTIONS.has(response.fault)) {
      throw new VcpError("command_rejected", false, stage);
    }
    if (PRIVILEGE_FAULTS.has(response.fault)) throw new VcpError("forbidden", false, stage);
    if (REMOTE_ACCESS_FAULTS.has(response.fault)) {
      throw new VcpError("remote_access_required", false, stage);
    }
    if (TRANSIENT_FAULTS.has(response.fault)) {
      return this.retryUnexecuted(accessToken, command, sessionRetryUsed, attempt, stage);
    }
    throw new VcpError("session_unavailable", false, stage);
  }

  /** WAIT and BUSY/TIMEOUT/INTERNAL are temporary and explicitly "not
   * executed", so a fresh UUID/counter is safe. Nothing reaches this helper
   * for transport ambiguity, decode/authentication failures, or fault 25. */
  private async retryUnexecuted(
    accessToken: string,
    command: SignedCommandName,
    sessionRetryUsed: boolean,
    attempt: number,
    stage: string,
  ): Promise<void> {
    if (attempt >= MAX_COMMAND_ATTEMPTS) {
      throw new VcpError("vehicle_unavailable", true, `${stage}_exhausted`);
    }
    await this.sleep(COMMAND_RETRY_INTERVAL_MS);
    return this.sendSigned(accessToken, command, sessionRetryUsed, attempt + 1);
  }

  /** Is this reply for the request with `uuid`? A request UUID, when present,
   * must match. VCSEC may omit it: Tesla's dispatcher (internal/dispatcher,
   * process) matches VCSEC replies by routing address alone, so a VCSEC reply
   * without one must come from VCSEC and be addressed to this client's
   * routing address. Callers never treat such a plaintext reply alone as
   * proof that a command ran. */
  private correlated(response: RoutableResponse, uuid: Uint8Array, domain: VcpDomain): boolean {
    if (response.requestUuid?.byteLength) return constantTimeEqual(response.requestUuid, uuid);
    return (
      domain === DOMAIN_VEHICLE_SECURITY &&
      response.fromDomain === DOMAIN_VEHICLE_SECURITY &&
      response.toRoutingAddress !== null &&
      constantTimeEqual(response.toRoutingAddress, this.routingAddress)
    );
  }

  private async getSession(vin: string, accessToken: string, domain: VcpDomain): Promise<Session> {
    const cached = this.sessions.get(domain);
    if (cached && this.now() - cached.createdAtMs <= SESSION_TTL_MS) return cached;
    this.sessions.delete(domain);
    return this.handshake(vin, accessToken, domain);
  }

  private async handshake(vin: string, accessToken: string, domain: VcpDomain): Promise<Session> {
    const key = await this.keyMaterial();
    for (let attempt = 1; ; attempt++) {
      const uuid = this.checkedRandom16();
      const request = buildSessionInfoRequest(key.publicKey, this.routingAddress, uuid, domain);
      try {
        const response = parseRoutableResponse(await this.postSignedCommand(vin, accessToken, request));
        if (!this.correlated(response, uuid, domain)) {
          throw new VcpError("session_unavailable", true, "handshake_correlation");
        }
        if (KEY_FAULTS.has(response.fault)) {
          throw new VcpError("pairing_required", false, `handshake_fault_${response.fault}`);
        }
        if (response.fault !== MESSAGE_FAULT.NONE) {
          throw new VcpError(
            "session_unavailable",
            TRANSIENT_FAULTS.has(response.fault),
            `handshake_fault_${response.fault}`,
          );
        }
        if (response.operationStatus !== OPERATION_STATUS.OK) {
          throw new VcpError(
            "session_unavailable",
            response.operationStatus === OPERATION_STATUS.WAIT,
            `handshake_operation_${response.operationStatus}`,
          );
        }
        if (!response.sessionInfo || response.sessionInfoTag?.byteLength !== 32) {
          throw new VcpError("session_unavailable", false, "handshake_missing_session_info");
        }
        const info = parseSessionInfo(response.sessionInfo);
        if (info.status === 1) {
          throw new VcpError("pairing_required", false, "handshake_key_not_on_whitelist");
        }
        if (info.status !== 0) {
          throw new VcpError("session_unavailable", false, `handshake_status_${info.status}`);
        }
        const sessionKey = await deriveSessionKey(key.privateKey, info.publicKey);
        const expectedTag = await hmacSha256(
          await deriveSessionInfoKey(sessionKey),
          encodeSessionInfoMetadata(vin, uuid),
          new Uint8Array([0xff]),
          response.sessionInfo,
        );
        // A missing or wrong tag is a hard failure: never accept an
        // unauthenticated session (its counter/epoch/clock could be forged).
        if (!constantTimeEqual(expectedTag, response.sessionInfoTag)) {
          throw new VcpError("session_unavailable", false, "handshake_tag_mismatch");
        }
        const now = this.now();
        const session: Session = {
          responseEncryptionKey: sessionKey.slice(),
          signingKey: await deriveSigningKey(sessionKey),
          epoch: info.epoch.slice(),
          counter: info.counter,
          timeZeroMs: now - info.clockTime * 1_000,
          createdAtMs: now,
        };
        this.sessions.set(domain, session);
        return session;
      } catch (error) {
        const typed =
          error instanceof VcpError ? error : new VcpError("session_unavailable", false, "handshake_decode");
        // A waking VCSEC answers 408 or BUSY for a few seconds; retry those
        // briefly, as the Python plugin does. Everything else is final.
        if (!typed.retryable || attempt >= MAX_HANDSHAKE_ATTEMPTS) throw typed;
        await this.sleep(attempt * 1_000);
      }
    }
  }

  private async postSignedCommand(vin: string, accessToken: string, envelope: Uint8Array): Promise<Uint8Array> {
    let response: Response;
    try {
      response = await fetchUpstream(
        this.fetchFn,
        `${this.fleetBaseUrl}/api/1/vehicles/${encodeURIComponent(vin)}/signed_command`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
            Accept: "application/json",
            "User-Agent": USER_AGENT,
          },
          body: JSON.stringify({ routable_message: bytesToBase64(envelope) }),
        },
        UPSTREAM_TIMEOUT_MS,
      );
    } catch {
      throw new VcpError("service_unavailable", true, "upstream_transport");
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => {});
      throw upstreamError(response.status);
    }
    let text: string;
    try {
      text = await readBoundedText(response, MAX_UPSTREAM_BODY_BYTES);
    } catch {
      throw new VcpError("service_unavailable", true, "upstream_response_too_large");
    }
    try {
      const parsed = JSON.parse(text) as { response?: unknown };
      if (typeof parsed.response !== "string") throw new Error("shape");
      return bytesFromBase64(parsed.response);
    } catch {
      throw new VcpError("service_unavailable", true, "upstream_response_shape");
    }
  }
}

export function toSignedCommandResult(error: unknown): SignedCommandResult {
  const typed = error instanceof VcpError ? error : new VcpError("service_unavailable", false, "internal");
  return {
    ok: false,
    error: { code: typed.code, retryable: typed.retryable, stage: typed.stage ?? "unspecified" },
  };
}

/** One instance per VIN (idFromName(vin)). Commands are serialized so the
 * anti-replay counter is never used concurrently. */
export class TeslaVcpSession extends DurableObject<Env> {
  /** Injection point for tests; production waits for real. */
  sleep: (milliseconds: number) => Promise<void> = delay;
  private core: TeslaVcpCore | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  async signedCommand(request: SignedCommandRequest): Promise<SignedCommandResult> {
    const task = this.queue.then(() => this.run(request));
    this.queue = task.catch(() => undefined);
    return task;
  }

  private async run(request: SignedCommandRequest): Promise<SignedCommandResult> {
    try {
      if (!this.core) {
        const privateKey = this.env.TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64;
        if (!privateKey) throw new VcpError("unconfigured", false, "missing_private_key");
        this.core = new TeslaVcpCore({
          fleetBaseUrl: this.env.TESLA_FLEET_BASE_URL,
          privateKeyPkcs8Base64: privateKey,
          publicKeyPem: this.env.TESLA_PUBLIC_KEY_PEM,
          sleep: (milliseconds) => this.sleep(milliseconds),
        });
      }
      await this.core.command(request);
      return { ok: true };
    } catch (error) {
      const result = toSignedCommandResult(error);
      if (!result.ok) {
        // The only VCP runtime log: stage and code only, never a VIN, token,
        // key, or payload.
        console.warn(`[tesla-vcp] command_failed code=${result.error.code} stage=${result.error.stage}`);
      }
      return result;
    }
  }
}
