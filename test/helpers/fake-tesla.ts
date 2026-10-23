// A fake Tesla: OAuth token endpoint, Fleet REST endpoints, and a simulated
// vehicle that runs the real VCP handshake with WebCrypto ECDH and verifies
// every signed command's HMAC, counter, and expiry before acting on it.

import { vi } from "vitest";
import { asArrayBuffer, bytesFromBase64, bytesToBase64, concatBytes, constantTimeEqual } from "../../src/bytes";
import { deriveSessionInfoKey, deriveSigningKey, hmacSha256 } from "../../src/tesla/vcp/crypto";
import {
  bytesField,
  DOMAIN_VEHICLE_SECURITY,
  encodeCommandMetadata,
  encodeFixed32Field,
  encodeLengthDelimited,
  encodeSessionInfoMetadata,
  encodeVarintField,
  numberField,
  parseFields,
} from "../../src/tesla/vcp/protocol";

export const FLEET = "https://fleet-api.tesla.test";
export const TOKEN_URL = "https://fleet-auth.tesla.test/oauth2/v3/token";

const VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789";

export function randomVin(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(17));
  return Array.from(bytes, (byte) => VIN_CHARS[byte % VIN_CHARS.length]).join("");
}

export function randomVehicleId(): string {
  return String(1_000_000_000_000 + Math.floor(Math.random() * 8_000_000_000_000));
}

export function uniqueName(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

/** What the car does with the next signed (non-handshake) command. */
export type CarBehavior =
  | { kind: "ok" }
  | { kind: "http"; status: number }
  | { kind: "vcsec_error"; information: number }
  | { kind: "fault"; fault: number }
  | { kind: "wait" };

export class FakeCar {
  readonly epoch = crypto.getRandomValues(new Uint8Array(16));
  counter = 5;
  clockTime = 1_000;
  locked = false;
  handshakes = 0;
  commands = 0;
  /** Behaviors consumed one per signed command; empty means "ok". */
  behaviors: CarBehavior[] = [];
  /** Corrupt the SessionInfo HMAC tag (simulates a forged handshake). */
  forgeSessionTag = false;
  /** Answer handshakes with this message fault (e.g. 3 = unknown key). */
  handshakeFault = 0;
  private keyPair: CryptoKeyPair | null = null;
  private publicKey: Uint8Array | null = null;
  private sessionKey: Uint8Array | null = null;

  constructor(readonly vin: string) {}

  private async keys(): Promise<{ pair: CryptoKeyPair; publicKey: Uint8Array }> {
    if (!this.keyPair || !this.publicKey) {
      this.keyPair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
        "deriveBits",
      ])) as CryptoKeyPair;
      this.publicKey = new Uint8Array((await crypto.subtle.exportKey("raw", this.keyPair.publicKey)) as ArrayBuffer);
    }
    return { pair: this.keyPair, publicKey: this.publicKey };
  }

  /** Handle one routable message; returns the response routable message. */
  async handle(message: Uint8Array): Promise<Uint8Array | { status: number }> {
    const fields = parseFields(message);
    const uuid = bytesField(fields, 51);
    const to = bytesField(fields, 6);
    if (!uuid || !to || numberField(parseFields(to), 1) !== DOMAIN_VEHICLE_SECURITY) {
      throw new Error("fake car: bad envelope");
    }
    const sessionRequest = bytesField(fields, 14);
    if (sessionRequest) return this.handshake(uuid, bytesField(parseFields(sessionRequest), 1));
    return this.command(fields, uuid);
  }

  private async handshake(uuid: Uint8Array, clientPublic: Uint8Array | null): Promise<Uint8Array> {
    this.handshakes++;
    if (!clientPublic) throw new Error("fake car: missing client key");
    if (this.handshakeFault) {
      return concatBytes(
        encodeLengthDelimited(12, encodeVarintField(2, this.handshakeFault)),
        encodeLengthDelimited(50, uuid),
      );
    }
    const { pair, publicKey } = await this.keys();
    const peer = await crypto.subtle.importKey(
      "raw",
      asArrayBuffer(clientPublic),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: "ECDH", public: peer } as unknown as SubtleCryptoDeriveKeyAlgorithm,
      pair.privateKey,
      256,
    );
    this.sessionKey = new Uint8Array(await crypto.subtle.digest("SHA-1", shared)).slice(0, 16);
    const sessionInfo = concatBytes(
      encodeVarintField(1, this.counter),
      encodeLengthDelimited(2, publicKey),
      encodeLengthDelimited(3, this.epoch),
      encodeFixed32Field(4, this.clockTime),
    );
    const tag = await hmacSha256(
      await deriveSessionInfoKey(this.sessionKey),
      encodeSessionInfoMetadata(this.vin, uuid),
      new Uint8Array([0xff]),
      sessionInfo,
    );
    if (this.forgeSessionTag) tag[0] = (tag[0] ?? 0) ^ 0xff;
    return concatBytes(
      encodeLengthDelimited(7, encodeVarintField(1, DOMAIN_VEHICLE_SECURITY)),
      encodeLengthDelimited(13, encodeLengthDelimited(6, encodeLengthDelimited(1, tag))),
      encodeLengthDelimited(15, sessionInfo),
      encodeLengthDelimited(50, uuid),
    );
  }

  private async command(
    fields: ReturnType<typeof parseFields>,
    uuid: Uint8Array,
  ): Promise<Uint8Array | { status: number }> {
    const behavior = this.behaviors.shift() ?? { kind: "ok" };
    if (behavior.kind === "http") return { status: behavior.status };
    const reply = (...parts: Uint8Array[]) => concatBytes(...parts, encodeLengthDelimited(50, uuid));
    if (behavior.kind === "fault") {
      return reply(encodeLengthDelimited(12, encodeVarintField(2, behavior.fault)));
    }
    const payload = bytesField(fields, 10);
    const signature = bytesField(fields, 13);
    const hmacData = signature ? bytesField(parseFields(signature), 8) : null;
    if (!payload || !hmacData || !this.sessionKey) {
      // Unknown session: the car reports an invalid signature.
      return reply(encodeLengthDelimited(12, encodeVarintField(2, 5)));
    }
    const hmacFields = parseFields(hmacData);
    const epoch = bytesField(hmacFields, 1);
    const counter = numberField(hmacFields, 2) ?? 0;
    const expiresAt = numberField(hmacFields, 3) ?? 0;
    const tag = bytesField(hmacFields, 4);
    const expected = await hmacSha256(
      await deriveSigningKey(this.sessionKey),
      encodeCommandMetadata({
        vin: this.vin,
        epoch: epoch ?? new Uint8Array(16),
        expiresAt,
        counter,
        domain: DOMAIN_VEHICLE_SECURITY,
        flags: numberField(fields, 52) ?? 0,
      }),
      new Uint8Array([0xff]),
      payload,
    );
    if (
      !epoch ||
      !constantTimeEqual(epoch, this.epoch) ||
      !tag ||
      !constantTimeEqual(tag, expected) ||
      expiresAt < this.clockTime ||
      expiresAt > this.clockTime + 60
    ) {
      return reply(encodeLengthDelimited(12, encodeVarintField(2, 5)));
    }
    if (counter <= this.counter) return reply(encodeLengthDelimited(12, encodeVarintField(2, 6)));
    this.counter = counter;
    this.commands++;
    if (behavior.kind === "wait") {
      return reply(encodeLengthDelimited(10, encodeLengthDelimited(4, encodeVarintField(1, 1))));
    }
    if (behavior.kind === "vcsec_error") {
      const status = concatBytes(
        encodeVarintField(1, 2),
        encodeLengthDelimited(2, encodeVarintField(2, behavior.information)),
      );
      return reply(encodeLengthDelimited(10, encodeLengthDelimited(4, status)));
    }
    // UnsignedMessage { RKEAction = LOCK } is exactly 0x10 0x01.
    if (payload.byteLength === 2 && payload[0] === 0x10 && payload[1] === 0x01) this.locked = true;
    // FromVCSECMessage { commandStatus { operationStatus OK } } (OK is the
    // proto3 default, so the CommandStatus is empty).
    return reply(encodeLengthDelimited(10, encodeLengthDelimited(4, new Uint8Array())));
  }
}

type Responder = (form: URLSearchParams) => Response | Promise<Response>;

export class FakeTesla {
  readonly vehicleId = randomVehicleId();
  readonly car: FakeCar;
  state: "online" | "asleep" | "offline" = "online";
  /** After wake_up, the car reports "online" once this many polls pass.
   * Infinity keeps it asleep forever. */
  pollsUntilOnline = 1;
  private pollsSinceWake: number | null = null;
  tokenRequests: URLSearchParams[] = [];
  requests: { method: string; path: string; authorization: string | null }[] = [];
  issuedAccessTokens: string[] = [];
  issuedRefreshTokens: string[] = [];
  /** Fleet REST responses consumed before normal handling (e.g. a 401). */
  fleetOverrides: { path: RegExp; status: number }[] = [];
  tokenResponder: Responder;

  constructor(vin = randomVin()) {
    this.car = new FakeCar(vin);
    this.tokenResponder = () => {
      const access = `access-${crypto.randomUUID()}`;
      const refresh = `refresh-${crypto.randomUUID()}`;
      this.issuedAccessTokens.push(access);
      this.issuedRefreshTokens.push(refresh);
      return Response.json({ access_token: access, refresh_token: refresh, expires_in: 28_800, token_type: "Bearer" });
    };
  }

  get vin(): string {
    return this.car.vin;
  }

  /** Requests other than the token endpoint (i.e. anything sent to Fleet). */
  get fleetRequests() {
    return this.requests.filter((request) => !request.path.startsWith("/oauth2"));
  }

  install() {
    return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const request = new Request(input as RequestInfo, init as RequestInit);
      return this.handle(request);
    });
  }

  private vehicleJson() {
    return {
      id: Number(this.vehicleId),
      id_s: this.vehicleId,
      vin: this.vin,
      display_name: "Test Car",
      state: this.state,
    };
  }

  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    this.requests.push({
      method: request.method,
      path: url.pathname,
      authorization: request.headers.get("Authorization"),
    });
    if (request.url === TOKEN_URL && request.method === "POST") {
      const form = new URLSearchParams(new TextDecoder().decode(await request.arrayBuffer()));
      this.tokenRequests.push(form);
      return this.tokenResponder(form);
    }
    if (url.origin !== FLEET) throw new Error(`unexpected fetch to ${url.origin}`);
    const override = this.fleetOverrides.findIndex((candidate) => candidate.path.test(url.pathname));
    if (override >= 0) {
      const [{ status }] = this.fleetOverrides.splice(override, 1) as [{ path: RegExp; status: number }];
      return Response.json({ error: "override" }, { status });
    }
    const base = `/api/1/vehicles/${this.vehicleId}`;
    if (request.method === "GET" && url.pathname === "/api/1/vehicles") {
      return Response.json({ response: [this.vehicleJson()], count: 1 });
    }
    if (request.method === "GET" && url.pathname === base) {
      if (this.pollsSinceWake !== null && this.state !== "online") {
        this.pollsSinceWake++;
        if (this.pollsSinceWake >= this.pollsUntilOnline) this.state = "online";
      }
      return Response.json({ response: this.vehicleJson() });
    }
    if (request.method === "GET" && url.pathname === `${base}/vehicle_data`) {
      if (this.state !== "online") return Response.json({ error: "vehicle unavailable" }, { status: 408 });
      return Response.json({
        response: {
          ...this.vehicleJson(),
          charge_state: {
            battery_level: 76,
            battery_range: 231.4,
            charging_state: "Disconnected",
            charge_limit_soc: 80,
          },
          climate_state: { inside_temp: 21.5, outside_temp: 12, is_climate_on: false },
          vehicle_state: {
            locked: this.car.locked,
            df: 0,
            pf: 0,
            dr: 0,
            pr: 0,
            ft: 0,
            rt: 0,
            fd_window: 0,
            fp_window: 0,
            rd_window: 0,
            rp_window: 0,
            sentry_mode: true,
            odometer: 12345.6,
          },
          drive_state: { latitude: 1, longitude: 2 },
        },
      });
    }
    if (request.method === "POST" && url.pathname === `${base}/wake_up`) {
      this.pollsSinceWake = 0;
      if (this.pollsUntilOnline === 0) this.state = "online";
      return Response.json({ response: this.vehicleJson() });
    }
    if (request.method === "POST" && url.pathname === `/api/1/vehicles/${this.vin}/signed_command`) {
      if (this.state !== "online") return Response.json({ error: "vehicle unavailable" }, { status: 408 });
      const body = (await request.json()) as { routable_message: string };
      const result = await this.car.handle(bytesFromBase64(body.routable_message));
      if (!(result instanceof Uint8Array)) return Response.json({ error: "upstream" }, { status: result.status });
      return Response.json({ response: bytesToBase64(result) });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }
}
