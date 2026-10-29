// A fake Tesla: OAuth token endpoint, Fleet REST endpoints, and a simulated
// vehicle that runs the real VCP handshake with WebCrypto ECDH and verifies
// every signed command's HMAC, counter, and expiry before acting on it.

import { vi } from "vitest";
import {
  asArrayBuffer,
  bytesFromBase64,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  constantTimeEqual,
} from "../../src/bytes";
import { deriveSessionInfoKey, deriveSigningKey, hmacSha256 } from "../../src/tesla/vcp/crypto";
import {
  bytesField,
  DOMAIN_INFOTAINMENT,
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
  | { kind: "wait" }
  /** Lock, then answer with an AES-GCM encrypted FromVCSECMessage. */
  | { kind: "encrypted_ok" }
  /** Lock, but answer only with CommandStatus(OK), an acknowledgement that
   * Tesla's RKE handler does not treat as completion. */
  | { kind: "ack" }
  /** Lock, then answer as Tesla's VCSEC may: without a request UUID, matched
   * by routing address only. */
  | { kind: "ok_no_uuid" }
  /** Answer with no request UUID, addressed to another client. */
  | { kind: "misaddressed" }
  /** Infotainment: an encrypted CarServer.Response with OPERATIONSTATUS_ERROR. */
  | { kind: "carserver_error"; reason: string }
  /** Infotainment: an unencrypted OK reply (a client asking for encryption
   * must refuse it). */
  | { kind: "plaintext_ok" };

type DomainSession = { sessionKey: Uint8Array | null; epoch: Uint8Array; counter: number };

/** Tesla's metadata TLV (tag, length, value). Built independently of the
 * signer's encoder so the fake checks the protocol, not itself. */
function tlv(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([tag, value.byteLength]), value);
}

function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

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
  /** Every accepted signed command, in order: domain and payload hex. */
  received: { domain: number; payload: string }[] = [];
  private keyPair: CryptoKeyPair | null = null;
  private publicKey: Uint8Array | null = null;
  private sessionKey: Uint8Array | null = null;
  /** Infotainment keeps its own session, epoch, and counter, as in a car. */
  private readonly infotainment: DomainSession = {
    sessionKey: null,
    epoch: crypto.getRandomValues(new Uint8Array(16)),
    counter: 40,
  };
  private lastRoutingAddress: Uint8Array = new Uint8Array(16);

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
    const from = bytesField(fields, 7);
    const routingAddress = from ? bytesField(parseFields(from), 2) : null;
    const domain = to ? numberField(parseFields(to), 1) : null;
    if (!uuid || !routingAddress || (domain !== DOMAIN_VEHICLE_SECURITY && domain !== DOMAIN_INFOTAINMENT)) {
      throw new Error("fake car: bad envelope");
    }
    this.lastRoutingAddress = routingAddress;
    const sessionRequest = bytesField(fields, 14);
    if (domain === DOMAIN_INFOTAINMENT) {
      if (sessionRequest) return this.infotainmentHandshake(uuid, bytesField(parseFields(sessionRequest), 1));
      return this.infotainmentCommand(fields, uuid);
    }
    if (sessionRequest) return this.handshake(uuid, bytesField(parseFields(sessionRequest), 1));
    return this.command(fields, uuid);
  }

  private async sharedKey(clientPublic: Uint8Array): Promise<Uint8Array> {
    const { pair } = await this.keys();
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
    return new Uint8Array(await crypto.subtle.digest("SHA-1", shared)).slice(0, 16);
  }

  private async infotainmentHandshake(uuid: Uint8Array, clientPublic: Uint8Array | null): Promise<Uint8Array> {
    this.handshakes++;
    if (!clientPublic) throw new Error("fake car: missing client key");
    if (this.handshakeFault) {
      return concatBytes(
        encodeLengthDelimited(12, encodeVarintField(2, this.handshakeFault)),
        encodeLengthDelimited(50, uuid),
      );
    }
    const { publicKey } = await this.keys();
    const session = this.infotainment;
    session.sessionKey = await this.sharedKey(clientPublic);
    const sessionInfo = concatBytes(
      encodeVarintField(1, session.counter),
      encodeLengthDelimited(2, publicKey),
      encodeLengthDelimited(3, session.epoch),
      encodeFixed32Field(4, this.clockTime),
    );
    const tag = await hmacSha256(
      await deriveSessionInfoKey(session.sessionKey),
      encodeSessionInfoMetadata(this.vin, uuid),
      new Uint8Array([0xff]),
      sessionInfo,
    );
    return concatBytes(
      encodeLengthDelimited(7, encodeVarintField(1, DOMAIN_INFOTAINMENT)),
      encodeLengthDelimited(13, encodeLengthDelimited(6, encodeLengthDelimited(1, tag))),
      encodeLengthDelimited(15, sessionInfo),
      encodeLengthDelimited(50, uuid),
    );
  }

  /** Verify a signed infotainment command against the infotainment session
   * and answer with an AES-GCM encrypted CarServer.Response. */
  private async infotainmentCommand(
    fields: ReturnType<typeof parseFields>,
    uuid: Uint8Array,
  ): Promise<Uint8Array | { status: number }> {
    const behavior = this.behaviors.shift() ?? { kind: "ok" };
    if (behavior.kind === "http") return { status: behavior.status };
    const reply = (...parts: Uint8Array[]) => concatBytes(...parts, encodeLengthDelimited(50, uuid));
    if (behavior.kind === "fault") return reply(encodeLengthDelimited(12, encodeVarintField(2, behavior.fault)));
    const session = this.infotainment;
    const payload = bytesField(fields, 10);
    const signature = bytesField(fields, 13);
    const hmacData = signature ? bytesField(parseFields(signature), 8) : null;
    if (!payload || !hmacData || !session.sessionKey) return reply(encodeLengthDelimited(12, encodeVarintField(2, 5)));
    const hmacFields = parseFields(hmacData);
    const epoch = bytesField(hmacFields, 1);
    const counter = numberField(hmacFields, 2) ?? 0;
    const expiresAt = numberField(hmacFields, 3) ?? 0;
    const tag = bytesField(hmacFields, 4);
    const flags = numberField(fields, 52) ?? 0;
    const expected = await hmacSha256(
      await deriveSigningKey(session.sessionKey),
      encodeCommandMetadata({
        vin: this.vin,
        epoch: epoch ?? new Uint8Array(16),
        expiresAt,
        counter,
        domain: DOMAIN_INFOTAINMENT,
        flags,
      }),
      new Uint8Array([0xff]),
      payload,
    );
    if (
      !epoch ||
      !constantTimeEqual(epoch, session.epoch) ||
      !tag ||
      !constantTimeEqual(tag, expected) ||
      expiresAt < this.clockTime ||
      expiresAt > this.clockTime + 60
    ) {
      return reply(encodeLengthDelimited(12, encodeVarintField(2, 5)));
    }
    if (counter <= session.counter) return reply(encodeLengthDelimited(12, encodeVarintField(2, 6)));
    session.counter = counter;
    this.commands++;
    // ActionStatus { result = OK } (an empty message) or { result = ERROR,
    // result_reason { plain_text } }.
    const status =
      behavior.kind === "carserver_error"
        ? concatBytes(
            encodeVarintField(1, 1),
            encodeLengthDelimited(2, encodeLengthDelimited(1, new TextEncoder().encode(behavior.reason))),
          )
        : new Uint8Array();
    const response = encodeLengthDelimited(1, status);
    if (behavior.kind !== "carserver_error") {
      this.received.push({ domain: DOMAIN_INFOTAINMENT, payload: bytesToHex(payload) });
    }
    if (behavior.kind === "plaintext_ok") {
      return reply(
        encodeLengthDelimited(7, encodeVarintField(1, DOMAIN_INFOTAINMENT)),
        encodeLengthDelimited(10, response),
      );
    }
    return this.encryptedReply(uuid, tag, DOMAIN_INFOTAINMENT, session.sessionKey, response);
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
    const { publicKey } = await this.keys();
    this.sessionKey = await this.sharedKey(clientPublic);
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
    // UnsignedMessage { RKEAction = LOCK } is exactly 0x10 0x01, UNLOCK 0x10 0x00.
    if (payload.byteLength === 2 && payload[0] === 0x10 && payload[1] === 0x01) this.locked = true;
    if (payload.byteLength === 2 && payload[0] === 0x10 && payload[1] === 0x00) this.locked = false;
    this.received.push({ domain: DOMAIN_VEHICLE_SECURITY, payload: bytesToHex(payload) });
    if (behavior.kind === "encrypted_ok") {
      return this.encryptedReply(uuid, tag, DOMAIN_VEHICLE_SECURITY, this.sessionKey, new Uint8Array());
    }
    if (behavior.kind === "ack") {
      // FromVCSECMessage { commandStatus { operationStatus OK } } (OK is the
      // proto3 default, so the CommandStatus is empty).
      return reply(encodeLengthDelimited(10, encodeLengthDelimited(4, new Uint8Array())));
    }
    // Completion: an empty FromVCSECMessage, so no payload at all, addressed
    // to the client's routing address as the vehicle does.
    const toClient = (address: Uint8Array) =>
      concatBytes(
        encodeLengthDelimited(6, encodeLengthDelimited(2, address)),
        encodeLengthDelimited(7, encodeVarintField(1, DOMAIN_VEHICLE_SECURITY)),
      );
    if (behavior.kind === "ok_no_uuid") return toClient(this.lastRoutingAddress);
    if (behavior.kind === "misaddressed") return toClient(crypto.getRandomValues(new Uint8Array(16)));
    return reply(toClient(this.lastRoutingAddress));
  }

  /** Encrypt a reply as the vehicle does: AAD is the SHA-256 of the
   * response metadata, whose request hash is RequestID() from Tesla's
   * internal/authentication/peer.go (0x08 || the HMAC tag, truncated to 16
   * bytes for VCSEC only). */
  private async encryptedReply(
    uuid: Uint8Array,
    requestTag: Uint8Array,
    domain: number,
    sessionKey: Uint8Array,
    plaintext: Uint8Array,
  ): Promise<Uint8Array> {
    const responseCounter = 1;
    const requestHash = domain === DOMAIN_VEHICLE_SECURITY ? requestTag.subarray(0, 16) : requestTag;
    const metadata = concatBytes(
      tlv(0, new Uint8Array([9])),
      tlv(1, new Uint8Array([domain])),
      tlv(2, new TextEncoder().encode(this.vin)),
      tlv(5, u32(responseCounter)),
      tlv(7, u32(0)),
      tlv(8, concatBytes(new Uint8Array([8]), requestHash)),
      tlv(9, u32(0)),
      new Uint8Array([0xff]),
    );
    const additionalData = await crypto.subtle.digest("SHA-256", asArrayBuffer(metadata));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey("raw", asArrayBuffer(sessionKey), "AES-GCM", false, ["encrypt"]);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
        key,
        asArrayBuffer(plaintext),
      ),
    );
    const responseData = concatBytes(
      encodeLengthDelimited(1, nonce),
      encodeVarintField(2, responseCounter),
      encodeLengthDelimited(3, sealed.subarray(sealed.byteLength - 16)),
    );
    return concatBytes(
      encodeLengthDelimited(7, encodeVarintField(1, domain)),
      encodeLengthDelimited(10, sealed.subarray(0, sealed.byteLength - 16)),
      encodeLengthDelimited(13, encodeLengthDelimited(9, responseData)),
      encodeLengthDelimited(50, uuid),
    );
  }
}

type Responder = (form: URLSearchParams) => Response | Promise<Response>;

/** An energy site id above 2^53: JSON.parse would round it. */
export const ENERGY_SITE_ID = "9007199254740993";

export class FakeTesla {
  readonly vehicleId = randomVehicleId();
  readonly car: FakeCar;
  state: "online" | "asleep" | "offline" = "online";
  /** After wake_up, the car reports "online" once this many polls pass.
   * Infinity keeps it asleep forever. */
  pollsUntilOnline = 1;
  private pollsSinceWake: number | null = null;
  tokenRequests: URLSearchParams[] = [];
  requests: {
    method: string;
    path: string;
    search: string;
    body: string;
    authorization: string | null;
  }[] = [];
  /** Canned Fleet REST answers, keyed "METHOD /path" (no query). A function
   * is called per request. */
  rest = new Map<string, () => Response>();
  /** The vehicle REST command answer ({ result, reason }). */
  commandResult: { result: boolean; reason: string } = { result: true, reason: "" };
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
    this.installDefaultRest();
  }

  get vin(): string {
    return this.car.vin;
  }

  /** Answer `method path` with `{ response }` (or a raw JSON text). */
  respond(method: string, path: string, response: unknown, status = 200): void {
    this.rest.set(`${method} ${path}`, () =>
      typeof response === "string"
        ? new Response(response, { status, headers: { "Content-Type": "application/json" } })
        : Response.json(status === 200 ? { response } : { error: response }, { status }),
    );
  }

  private installDefaultRest(): void {
    const base = `/api/1/vehicles/${this.vehicleId}`;
    // Written as text so the site id keeps all 16 digits on the wire.
    this.respond(
      "GET",
      "/api/1/products",
      `{"response":[${JSON.stringify(this.vehicleJson())},{"energy_site_id":${ENERGY_SITE_ID},"site_name":"Home","resource_type":"battery"}],"count":2}`,
    );
    for (const suffix of [
      "/vehicle_data_cached",
      "/mobile_enabled",
      "/nearby_charging_sites",
      "/recent_alerts",
      "/release_notes",
      "/service_data",
      "/drivers",
      "/invitations",
      "/fleet_telemetry_config",
      "/fleet_telemetry_errors",
    ]) {
      this.respond("GET", `${base}${suffix}`, { endpoint: suffix.slice(1) });
    }
    const site = `/api/1/energy_sites/${ENERGY_SITE_ID}`;
    for (const suffix of [
      "/live_status",
      "/site_info",
      "/site_status",
      "/backup_time_remaining",
      "/calendar_history",
      "/telemetry_history",
      "/charger_live_status",
      "/tariff_rate",
    ]) {
      this.respond("GET", `${site}${suffix}`, { endpoint: suffix.slice(1) });
    }
    for (const suffix of [
      "/backup",
      "/operation",
      "/storm_mode",
      "/grid_import_export",
      "/off_grid_vehicle_charging_reserve",
      "/time_of_use_settings",
    ]) {
      this.respond("POST", `${site}${suffix}`, { code: 201, message: "Updated" });
    }
    for (const path of [
      "/api/1/users/me",
      "/api/1/users/region",
      "/api/1/users/orders",
      "/api/1/users/feature_config",
    ]) {
      this.respond("GET", path, { endpoint: path });
    }
    for (const path of [
      "/api/1/dx/vehicles/options",
      "/api/1/dx/warranty/details",
      "/api/1/dx/vehicles/subscriptions/eligibility",
      "/api/1/dx/vehicles/upgrades/eligibility",
      "/api/1/dx/charging/history",
    ]) {
      this.respond("GET", path, { endpoint: path });
    }
    this.respond("POST", "/api/1/vehicles/fleet_status", { vehicle_command_protocol_required: true });
    this.respond("DELETE", `${base}/drivers`, true);
    this.respond("POST", `${base}/invitations`, { id: "123", short_url: "https://ts.la/share" });
    this.respond("DELETE", `${base}/fleet_telemetry_config`, { updated_vehicles: 1 });
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
    const body = request.method === "GET" ? "" : await request.text();
    this.requests.push({
      method: request.method,
      path: url.pathname,
      search: url.search,
      body,
      authorization: request.headers.get("Authorization"),
    });
    if (request.url === TOKEN_URL && request.method === "POST") {
      const form = new URLSearchParams(body);
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
      const { routable_message } = JSON.parse(body) as { routable_message: string };
      const result = await this.car.handle(bytesFromBase64(routable_message));
      if (!(result instanceof Uint8Array)) return Response.json({ error: "upstream" }, { status: result.status });
      return Response.json({ response: bytesToBase64(result) });
    }
    if (request.method === "POST" && url.pathname.startsWith(`${base}/command/`)) {
      if (this.state !== "online") return Response.json({ error: "vehicle unavailable" }, { status: 408 });
      return Response.json({ response: this.commandResult });
    }
    if (request.method === "POST" && /^\/api\/1\/vehicles\/\d+\/invitations\/\d+\/revoke$/.test(url.pathname)) {
      return Response.json({ response: true });
    }
    const canned = this.rest.get(`${request.method} ${url.pathname}`);
    if (canned) {
      if (
        url.pathname.startsWith(`${base}/`) &&
        /\/(nearby_charging_sites|release_notes|service_data|recent_alerts)$/.test(url.pathname) &&
        this.state !== "online"
      ) {
        return Response.json({ error: "vehicle unavailable" }, { status: 408 });
      }
      return canned();
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }
}
