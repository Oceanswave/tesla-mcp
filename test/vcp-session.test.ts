import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { concatBytes } from "../src/bytes";
import {
  encodeLengthDelimited,
  encodeVarintField,
  MESSAGE_FAULT,
  parseVcsecResult,
  VCSEC_INFORMATION,
} from "../src/tesla/vcp/protocol";
import { TeslaVcpCore, VcpError } from "../src/tesla/vcp/session";
import { FakeTesla, FLEET } from "./helpers/fake-tesla";

const TOKEN = "test-access-token-0123456789";

function coreFor(tesla: FakeTesla, sleeps: number[] = []) {
  return new TeslaVcpCore({
    fleetBaseUrl: FLEET,
    privateKeyPkcs8Base64: env.TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64 as string,
    publicKeyPem: env.TESLA_PUBLIC_KEY_PEM,
    fetchFn: (input, init) => tesla.handle(new Request(input as RequestInfo, init)),
    sleep: async (milliseconds) => {
      sleeps.push(milliseconds);
    },
  });
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "ok";
  } catch (error) {
    if (error instanceof VcpError) return error.code;
    throw error;
  }
}

describe("VCSEC session against a simulated vehicle", () => {
  it("handshakes, signs a lock the car verifies, and reuses the session", async () => {
    const tesla = new FakeTesla();
    const core = coreFor(tesla);
    await core.command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" });
    expect(tesla.car.locked).toBe(true);
    expect(tesla.car.handshakes).toBe(1);
    await core.command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" });
    expect(tesla.car.handshakes).toBe(1);
    expect(tesla.car.commands).toBe(2);
    // Bearer token went only to Fleet, on the signed_command path.
    expect(tesla.requests.every((request) => request.authorization === `Bearer ${TOKEN}`)).toBe(true);
  });

  it("authenticates and decrypts an AES-GCM encrypted VCSEC reply", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "encrypted_ok" }];
    expect(await codeOf(coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "ok",
    );
    expect(tesla.car.locked).toBe(true);
  });

  it("accepts a VCSEC reply without a request UUID but asks the caller to confirm it", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "ok_no_uuid" }];
    const core = coreFor(tesla);
    await expect(core.command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" })).rejects.toMatchObject({
      code: "status_unknown",
      stage: "vcsec_uncorrelated_completion",
    });
    expect(tesla.car.locked).toBe(true);
    expect(tesla.car.commands).toBe(1);
  });

  it("treats a reply without a request UUID for another address as unknown, never success", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "misaddressed" }];
    expect(await codeOf(coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "status_unknown",
    );
    expect(tesla.car.commands).toBe(1);
  });

  it("reports an acknowledged-only reply as status_unknown without resending", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "ack" }];
    expect(await codeOf(coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "status_unknown",
    );
    expect(tesla.car.commands).toBe(1);
  });

  it("rejects a session whose SessionInfo HMAC does not verify", async () => {
    const tesla = new FakeTesla();
    tesla.car.forgeSessionTag = true;
    expect(await codeOf(coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "session_unavailable",
    );
    expect(tesla.car.commands).toBe(0);
  });

  it("reports pairing_required when the car does not know the key", async () => {
    const tesla = new FakeTesla();
    tesla.car.handshakeFault = MESSAGE_FAULT.UNKNOWN_KEY_ID;
    expect(await codeOf(coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "pairing_required",
    );
  });

  it("re-handshakes exactly once on a stale-session fault", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "fault", fault: MESSAGE_FAULT.INVALID_TOKEN_OR_COUNTER }];
    await coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" });
    expect(tesla.car.handshakes).toBe(2);
    expect(tesla.car.locked).toBe(true);

    const stuck = new FakeTesla();
    stuck.car.behaviors = [
      { kind: "fault", fault: MESSAGE_FAULT.INVALID_SIGNATURE },
      { kind: "fault", fault: MESSAGE_FAULT.INVALID_SIGNATURE },
    ];
    expect(await codeOf(coreFor(stuck).command({ vin: stuck.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "session_unavailable",
    );
    expect(stuck.car.handshakes).toBe(2);
  });

  it("retries WAIT a bounded number of times with a fresh counter", async () => {
    const tesla = new FakeTesla();
    const sleeps: number[] = [];
    tesla.car.behaviors = [{ kind: "wait" }];
    await coreFor(tesla, sleeps).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" });
    expect(tesla.car.locked).toBe(true);
    expect(sleeps).toEqual([1_000]);

    const busy = new FakeTesla();
    busy.car.behaviors = [{ kind: "wait" }, { kind: "wait" }, { kind: "wait" }, { kind: "wait" }];
    expect(await codeOf(coreFor(busy).command({ vin: busy.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "vehicle_unavailable",
    );
    expect(busy.car.commands).toBe(3);
  });

  it("maps VCSEC rejections and HTTP answers to stable codes", async () => {
    const notOnWhitelist = new FakeTesla();
    notOnWhitelist.car.behaviors = [{ kind: "vcsec_error", information: VCSEC_INFORMATION.FAULT_NOT_ON_WHITELIST }];
    expect(
      await codeOf(
        coreFor(notOnWhitelist).command({ vin: notOnWhitelist.vin, accessToken: TOKEN, command: "door_lock" }),
      ),
    ).toBe("pairing_required");

    const rejected = new FakeTesla();
    rejected.car.behaviors = [{ kind: "vcsec_error", information: 1 }];
    expect(
      await codeOf(coreFor(rejected).command({ vin: rejected.vin, accessToken: TOKEN, command: "door_lock" })),
    ).toBe("command_rejected");

    const asleep = new FakeTesla();
    asleep.state = "asleep";
    expect(await codeOf(coreFor(asleep).command({ vin: asleep.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "vehicle_unavailable",
    );

    for (const [status, code] of [
      [401, "unauthorized"],
      [429, "rate_limited"],
      [500, "status_unknown"],
    ] as const) {
      const tesla = new FakeTesla();
      tesla.car.behaviors = [{ kind: "http", status }];
      expect(await codeOf(coreFor(tesla).command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
        code,
      );
    }
  });

  it("refuses invalid requests before contacting Tesla", async () => {
    const tesla = new FakeTesla();
    const core = coreFor(tesla);
    expect(await codeOf(core.command({ vin: "not-a-vin", accessToken: TOKEN, command: "door_lock" }))).toBe(
      "invalid_request",
    );
    expect(await codeOf(core.command({ vin: tesla.vin, accessToken: TOKEN, command: "get" as "door_lock" }))).toBe(
      "invalid_request",
    );
    // Parameters are checked by the payload builder before any handshake.
    const badLimit = await core
      .command({ vin: tesla.vin, accessToken: TOKEN, command: "set_charge_limit", params: { percent: 10 } })
      .catch((error: unknown) => error);
    expect(badLimit).toMatchObject({ code: "invalid_request", stage: "param_percent" });
    expect(tesla.requests).toHaveLength(0);
  });

  it("refuses a private key that does not match the published public key", async () => {
    const other = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
    ])) as CryptoKeyPair;
    const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", other.privateKey)) as ArrayBuffer);
    const tesla = new FakeTesla();
    const core = new TeslaVcpCore({
      fleetBaseUrl: FLEET,
      privateKeyPkcs8Base64: btoa(String.fromCharCode(...pkcs8)),
      publicKeyPem: env.TESLA_PUBLIC_KEY_PEM,
      fetchFn: (input, init) => tesla.handle(new Request(input as RequestInfo, init)),
    });
    expect(await codeOf(core.command({ vin: tesla.vin, accessToken: TOKEN, command: "door_lock" }))).toBe(
      "unconfigured",
    );
    expect(tesla.requests).toHaveLength(0);
  });
});

describe("parseVcsecResult", () => {
  const commandStatus = (inner: Uint8Array) => encodeLengthDelimited(4, inner);
  it("classifies FromVCSECMessage replies", () => {
    expect(parseVcsecResult(new Uint8Array())).toEqual({ status: "ok" });
    // CommandStatus(OK) acknowledges receipt; Tesla's RKE handler waits for more.
    expect(parseVcsecResult(commandStatus(new Uint8Array()))).toEqual({ status: "acknowledged" });
    expect(parseVcsecResult(commandStatus(encodeVarintField(1, 1)))).toEqual({ status: "wait" });
    expect(
      parseVcsecResult(
        commandStatus(concatBytes(encodeVarintField(1, 2), encodeLengthDelimited(2, encodeVarintField(2, 17)))),
      ),
    ).toEqual({ status: "error", information: 17, genericError: 0 });
    expect(parseVcsecResult(encodeLengthDelimited(46, encodeVarintField(1, 3)))).toEqual({
      status: "error",
      information: 0,
      genericError: 3,
    });
    expect(parseVcsecResult(new Uint8Array([0x22, 0x05, 0x08]))).toEqual({ status: "unknown" });
    expect(parseVcsecResult(commandStatus(encodeVarintField(1, 9)))).toEqual({ status: "unknown" });
  });
});
