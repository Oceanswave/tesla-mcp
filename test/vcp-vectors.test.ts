// Cross-language vectors: the TypeScript signer must produce exactly the bytes
// the owner's production Python plugin produces for a VCSEC lock. Regenerate
// with scripts/vcsec_vectors.py. The keys are the private scalars 1 (client)
// and 2 (vehicle), assembled here at runtime; no key file is committed.

import { describe, expect, it } from "vitest";
import { bytesFromHex, bytesToBase64, bytesToHex, concatBytes } from "../src/bytes";
import {
  deriveSessionInfoKey,
  deriveSessionKey,
  deriveSigningKey,
  hmacSha256,
  importVcpPrivateKey,
} from "../src/tesla/vcp/crypto";
import {
  buildSessionInfoRequest,
  buildVcsecLockPayload,
  DOMAIN_INFOTAINMENT,
  DOMAIN_VEHICLE_SECURITY,
  encodeCommandMetadata,
  encodeLengthDelimited,
  encodeResponseMetadata,
  encodeSessionInfoMetadata,
  responseRequestHash,
  SIGNED_COMMANDS,
} from "../src/tesla/vcp/protocol";
import { TeslaVcpCore } from "../src/tesla/vcp/session";

const PY = {
  client_pub:
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  vehicle_pub:
    "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
  // Derived from the public test scalars 1 and 2, so worthless as secrets; the
  // generic-api-key rule only sees "key" next to hex.
  session_key: "b59d61fedc3b7a1ee22fde1780a59522", // gitleaks:allow
  signing_key: "62bae25f96a2ec94e54651e6b0ca389c56d230f6bbf5a1b21fef11d12cf7d44b", // gitleaks:allow
  session_info_key: "45b2513c0595df7bf4a8313e3c654835446cf99fbb979ff9864447000da07567", // gitleaks:allow
  session_info:
    "08071241047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d11a10000102030405060708090a0b0c0d0e0f25e8030000",
  session_info_tag: "397a81d849eaacd4da2fc0072a3e0ff91085c094ebc2817d5856e2e04cca2366",
  handshake_request:
    "320208023a121210202122232425262728292a2b2c2d2e2f72430a41046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f59a0310404142434445464748494a4b4c4d4e4f",
  lock_payload: "1001",
  lock_metadata:
    "000108010102021135594a3345314541314e463030303030310310000102030405060708090a0b0c0d0e0f0404000003f7050400000008",
  lock_tag: "edcc29435c1fc87e36479bdb209b132e344a3f8a5f2e654112d0aaeeada015ed",
  lock_routable_message:
    "320208023a121210202122232425262728292a2b2c2d2e2f520210016a82010a430a41046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5423b0a10000102030405060708090a0b0c0d0e0f10081df70300002220edcc29435c1fc87e36479bdb209b132e344a3f8a5f2e654112d0aaeeada015ed9a0310303132333435363738393a3b3c3d3e3f",
};

const VIN = "5YJ3E1EA1NF000001";
const EPOCH = bytesFromHex("000102030405060708090a0b0c0d0e0f");
const ROUTING = bytesFromHex("202122232425262728292a2b2c2d2e2f");
const UUID_COMMAND = bytesFromHex("303132333435363738393a3b3c3d3e3f");
const UUID_HANDSHAKE = bytesFromHex("404142434445464748494a4b4c4d4e4f");

// DER framing for a P-256 key; the scalar and point are spliced in.
const PKCS8_PREFIX = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420";
const SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

function scalarKey(scalar: number, publicPointHex: string) {
  const d = scalar.toString(16).padStart(64, "0");
  const pkcs8 = bytesFromHex(`${PKCS8_PREFIX}${d}a144034200${publicPointHex}`);
  const spki = bytesToBase64(bytesFromHex(`${SPKI_PREFIX}${publicPointHex}`));
  const label = "PUBLIC KEY";
  return {
    pkcs8Base64: bytesToBase64(pkcs8),
    publicKeyPem: `-----BEGIN ${label}-----\n${spki.match(/.{1,64}/g)?.join("\n")}\n-----END ${label}-----\n`,
  };
}

const CLIENT = scalarKey(1, PY.client_pub);
const VEHICLE = scalarKey(2, PY.vehicle_pub);

describe("VCSEC lock vectors match the Python plugin", () => {
  it("derives the same session, signing, and session-info keys", async () => {
    const client = await importVcpPrivateKey(CLIENT.pkcs8Base64, CLIENT.publicKeyPem);
    expect(bytesToHex(client.publicKey)).toBe(PY.client_pub);
    const sessionKey = await deriveSessionKey(client.privateKey, bytesFromHex(PY.vehicle_pub));
    expect(bytesToHex(sessionKey)).toBe(PY.session_key);
    expect(bytesToHex(await deriveSigningKey(sessionKey))).toBe(PY.signing_key);
    expect(bytesToHex(await deriveSessionInfoKey(sessionKey))).toBe(PY.session_info_key);

    // ECDH is symmetric: the vehicle side derives the same key.
    const vehicle = await importVcpPrivateKey(VEHICLE.pkcs8Base64, VEHICLE.publicKeyPem);
    expect(bytesToHex(await deriveSessionKey(vehicle.privateKey, client.publicKey))).toBe(PY.session_key);
  });

  it("verifies the Python session-info tag", async () => {
    const tag = await hmacSha256(
      bytesFromHex(PY.session_info_key),
      encodeSessionInfoMetadata(VIN, UUID_HANDSHAKE),
      new Uint8Array([0xff]),
      bytesFromHex(PY.session_info),
    );
    expect(bytesToHex(tag)).toBe(PY.session_info_tag);
  });

  it("encodes the VCSEC handshake, lock payload, metadata, and tag identically", async () => {
    expect(
      bytesToHex(
        buildSessionInfoRequest(bytesFromHex(PY.client_pub), ROUTING, UUID_HANDSHAKE, DOMAIN_VEHICLE_SECURITY),
      ),
    ).toBe(PY.handshake_request);
    expect(bytesToHex(buildVcsecLockPayload())).toBe(PY.lock_payload);
    expect(SIGNED_COMMANDS.door_lock.domain).toBe(DOMAIN_VEHICLE_SECURITY);
    const metadata = encodeCommandMetadata({
      vin: VIN,
      epoch: EPOCH,
      expiresAt: 1015,
      counter: 8,
      domain: DOMAIN_VEHICLE_SECURITY,
      flags: SIGNED_COMMANDS.door_lock.flags,
    });
    expect(bytesToHex(metadata)).toBe(PY.lock_metadata);
    const tag = await hmacSha256(
      bytesFromHex(PY.signing_key),
      metadata,
      new Uint8Array([0xff]),
      bytesFromHex(PY.lock_payload),
    );
    expect(bytesToHex(tag)).toBe(PY.lock_tag);
  });

  it("binds encrypted responses to Tesla's RequestID (VCSEC truncates the tag to 16 bytes)", () => {
    const tag = bytesFromHex(PY.lock_tag);
    expect(bytesToHex(responseRequestHash(DOMAIN_VEHICLE_SECURITY, tag))).toBe(`08${PY.lock_tag.slice(0, 32)}`);
    expect(bytesToHex(responseRequestHash(DOMAIN_INFOTAINMENT, tag))).toBe(`08${PY.lock_tag}`);
    expect(
      bytesToHex(
        encodeResponseMetadata({
          vin: VIN,
          domain: DOMAIN_VEHICLE_SECURITY,
          counter: 7,
          flags: 0,
          requestHash: responseRequestHash(DOMAIN_VEHICLE_SECURITY, tag),
          fault: 0,
        }),
      ),
    ).toBe(
      [
        "000109", // SIGNATURE_TYPE_AES_GCM_RESPONSE
        "010102", // from domain
        `0211${bytesToHex(new TextEncoder().encode(VIN))}`, // personalization
        "050400000007", // counter
        "070400000000", // flags
        `0811${"08"}${PY.lock_tag.slice(0, 32)}`, // request hash, 17 bytes
        "090400000000", // fault
      ].join(""),
    );
    expect(() =>
      encodeResponseMetadata({ vin: VIN, domain: 2, counter: 0, flags: 0, requestHash: tag, fault: 0 }),
    ).toThrow("invalid response metadata");
  });

  it("sends byte-identical handshake and signed lock through the full session core", async () => {
    const randoms = [ROUTING, UUID_HANDSHAKE, UUID_COMMAND];
    const sent: string[] = [];
    const now = 1_900_000_000_000;
    const core = new TeslaVcpCore({
      fleetBaseUrl: "https://fleet-api.tesla.test",
      privateKeyPkcs8Base64: CLIENT.pkcs8Base64,
      publicKeyPem: CLIENT.publicKeyPem,
      now: () => now,
      randomBytes16: () => randoms.shift() as Uint8Array,
      sleep: async () => {},
      fetchFn: async (input, init) => {
        expect(String(input)).toBe(`https://fleet-api.tesla.test/api/1/vehicles/${VIN}/signed_command`);
        const message = JSON.parse(String(init?.body)).routable_message as string;
        sent.push(bytesToHex(Uint8Array.from(atob(message), (c) => c.charCodeAt(0))));
        const response =
          sent.length === 1
            ? concatBytes(
                encodeLengthDelimited(
                  13,
                  encodeLengthDelimited(6, encodeLengthDelimited(1, bytesFromHex(PY.session_info_tag))),
                ),
                encodeLengthDelimited(15, bytesFromHex(PY.session_info)),
                encodeLengthDelimited(50, UUID_HANDSHAKE),
              )
            : // Completion: an empty FromVCSECMessage (a bare CommandStatus is
              // only an acknowledgement).
              encodeLengthDelimited(50, UUID_COMMAND);
        return Response.json({ response: bytesToBase64(response) });
      },
    });
    await core.command({ vin: VIN, accessToken: "test-access-token-0123456789", command: "door_lock" });
    expect(sent).toEqual([PY.handshake_request, PY.lock_routable_message]);
  });
});
