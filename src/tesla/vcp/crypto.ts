import { asArrayBuffer, concatBytes, constantTimeEqual } from "../../bytes";

const encoder = new TextEncoder();

function decodePublicKeyPem(value: string): Uint8Array {
  if (value.length > 4_096) throw new Error("public key is too large");
  const match = /^-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END PUBLIC KEY-----\s*$/.exec(value.trim());
  const body = match?.[1]?.replace(/\s/g, "");
  if (!body) throw new Error("public key must be PEM encoded");
  return derFromBase64(body);
}

function derFromBase64(value: string): Uint8Array {
  if (!value || value.length > 12_000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error("key must be base64 DER");
  }
  const binary = atob(value);
  const der = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) der[index] = binary.charCodeAt(index);
  return der;
}

function readDerLength(data: Uint8Array, start: number): [number, number] | null {
  let offset = start;
  if (offset >= data.byteLength) return null;
  const first = data[offset++] as number;
  if (!(first & 0x80)) return [first, offset];
  const count = first & 0x7f;
  if (!count || count > 2 || offset + count > data.byteLength) return null;
  let length = 0;
  for (let index = 0; index < count; index++) length = length * 256 + (data[offset++] as number);
  return [length, offset];
}

/** SPKI and the SEC1 structure embedded in standard EC PKCS#8 keys both carry
 * the uncompressed public point in a 66-byte BIT STRING. */
function embeddedPublicPoint(data: Uint8Array): Uint8Array {
  for (let offset = 0; offset < data.byteLength - 4; offset++) {
    if (data[offset] !== 0x03) continue; // ASN.1 BIT STRING
    const decoded = readDerLength(data, offset + 1);
    if (!decoded) continue;
    const [length, start] = decoded;
    if (length === 66 && start + length <= data.byteLength && data[start] === 0 && data[start + 1] === 4) {
      return data.slice(start + 1, start + length);
    }
  }
  throw new Error("key does not include a P-256 public point");
}

export type VcpKeyMaterial = {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
};

/** Import the command key secret (base64 PKCS#8 DER) as a non-extractable
 * ECDH key and prove it matches the published public key, so a mismatched
 * deployment fails before contacting Tesla. */
export async function importVcpPrivateKey(pkcs8Base64: string, expectedPublicKeyPem: string): Promise<VcpKeyMaterial> {
  const pkcs8 = derFromBase64(pkcs8Base64);
  const publicKey = embeddedPublicPoint(pkcs8);
  const expectedPublicDer = decodePublicKeyPem(expectedPublicKeyPem);
  if (!constantTimeEqual(publicKey, embeddedPublicPoint(expectedPublicDer))) {
    throw new Error("private key does not match the published public key");
  }
  // Prove the private scalar matches the published key instead of trusting
  // the optional public point embedded inside PKCS#8.
  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    asArrayBuffer(pkcs8),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const verificationKey = await crypto.subtle.importKey(
    "spki",
    asArrayBuffer(expectedPublicDer),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const proof = encoder.encode("tesla-mcp VCP key consistency");
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingKey, asArrayBuffer(proof));
  if (
    !(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verificationKey, signature, asArrayBuffer(proof)))
  ) {
    throw new Error("private key does not match the published public key");
  }
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    asArrayBuffer(pkcs8),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  return { privateKey, publicKey };
}

/** K = SHA1(ECDH(client, vehicle).x)[:16], per Tesla's protocol. */
export async function deriveSessionKey(privateKey: CryptoKey, vehiclePublicKey: Uint8Array): Promise<Uint8Array> {
  if (vehiclePublicKey.byteLength !== 65 || vehiclePublicKey[0] !== 4) {
    throw new Error("invalid vehicle public key");
  }
  const publicKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(vehiclePublicKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    // WebCrypto's standard member is `public`; Cloudflare's generated type
    // spells the same Web IDL member `$public`.
    { name: "ECDH", public: publicKey } as unknown as SubtleCryptoDeriveKeyAlgorithm,
    privateKey,
    256,
  );
  // Tesla specifies SHA-1 here as a PRF over the uniformly random ECDH
  // x-coordinate, truncated to the 128-bit session key.
  const digest = await crypto.subtle.digest("SHA-1", sharedSecret);
  return new Uint8Array(digest).slice(0, 16);
}

export async function hmacSha256(key: Uint8Array, ...data: Uint8Array[]): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", asArrayBuffer(key), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, asArrayBuffer(concatBytes(...data))));
}

export function deriveSigningKey(sessionKey: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(sessionKey, encoder.encode("authenticated command"));
}

export function deriveSessionInfoKey(sessionKey: Uint8Array): Promise<Uint8Array> {
  return hmacSha256(sessionKey, encoder.encode("session info"));
}

export async function sha256Digest(...data: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(concatBytes(...data))));
}

/** Decrypt and authenticate a Tesla AES-GCM response. Response encryption
 * uses the 128-bit ECDH-derived session key directly. */
export async function decryptAesGcmResponse(
  sessionKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  if (
    sessionKey.byteLength !== 16 ||
    nonce.byteLength !== 12 ||
    tag.byteLength !== 16 ||
    additionalData.byteLength !== 32
  ) {
    throw new Error("invalid AES-GCM response parameters");
  }
  const key = await crypto.subtle.importKey("raw", asArrayBuffer(sessionKey), { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(nonce),
      additionalData: asArrayBuffer(additionalData),
      tagLength: 128,
    },
    key,
    asArrayBuffer(concatBytes(ciphertext, tag)),
  );
  return new Uint8Array(plaintext);
}
