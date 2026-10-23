// Tesla OAuth tokens at rest: AES-256-GCM with a random 12-byte IV and a fixed
// AAD that binds ciphertexts to this purpose and format version.

import { asArrayBuffer, bytesFromBase64, bytesToBase64 } from "../bytes";

export const TOKEN_AAD = "tesla-mcp:tokens:v1";
const PREFIX = "v1";
const encoder = new TextEncoder();

export type StoredTokens = {
  accessToken: string | null;
  refreshToken: string;
  /** Epoch milliseconds; 0 when unknown (forces a refresh). */
  expiresAt: number;
};

export class TokenCryptoError extends Error {
  constructor(readonly reason: "key_missing" | "key_invalid" | "ciphertext_invalid") {
    super(`token_crypto_${reason}`);
    this.name = "TokenCryptoError";
  }
}

export async function importTokenKey(base64Key: string | undefined): Promise<CryptoKey> {
  if (!base64Key) throw new TokenCryptoError("key_missing");
  let raw: Uint8Array;
  try {
    raw = bytesFromBase64(base64Key.trim(), 64);
  } catch {
    throw new TokenCryptoError("key_invalid");
  }
  if (raw.byteLength !== 32) throw new TokenCryptoError("key_invalid");
  return crypto.subtle.importKey("raw", asArrayBuffer(raw), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptTokens(key: CryptoKey, tokens: StoredTokens, aad: string = TOKEN_AAD): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(aad), tagLength: 128 },
    key,
    encoder.encode(JSON.stringify(tokens)),
  );
  return `${PREFIX}.${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
}

export async function decryptTokens(key: CryptoKey, blob: string, aad: string = TOKEN_AAD): Promise<StoredTokens> {
  const [prefix, ivText, ciphertextText, ...rest] = blob.split(".");
  if (prefix !== PREFIX || !ivText || !ciphertextText || rest.length) {
    throw new TokenCryptoError("ciphertext_invalid");
  }
  let plaintext: ArrayBuffer;
  try {
    const iv = bytesFromBase64(ivText);
    if (iv.byteLength !== 12) throw new Error("iv");
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: encoder.encode(aad),
        tagLength: 128,
      },
      key,
      asArrayBuffer(bytesFromBase64(ciphertextText)),
    );
  } catch {
    throw new TokenCryptoError("ciphertext_invalid");
  }
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Partial<StoredTokens>;
  if (
    typeof parsed.refreshToken !== "string" ||
    !parsed.refreshToken ||
    (parsed.accessToken !== null && typeof parsed.accessToken !== "string") ||
    typeof parsed.expiresAt !== "number"
  ) {
    throw new TokenCryptoError("ciphertext_invalid");
  }
  return {
    accessToken: parsed.accessToken,
    refreshToken: parsed.refreshToken,
    expiresAt: parsed.expiresAt,
  };
}
