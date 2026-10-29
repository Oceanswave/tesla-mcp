// Small byte helpers shared by the protocol, token, and HTTP layers.

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

/** WebCrypto wants an ArrayBuffer-backed view; copy to drop any offset. */
export function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function bytesFromHex(value: string): Uint8Array {
  if (value.length % 2 || !/^[0-9a-f]*$/i.test(value)) {
    throw new Error("invalid hex");
  }
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function bytesFromBase64(value: string, maxLength = 131_072): Uint8Array {
  if (!value || value.length > maxLength || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error("invalid base64");
  }
  const binary = atob(value);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    output[index] = binary.charCodeAt(index);
  }
  return output;
}

/** Length-hiding comparison for equal-purpose secrets (HMAC tags, hashes). */
export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.byteLength ^ right.byteLength;
  const length = Math.max(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index++) {
    difference |=
      (left[index % Math.max(1, left.byteLength)] ?? 0) ^ (right[index % Math.max(1, right.byteLength)] ?? 0);
  }
  return difference === 0;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(data)));
}

export function random16(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

const encoder = new TextEncoder();

/** Compare a presented secret with the expected one without leaking either
 * its content or its length through timing: both are hashed first. */
export async function secretsEqual(presented: string, expected: string): Promise<boolean> {
  const [left, right] = await Promise.all([sha256(encoder.encode(presented)), sha256(encoder.encode(expected))]);
  return constantTimeEqual(left, right);
}
