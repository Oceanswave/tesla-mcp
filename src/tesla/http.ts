// Upstream transport helpers: bounded time and bounded bytes on every call.

export class BoundedResponseError extends Error {
  constructor(readonly reason: "invalid_length" | "too_large") {
    super(`bounded_response_${reason}`);
    this.name = "BoundedResponseError";
  }
}

/** Stream a response through a hard byte ceiling. Checking Content-Length
 * alone (or byteLength after response.text()) still lets an upstream omit or
 * lie about the header and make the Worker buffer an unbounded body. */
export async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
  const declared = response.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
    await response.body?.cancel().catch(() => {});
    throw new BoundedResponseError(/^\d+$/.test(declared) ? "too_large" : "invalid_length");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel().catch(() => {});
        throw new BoundedResponseError("too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export type FetchFn = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** The global fetch, bound to the global scope. workerd rejects a fetch
 * invoked with any other receiver. Resolved per call so tests can spy on it. */
export const defaultFetch: FetchFn = (input, init) => globalThis.fetch(input, init);

/** Fetch with a timeout and no redirect following: bearer tokens and signed
 * commands must only ever reach the configured Tesla origin. */
export function fetchUpstream(fetchFn: FetchFn, url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  return fetchFn(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
}
