// Tesla OAuth for the owner's browser sign-in: the authorize URL /login sends
// the browser to, and the unverified claims read from an access token. The
// token came straight from Tesla's token endpoint over TLS; its claims are
// only used to report scopes and to keep sign-in on the same account.

import { bytesFromBase64, bytesToBase64 } from "../bytes";
import { SIGN_IN_SCOPES } from "./endpoints";

export const TESLA_AUTHORIZE_URL = "https://auth.tesla.com/oauth2/v3/authorize";

/** How long a /login state value stays usable. */
export const SIGN_IN_STATE_TTL_MS = 10 * 60_000;

/** 32 random bytes, base64url without padding (43 characters). */
export const SIGN_IN_STATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function newSignInState(): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function authorizeUrl(input: { clientId: string; redirectUri: string; state: string }): string {
  const url = new URL(TESLA_AUTHORIZE_URL);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    scope: SIGN_IN_SCOPES.join(" "),
    state: input.state,
    prompt_missing_scopes: "true",
  }).toString();
  return url.toString();
}

/** The redirect URI registered with Tesla: OAUTH_REDIRECT_BASE (trailing
 * slashes dropped) + /callback. Never derived from the request. Null when the
 * base is missing or not a plain https URL. */
export function signInRedirectUri(base: string | undefined): string | null {
  const value = base?.trim().replace(/\/+$/, "");
  if (!value) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
  return `${value}/callback`;
}

export type AccessTokenClaims = { sub: string | null; scopes: string[] | null };

/** `sub` and `scp` from a JWT access token, without verifying it. Anything
 * unreadable comes back as null. */
export function accessTokenClaims(token: string | null): AccessTokenClaims {
  const none = { sub: null, scopes: null };
  const payload = token?.split(".")[1];
  if (!payload) return none;
  let claims: unknown;
  try {
    const base64 = payload.replaceAll("-", "+").replaceAll("_", "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    claims = JSON.parse(new TextDecoder().decode(bytesFromBase64(padded, 16_384)));
  } catch {
    return none;
  }
  if (!claims || typeof claims !== "object") return none;
  const { sub, scp } = claims as Record<string, unknown>;
  const scopes = Array.isArray(scp)
    ? scp.filter((scope): scope is string => typeof scope === "string")
    : typeof scp === "string"
      ? scp.split(" ").filter(Boolean)
      : null;
  return {
    sub: typeof sub === "string" && sub ? sub : null,
    scopes: scopes ? scopes.filter((scope) => /^[A-Za-z0-9_.:-]{1,64}$/.test(scope)) : null,
  };
}
