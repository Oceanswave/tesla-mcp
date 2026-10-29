import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Every credential the test runtime sees is generated here, fresh per run.
// Nothing is read from .dev.vars and no key material is committed.
const subtle = crypto.subtle;
const base64 = (bytes: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const keyPair = (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
  "sign",
  "verify",
])) as CryptoKeyPair;
const pkcs8 = base64((await subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer);
const spki = base64((await subtle.exportKey("spki", keyPair.publicKey)) as ArrayBuffer);
const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${spki.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----\n`;
const randomToken = (bytes: number) =>
  base64(crypto.getRandomValues(new Uint8Array(bytes))).replace(
    /[+/=]/g,
    (c) => ({ "+": "-", "/": "_", "=": "" })[c] ?? "",
  );

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          // Unroutable hosts: a missed mock can never reach Tesla.
          TESLA_FLEET_BASE_URL: "https://fleet-api.tesla.test",
          TESLA_AUTH_TOKEN_URL: "https://fleet-auth.tesla.test/oauth2/v3/token",
          TESLA_PUBLIC_KEY_PEM: publicKeyPem,
          TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64: pkcs8,
          MCP_BEARER_TOKEN: randomToken(32),
          TOKEN_ENCRYPTION_KEY: base64(crypto.getRandomValues(new Uint8Array(32))),
          TESLA_CLIENT_ID: "test-client-id",
          TESLA_CLIENT_SECRET: "",
          TESLA_BOOTSTRAP_REFRESH_TOKEN: `test-bootstrap-${randomToken(24)}`,
          DEFAULT_VIN: "",
          OAUTH_EXTRA_REDIRECT_URIS: "",
          OAUTH_ADMIN_PASSPHRASE: randomToken(24),
          // A host unlike the one test requests use: the redirect URI must come
          // from this var, never from the request.
          OAUTH_REDIRECT_BASE: "https://sign-in.example.net/",
          // Production enables dangerous commands in wrangler.jsonc; tests pin the
          // safe default so the gate stays covered.
          DANGEROUS_COMMANDS_ENABLED: "false",
        },
      },
    }),
  ],
  test: {
    testTimeout: 20_000,
  },
});
