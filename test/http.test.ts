import { SELF } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { handleRequest, MAX_MCP_BODY_BYTES, PUBLIC_KEY_PATH } from "../src/index";

const BASE = "https://tesla-mcp.example";
const INIT = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } },
});

function mcpRequest(authorization?: string, body = INIT): Request {
  return new Request(`${BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(authorization ? { Authorization: authorization } : {}),
    },
    body,
  });
}

describe("routes", () => {
  it("serves the public key for Tesla with a PEM content type and caching", async () => {
    const response = await SELF.fetch(`${BASE}${PUBLIC_KEY_PATH}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/x-pem-file");
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=3600");
    expect(new TextDecoder().decode(await response.arrayBuffer())).toBe(env.TESLA_PUBLIC_KEY_PEM);
  });

  it("serves the home page, health check, and callback placeholder with security headers", async () => {
    for (const path of ["/", "/healthz", "/callback"]) {
      const response = await SELF.fetch(`${BASE}${path}`);
      expect(response.status).toBe(200);
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(await response.text()).not.toMatch(/workers\.dev/);
    }
    expect(await (await SELF.fetch(`${BASE}/healthz`)).json()).toEqual({ status: "ok", service: "tesla-mcp" });
  });

  it("returns 404 for everything else", async () => {
    for (const path of ["/admin", "/mcp/extra", "/.well-known/other", "/callback/x"]) {
      expect((await SELF.fetch(`${BASE}${path}`)).status).toBe(404);
    }
    expect((await SELF.fetch(`${BASE}/healthz`, { method: "POST" })).status).toBe(404);
  });
});

describe("/mcp authentication", () => {
  it("rejects a missing or wrong bearer token with WWW-Authenticate", async () => {
    for (const authorization of [undefined, "Bearer wrong-token", "Basic abc", `Bearer ${env.MCP_BEARER_TOKEN}x`]) {
      const response = await SELF.fetch(mcpRequest(authorization));
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toMatch(/^Bearer realm="tesla-mcp"/);
      expect(await response.text()).not.toContain(env.MCP_BEARER_TOKEN as string);
    }
  });

  it("accepts the configured bearer token", async () => {
    const response = await SELF.fetch(mcpRequest(`Bearer ${env.MCP_BEARER_TOKEN}`));
    expect(response.status).toBe(200);
    const raw = await response.text();
    const body = JSON.parse(
      raw.startsWith("{") ? raw : (raw.split("\n").find((line) => line.startsWith("data: ")) ?? "").slice(6),
    );
    expect(body.result.serverInfo.name).toBe("tesla-mcp");
  });

  it("fails closed when MCP_BEARER_TOKEN is unset", async () => {
    for (const token of [undefined, ""]) {
      const response = await handleRequest(mcpRequest(`Bearer ${env.MCP_BEARER_TOKEN}`), {
        ...env,
        MCP_BEARER_TOKEN: token,
      });
      expect(response.status).toBe(401);
      const empty = await handleRequest(mcpRequest("Bearer "), { ...env, MCP_BEARER_TOKEN: token });
      expect(empty.status).toBe(401);
    }
  });

  it("limits the request body size", async () => {
    const response = await SELF.fetch(mcpRequest(`Bearer ${env.MCP_BEARER_TOKEN}`, "x".repeat(MAX_MCP_BODY_BYTES + 1)));
    expect(response.status).toBe(413);
  });
});
