// Connect an MCP client to the real /mcp handler as a fresh owner.

import { env } from "cloudflare:workers";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { McpAuthenticator } from "../../src/auth";
import { handleRequest } from "../../src/routes";
import { uniqueName } from "./fake-tesla";

const ENDPOINT = "https://tesla-mcp.example/mcp";

export type ToolResult = { isError?: boolean; structuredContent?: Record<string, unknown>; content: unknown[] };

/** Each caller acts as its own owner (its own OwnerState), through the real
 * /mcp handler, with the authenticator seam a later OAuth sign-in will use. */
export async function connect(overrides: Partial<typeof env> = {}) {
  const ownerId = uniqueName("mcp-owner");
  const authenticator: McpAuthenticator = {
    authenticate: async () => ({ ok: true, principal: { ownerId } }),
  };
  const client = new Client({ name: "tesla-mcp-test", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(ENDPOINT), {
    fetch: (url, init) => handleRequest(new Request(url, init), { ...env, ...overrides }, authenticator),
  });
  await client.connect(transport);
  const owner = env.OWNER.get(env.OWNER.idFromName(ownerId));
  return { client, owner };
}
