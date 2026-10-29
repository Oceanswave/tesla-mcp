import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { McpAuthenticator } from "../src/auth";
import { DANGEROUS_ACTIONS, type DangerousAction, gateTools } from "../src/mcp/dangerous";
import type { OwnerState } from "../src/owner/state";
import { handleRequest } from "../src/routes";
import { FakeTesla, uniqueName } from "./helpers/fake-tesla";

const ENDPOINT = "https://tesla-mcp.example/mcp";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Each test acts as its own owner (its own OwnerState), through the real
 * /mcp handler, with the authenticator seam a later OAuth sign-in will use. */
async function connect(overrides: Partial<typeof env> = {}) {
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

type ToolResult = { isError?: boolean; structuredContent?: Record<string, unknown>; content: unknown[] };

const EXPECTED_TOOLS = [
  "tesla_audit_recent",
  "tesla_auth_status",
  "tesla_lock",
  "tesla_vehicle_status",
  "tesla_vehicles_list",
  "tesla_wake",
];

describe("MCP over the real /mcp handler", () => {
  it("initializes, lists tools, and calls a read tool", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    expect(client.getServerVersion()?.name).toBe("tesla-mcp");
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name).sort()).toEqual(EXPECTED_TOOLS);
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint).toBe(!["tesla_lock", "tesla_wake"].includes(tool.name));
    }
    for (const name of ["tesla_lock", "tesla_wake"]) {
      const schema = tools.find((tool) => tool.name === name)?.inputSchema as { properties: Record<string, unknown> };
      expect(Object.keys(schema.properties).sort()).toEqual(["confirm", "dryRun", "vehicle_id"]);
    }

    const listed = (await client.callTool({ name: "tesla_vehicles_list", arguments: {} })) as ToolResult;
    expect(listed.isError).toBeFalsy();
    expect(listed.structuredContent?.vehicles).toEqual([{ id: tesla.vehicleId, name: "Test Car", state: "online" }]);

    const status = (await client.callTool({ name: "tesla_vehicle_status", arguments: {} })) as ToolResult;
    expect(status.structuredContent).toMatchObject({
      state: "online",
      status: { locked: false, batteryPercent: 76, sentryMode: true, odometerMiles: 12345.6 },
    });
    // No location ever leaves the server.
    expect(JSON.stringify(status)).not.toMatch(/latitude|longitude/);
    await client.close();
  });

  it("never wakes the car for status", async () => {
    const tesla = new FakeTesla();
    tesla.state = "asleep";
    tesla.install();
    const { client } = await connect();
    const status = (await client.callTool({ name: "tesla_vehicle_status", arguments: {} })) as ToolResult;
    expect(status.structuredContent).toMatchObject({ state: "asleep", status: null });
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/wake_up"))).toBe(false);
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/vehicle_data"))).toBe(false);
    await client.close();
  });

  it("refuses state-changing tools without confirm: true and sends nothing", async () => {
    const tesla = new FakeTesla();
    const fetchSpy = tesla.install();
    const { client, owner } = await connect();
    for (const name of ["tesla_lock", "tesla_wake"]) {
      for (const args of [{}, { confirm: false }]) {
        const result = (await client.callTool({ name, arguments: args })) as ToolResult;
        expect(result.isError).toBe(true);
        expect(result.structuredContent?.error).toBe("confirmation_required");
      }
      const invalid = (await client.callTool({ name, arguments: { confirm: "yes" } })) as ToolResult;
      expect(invalid.isError).toBe(true);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    const audit = await owner.auditRecent(10);
    expect(audit.filter((row) => row.outcome === "denied")).toHaveLength(4);
    await client.close();
  });

  it("dryRun describes the action and sends nothing", async () => {
    const tesla = new FakeTesla();
    const fetchSpy = tesla.install();
    const { client } = await connect();
    for (const name of ["tesla_lock", "tesla_wake"]) {
      const result = (await client.callTool({ name, arguments: { confirm: true, dryRun: true } })) as ToolResult;
      expect(result.isError).toBeFalsy();
      expect(result.structuredContent).toMatchObject({ dryRun: true });
      expect(String(result.structuredContent?.summary)).toMatch(/Nothing was sent/);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(tesla.car.locked).toBe(false);
    await client.close();
  });

  it("locks the car with a signed VCSEC command when confirmed", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client, owner } = await connect();
    const result = (await client.callTool({ name: "tesla_lock", arguments: { confirm: true } })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ summary: "The car is locked.", detail: "locked", attempts: 1 });
    expect(tesla.car.locked).toBe(true);
    const [latest] = await owner.auditRecent(1);
    expect(latest).toMatchObject({ source: "tool", action: "lock", outcome: "ok", vehicleId: tesla.vehicleId });
    const audit = (await client.callTool({ name: "tesla_audit_recent", arguments: { limit: 5 } })) as ToolResult;
    expect(audit.structuredContent?.entries).toEqual(
      expect.arrayContaining([expect.objectContaining({ action: "lock" })]),
    );
    await client.close();
  });

  it("wakes an asleep car, waits for it, locks, and reads the lock state back", async () => {
    const tesla = new FakeTesla();
    tesla.state = "asleep";
    tesla.pollsUntilOnline = 2;
    tesla.install();
    const { client, owner } = await connect();
    await runInDurableObject(owner, (instance: OwnerState) => {
      instance.sleep = async () => {};
    });
    await runInDurableObject(env.TESLA_VCP.get(env.TESLA_VCP.idFromName(tesla.vin)), (instance) => {
      instance.sleep = async () => {};
    });
    const result = (await client.callTool({ name: "tesla_lock", arguments: { confirm: true } })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({
      summary: "The car woke up and is now locked.",
      locked: true,
      confirmed: true,
      detail: "locked_after_wake",
      woke: true,
      attempts: 1,
    });
    expect(tesla.car.locked).toBe(true);
    expect(tesla.fleetRequests.filter((request) => request.path.endsWith("/wake_up"))).toHaveLength(1);
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/vehicle_data"))).toBe(true);
    await client.close();
  });

  it("names the specific reason when the lock fails", async () => {
    const tesla = new FakeTesla();
    tesla.car.handshakeFault = 3;
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({ name: "tesla_lock", arguments: { confirm: true } })) as ToolResult;
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ error: "command_failed", reason: "pairing_required" });
    expect(String(result.structuredContent?.summary)).toMatch(/Pair the virtual key/);
    await client.close();
  });

  it("reports the sign-in state without contacting Tesla", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    // Nothing has signed in yet, but a bootstrap token is ready to use.
    const ready = (await client.callTool({ name: "tesla_auth_status", arguments: {} })) as ToolResult;
    expect(ready.structuredContent).toMatchObject({ authState: "ok", message: null });
    expect(tesla.requests).toHaveLength(0);
    await client.close();
  });

  it("reports reauth_required once Tesla rejects the sign-in", async () => {
    const tesla = new FakeTesla();
    tesla.tokenResponder = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    tesla.install();
    const { client } = await connect();
    const listed = (await client.callTool({ name: "tesla_vehicles_list", arguments: {} })) as ToolResult;
    expect(listed.structuredContent).toMatchObject({ error: "reauth_required" });
    const requests = tesla.requests.length;
    const status = (await client.callTool({ name: "tesla_auth_status", arguments: {} })) as ToolResult;
    expect(status.isError).toBeUndefined();
    expect(status.structuredContent).toMatchObject({ authState: "reauth_required" });
    expect(String(status.structuredContent?.summary)).toMatch(/wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN/);
    expect(tesla.requests).toHaveLength(requests);
    await client.close();
  });
});

describe("dangerous-command gate", () => {
  it("registers no dangerous tools by default", async () => {
    expect(env.DANGEROUS_COMMANDS_ENABLED).toBe("false");
    const { client } = await connect();
    const names = (await client.listTools()).tools.map((tool) => tool.name).join(" ");
    for (const pattern of [
      /unlock/,
      /remote_start/,
      /trunk/,
      /frunk/,
      /window/,
      /valet/,
      /pin/,
      /speed/,
      /homelink/,
      /erase/,
    ]) {
      expect(names).not.toMatch(pattern);
    }
    await client.close();
  });

  it("filters any tool tagged with a dangerous action unless explicitly enabled", () => {
    const tools: { name: string; dangerousAction?: DangerousAction }[] = [
      { name: "safe" },
      ...DANGEROUS_ACTIONS.map((action) => ({ name: action, dangerousAction: action })),
    ];
    expect(gateTools(tools, false).map((tool) => tool.name)).toEqual(["safe"]);
    expect(gateTools(tools, true)).toHaveLength(tools.length);
  });
});
