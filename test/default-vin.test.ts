import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OwnerState } from "../src/owner/state";
import { FakeTesla, randomVehicleId, randomVin } from "./helpers/fake-tesla";
import { connect, type ToolResult } from "./helpers/mcp";

afterEach(() => {
  vi.restoreAllMocks();
});

/** An account with the fake car plus a second, asleep one. */
function twoCars() {
  const tesla = new FakeTesla();
  const other = { id_s: randomVehicleId(), vin: randomVin(), display_name: "Second Car", state: "asleep" };
  tesla.otherVehicles.push(other);
  tesla.install();
  return { tesla, other };
}

/** Connect as a fresh owner whose OwnerState sees DEFAULT_VIN. */
async function connectWithDefault(defaultVin: string) {
  const connection = await connect({ DEFAULT_VIN: defaultVin });
  await runInDurableObject(connection.owner, (instance: OwnerState) => {
    Object.assign(instance, { env: { ...env, DEFAULT_VIN: defaultVin } });
  });
  return connection;
}

async function status(client: Awaited<ReturnType<typeof connect>>["client"], args: Record<string, unknown> = {}) {
  return (await client.callTool({ name: "tesla_vehicle_status", arguments: args })) as ToolResult;
}

describe("DEFAULT_VIN", () => {
  it("lists every car with its VIN", async () => {
    const { tesla, other } = twoCars();
    const { client } = await connect();
    const listed = (await client.callTool({ name: "tesla_vehicles_list", arguments: {} })) as ToolResult;
    expect(listed.structuredContent?.vehicles).toEqual([
      { id: tesla.vehicleId, vin: tesla.vin, name: "Test Car", state: "online" },
      { id: other.id_s, vin: other.vin, name: "Second Car", state: "asleep" },
    ]);
    await client.close();
  });

  it("uses DEFAULT_VIN given as a VIN or as a vehicle id, and reports the VIN in status", async () => {
    const { tesla } = twoCars();
    for (const value of [tesla.vin, tesla.vin.toLowerCase(), tesla.vehicleId]) {
      const { client } = await connectWithDefault(value);
      const result = await status(client);
      expect(result.isError, value).toBeFalsy();
      expect(result.structuredContent?.vehicle).toEqual({
        id: tesla.vehicleId,
        vin: tesla.vin,
        displayName: "Test Car",
      });
      await client.close();
    }
  });

  it("lets an explicit vehicle_id (id or VIN) win over DEFAULT_VIN", async () => {
    const { tesla, other } = twoCars();
    const { client } = await connectWithDefault(other.vin);
    for (const vehicle_id of [tesla.vin, tesla.vehicleId]) {
      const result = await status(client, { vehicle_id });
      expect(result.isError, vehicle_id).toBeFalsy();
      expect(result.structuredContent?.vehicle).toMatchObject({ id: tesla.vehicleId });
    }
    await client.close();
  });

  it("names the choices when unset and the account has more than one car", async () => {
    const { tesla, other } = twoCars();
    const { client } = await connectWithDefault("");
    const result = await status(client);
    expect(result.isError).toBe(true);
    expect(result.structuredContent?.error).toBe("vehicle_id_required");
    const summary = String(result.structuredContent?.summary);
    for (const part of ["Test Car", tesla.vehicleId, tesla.vin, "Second Car", other.id_s, other.vin, "DEFAULT_VIN"]) {
      expect(summary).toContain(part);
    }
    await client.close();
  });

  it("uses the only car when unset", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connectWithDefault("");
    expect((await status(client)).structuredContent?.vehicle).toMatchObject({ vin: tesla.vin });
    await client.close();
  });

  it("refuses a DEFAULT_VIN that is not on the account, and sends nothing to the car", async () => {
    const { tesla } = twoCars();
    const missing = randomVin();
    const { client } = await connectWithDefault(missing);
    const result = await status(client);
    expect(result.structuredContent?.error).toBe("vehicle_not_found");
    expect(String(result.structuredContent?.summary)).toContain(`DEFAULT_VIN is set to ${missing}`);
    const lock = (await client.callTool({ name: "tesla_lock", arguments: { confirm: true } })) as ToolResult;
    expect(lock.structuredContent?.error).toBe("vehicle_not_found");
    expect(tesla.car.locked).toBe(false);
    expect(tesla.fleetRequests.every((request) => request.path === "/api/1/vehicles")).toBe(true);
    await client.close();
  });

  it("keeps a VIN passed as vehicle_id out of the audit log", async () => {
    const { tesla } = twoCars();
    const { client, owner } = await connectWithDefault("");
    const denied = (await client.callTool({
      name: "tesla_lock",
      arguments: { vehicle_id: tesla.vin },
    })) as ToolResult;
    expect(denied.structuredContent?.error).toBe("confirmation_required");
    const unknown = randomVin();
    await client.callTool({ name: "tesla_wake", arguments: { vehicle_id: unknown, confirm: true } });
    const audit = JSON.stringify(await owner.auditRecent(10));
    expect(audit).not.toContain(tesla.vin);
    expect(audit).not.toContain(unknown);
    await client.close();
  });
});
