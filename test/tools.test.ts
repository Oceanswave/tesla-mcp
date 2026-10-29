// The full tool surface: schema invariants for every tool, and behavior of the
// signed-command, Fleet REST, and energy tools against the simulated Tesla.

import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CATALOG } from "../src/mcp/catalog";
import { DANGEROUS_ACTIONS, dangerousSignedCommand } from "../src/mcp/dangerous";
import { toolDefinitions } from "../src/mcp/server";
import type { OwnerState } from "../src/owner/state";
import { FLEET_ENDPOINTS, FLEET_SCOPES } from "../src/tesla/endpoints";
import { SIGNED_COMMANDS } from "../src/tesla/vcp/protocol";
import { ENERGY_SITE_ID, FakeTesla } from "./helpers/fake-tesla";
import { connect, type ToolResult } from "./helpers/mcp";
import { DANGEROUS_TOOLS } from "./helpers/tools";
import COMMANDS from "./vectors/vcp-commands.json";

afterEach(() => {
  vi.restoreAllMocks();
});

const vector = (id: string) => {
  const found = COMMANDS.vectors.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`no vector ${id}`);
  return found.payload;
};

type JsonSchema = {
  type?: string;
  properties?: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
};

// Tools that never call Tesla with the owner's token.
const LOCAL_TOOLS = ["tesla_audit_recent", "tesla_auth_status"];

describe("every tool follows the same conventions", async () => {
  const { client } = await connect({ DANGEROUS_COMMANDS_ENABLED: "true" });
  const { tools } = await client.listTools();
  await client.close();
  const definitions = toolDefinitions({} as never);

  it("has unique snake_case tesla_ names", () => {
    const names = tools.map((tool) => tool.name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(name).toMatch(/^tesla_[a-z0-9]+(_[a-z0-9]+)*$/);
    expect(names.length).toBe(definitions.length);
  });

  it("rejects unknown arguments and gates every change behind confirm and dryRun", () => {
    for (const tool of tools) {
      const schema = tool.inputSchema as JsonSchema;
      const properties = Object.keys(schema.properties ?? {});
      expect(schema.additionalProperties, tool.name).toBe(false);
      const mutates = tool.annotations?.readOnlyHint === false;
      expect(properties.includes("confirm"), tool.name).toBe(mutates);
      expect(properties.includes("dryRun"), tool.name).toBe(mutates);
      // confirm is checked by the gate, so a missing confirm is refused
      // (and audited) rather than rejected by the schema.
      expect(schema.required ?? [], tool.name).not.toContain("confirm");
      if (mutates) expect(tool.description, tool.name).toMatch(/confirm/);
    }
  });

  it("addresses vehicles with vehicle_id and energy sites with energy_site_id", () => {
    for (const spec of CATALOG) {
      const schema = tools.find((tool) => tool.name === spec.name)?.inputSchema as JsonSchema;
      const properties = Object.keys(schema.properties ?? {});
      const target = spec.kind === "signed" ? "vehicle" : FLEET_ENDPOINTS[spec.endpoint].target;
      expect(properties.includes("vehicle_id"), spec.name).toBe(target === "vehicle");
      expect(properties.includes("energy_site_id"), spec.name).toBe(target === "energy_site");
      if (target === "energy_site") expect(spec.name).toMatch(/^tesla_energy_/);
      if (target === "account") expect(spec.name).toMatch(/^tesla_account_/);
    }
  });

  it("names the Tesla scope it needs, from Tesla's scope list", () => {
    for (const definition of definitions) {
      if (LOCAL_TOOLS.includes(definition.name)) {
        expect(definition.scopes, definition.name).toBeUndefined();
        continue;
      }
      expect(definition.scopes, definition.name).toBeDefined();
      for (const scope of definition.scopes?.anyOf ?? []) expect(FLEET_SCOPES).toContain(scope);
      expect(definition.description, definition.name).toMatch(/Tesla scope: [a-z_]+/);
    }
  });

  it("reaches every signed command and every Fleet endpoint", () => {
    const commands = new Set(CATALOG.flatMap((spec) => (spec.kind === "signed" ? [spec.command] : [])));
    commands.add("door_lock"); // tesla_lock
    commands.add("ping"); // tesla_vehicle_ping
    expect([...commands].sort()).toEqual(Object.keys(SIGNED_COMMANDS).sort());
    const endpoints = new Set(CATALOG.flatMap((spec) => (spec.kind === "endpoint" ? [spec.endpoint] : [])));
    expect([...endpoints].sort()).toEqual(Object.keys(FLEET_ENDPOINTS).sort());
  });

  it("tags a tool dangerous exactly when the command or endpoint underneath is", () => {
    for (const spec of CATALOG) {
      const expected =
        spec.kind === "signed"
          ? dangerousSignedCommand(spec.command, spec.params ? spec.params({}) : {})
          : (FLEET_ENDPOINTS[spec.endpoint] as { dangerousAction?: string }).dangerousAction;
      expect(spec.dangerousAction, spec.name).toBe(expected);
    }
    const tagged = definitions.filter((definition) => definition.dangerousAction).map((definition) => definition.name);
    expect(tagged.sort()).toEqual(DANGEROUS_TOOLS);
    const used = new Set(definitions.map((definition) => definition.dangerousAction).filter(Boolean));
    expect([...used].sort()).toEqual([...DANGEROUS_ACTIONS].sort());
  });

  it("marks no dangerous or state-changing tool read-only", () => {
    for (const tool of tools) {
      if (DANGEROUS_TOOLS.includes(tool.name)) expect(tool.annotations?.readOnlyHint, tool.name).toBe(false);
    }
  });
});

describe("signed vehicle commands", () => {
  it("signs an infotainment command with Tesla's exact payload when confirmed", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client, owner } = await connect();
    const result = (await client.callTool({
      name: "tesla_charge_set_limit",
      arguments: { percent: 80, confirm: true },
    })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ summary: "The charge limit is 80%.", vehicleId: tesla.vehicleId });
    expect(tesla.car.received).toEqual([{ domain: 3, payload: vector("set_charge_limit_80") }]);
    const [latest] = await owner.auditRecent(1);
    expect(latest).toMatchObject({ action: "set_charge_limit", outcome: "ok", vehicleId: tesla.vehicleId });
    await client.close();
  });

  it("sends structured parameters, such as several seat heaters", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({
      name: "tesla_seat_heater_set",
      arguments: { seats: [{ seat: "front_left", level: "high" }], confirm: true },
    })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(tesla.car.received.map((entry) => entry.payload)).toEqual([vector("remote_seat_heater_front_left_high")]);
    await client.close();
  });

  it("refuses without confirm, describes with dryRun, and sends nothing either way", async () => {
    const tesla = new FakeTesla();
    const fetchSpy = tesla.install();
    const { client, owner } = await connect();
    const refused = (await client.callTool({ name: "tesla_climate_start", arguments: {} })) as ToolResult;
    expect(refused.structuredContent).toMatchObject({ error: "confirmation_required" });
    expect(String(refused.structuredContent?.summary)).toMatch(/turn on climate control/);
    const dry = (await client.callTool({
      name: "tesla_charge_set_limit",
      arguments: { percent: 90, confirm: true, dryRun: true },
    })) as ToolResult;
    expect(dry.structuredContent).toMatchObject({ dryRun: true, action: "set_charge_limit" });
    expect(String(dry.structuredContent?.summary)).toMatch(/90%.*Nothing was sent to Tesla/);
    expect(fetchSpy).not.toHaveBeenCalled();
    const audit = await owner.auditRecent(5);
    expect(audit.map((row) => [row.action, row.outcome, row.detail])).toEqual([
      ["set_charge_limit", "ok", "dry_run"],
      ["auto_conditioning_start", "denied", "confirm_required"],
    ]);
    await client.close();
  });

  it("rejects out-of-range and unknown arguments before contacting Tesla", async () => {
    const tesla = new FakeTesla();
    const fetchSpy = tesla.install();
    const { client } = await connect();
    for (const [name, args] of [
      ["tesla_charge_set_limit", { percent: 101, confirm: true }],
      ["tesla_charge_set_limit", { percent: "80", confirm: true }],
      ["tesla_charge_set_limit", { percent: 80, confirm: true, force: true }],
      ["tesla_climate_set_temperatures", { driver_temp_celsius: 40, passenger_temp_celsius: 20, confirm: true }],
      ["tesla_seat_heater_set", { seats: [{ seat: "roof", level: "high" }], confirm: true }],
      [
        "tesla_charge_schedule_add",
        { days_of_week: ["funday"], start_enabled: true, end_enabled: false, latitude: 0, longitude: 0, confirm: true },
      ],
      ["tesla_vehicle_set_name", { name: "a\nb", confirm: true }],
      ["tesla_vehicle_data", { endpoints: ["everything"] }],
      ["tesla_vehicle_data", { endpoints: [] }],
      ["tesla_energy_set_backup_reserve", { percent: 120, confirm: true }],
      ["tesla_energy_history", { period: "day", start_date: "yesterday" }],
      ["tesla_vehicle_status", { vehicle_id: "../../users/me" }],
    ] as const) {
      const result = (await client.callTool({ name, arguments: args })) as ToolResult;
      expect(result.isError, `${name} ${JSON.stringify(args)}`).toBe(true);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    await client.close();
  });

  it("checks parameters a schema cannot express before signing anything", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    // start_enabled without start_time_minutes.
    const result = (await client.callTool({
      name: "tesla_charge_schedule_add",
      arguments: {
        days_of_week: ["monday"],
        start_enabled: true,
        end_enabled: false,
        latitude: 1,
        longitude: 2,
        confirm: true,
      },
    })) as ToolResult;
    expect(result.structuredContent).toMatchObject({ error: "invalid_request" });
    expect(tesla.car.received).toEqual([]);
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/signed_command"))).toBe(false);
    await client.close();
  });

  it("passes on the car's own reason when it refuses a command", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "carserver_error", reason: "is_charging" }];
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({ name: "tesla_charge_start", arguments: { confirm: true } })) as ToolResult;
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: "command_failed",
      reason: "command_rejected",
      carReason: "is_charging",
    });
    await client.close();
  });

  it("does not trust an unencrypted infotainment reply", async () => {
    const tesla = new FakeTesla();
    tesla.car.behaviors = [{ kind: "plaintext_ok" }];
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({ name: "tesla_honk_horn", arguments: { confirm: true } })) as ToolResult;
    expect(result.structuredContent).toMatchObject({ error: "command_failed", reason: "status_unknown" });
    await client.close();
  });

  it("never wakes an asleep car for a command; it says to wake it", async () => {
    const tesla = new FakeTesla();
    tesla.state = "asleep";
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({ name: "tesla_flash_lights", arguments: { confirm: true } })) as ToolResult;
    expect(result.structuredContent).toMatchObject({ error: "vehicle_asleep" });
    expect(String(result.structuredContent?.summary)).toMatch(/tesla_wake/);
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/wake_up"))).toBe(false);
    await client.close();
  });

  it("pings without confirm and without changing anything", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({ name: "tesla_vehicle_ping", arguments: {} })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(tesla.car.received).toEqual([{ domain: 3, payload: vector("ping") }]);
    await client.close();
  });
});

describe("dangerous commands", () => {
  it("are refused by OwnerState too, even when called directly", async () => {
    const tesla = new FakeTesla();
    const fetchSpy = tesla.install();
    const { owner, client } = await connect();
    await client.close();
    for (const call of [
      owner.signedVehicleCommand({ command: "door_unlock" }),
      owner.signedVehicleCommand({ command: "set_sentry_mode", params: { on: false } }),
      owner.signedVehicleCommand({ command: "set_valet_mode", params: { on: true, pin: "1234" } }),
      owner.fleetEndpoint("share_invite_create"),
    ]) {
      expect(await call).toMatchObject({ ok: false, error: { code: "dangerous_disabled" } });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    // Turning Sentry Mode on is not dangerous.
    expect(await owner.signedVehicleCommand({ command: "set_sentry_mode", params: { on: true } })).toMatchObject({
      ok: true,
    });
  });

  it('work once DANGEROUS_COMMANDS_ENABLED is "true"', async () => {
    const tesla = new FakeTesla();
    tesla.car.locked = true;
    tesla.install();
    const { client, owner } = await connect({ DANGEROUS_COMMANDS_ENABLED: "true" });
    const refused = (await client.callTool({ name: "tesla_unlock", arguments: {} })) as ToolResult;
    expect(refused.structuredContent).toMatchObject({ error: "confirmation_required" });
    expect(tesla.car.locked).toBe(true);
    // The override above reaches the MCP handler only; OwnerState checks its
    // own binding (the same one in production), so enable it there too.
    const blocked = (await client.callTool({ name: "tesla_unlock", arguments: { confirm: true } })) as ToolResult;
    expect(blocked.structuredContent).toMatchObject({ error: "dangerous_disabled" });
    await runInDurableObject(owner, (instance: OwnerState) => {
      Object.assign(instance, { env: { ...env, DANGEROUS_COMMANDS_ENABLED: "true" } });
    });
    const result = (await client.callTool({ name: "tesla_unlock", arguments: { confirm: true } })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(tesla.car.locked).toBe(false);
    expect(tesla.car.received).toEqual([{ domain: 2, payload: vector("door_unlock") }]);
    await client.close();
  });
});

describe("Fleet REST tools", () => {
  it("asks vehicle_data for exactly the named categories", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({
      name: "tesla_vehicle_data",
      arguments: { endpoints: ["charge_state", "location_data"] },
    })) as ToolResult;
    expect(result.isError).toBeFalsy();
    const request = tesla.fleetRequests.find((entry) => entry.path.endsWith("/vehicle_data"));
    expect(request?.search).toBe("?endpoints=charge_state%3Blocation_data");
    expect(result.structuredContent?.data).toMatchObject({ charge_state: { battery_level: 76 } });
    await client.close();
  });

  it("reads cached data from an asleep car without waking it, and live data not at all", async () => {
    const tesla = new FakeTesla();
    tesla.state = "asleep";
    tesla.install();
    const { client } = await connect();
    const cached = (await client.callTool({ name: "tesla_vehicle_data_cached", arguments: {} })) as ToolResult;
    expect(cached.isError).toBeFalsy();
    expect(cached.structuredContent?.data).toEqual({ endpoint: "vehicle_data_cached" });
    for (const name of ["tesla_vehicle_nearby_charging_sites", "tesla_vehicle_release_notes"]) {
      const live = (await client.callTool({ name, arguments: {} })) as ToolResult;
      expect(live.structuredContent, name).toMatchObject({ error: "vehicle_asleep" });
    }
    expect(tesla.fleetRequests.some((request) => request.path.endsWith("/wake_up"))).toBe(false);
    await client.close();
  });

  it("names the missing scope when Tesla answers 403", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    tesla.fleetOverrides.push({ path: /\/vehicle_data$/, status: 403 });
    tesla.fleetOverrides.push({ path: /\/live_status$/, status: 403 });
    const { client } = await connect();
    const location = (await client.callTool({
      name: "tesla_vehicle_data",
      arguments: { endpoints: ["location_data"] },
    })) as ToolResult;
    expect(location.structuredContent).toMatchObject({ error: "forbidden" });
    expect(String(location.structuredContent?.summary)).toMatch(/vehicle_device_data, plus vehicle_location/);
    const energy = (await client.callTool({ name: "tesla_energy_live_status", arguments: {} })) as ToolResult;
    expect(String(energy.structuredContent?.summary)).toMatch(/energy_device_data/);
    await client.close();
  });

  it("queries dx endpoints by VIN and passes charging-history filters", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    await client.callTool({ name: "tesla_vehicle_warranty", arguments: {} });
    await client.callTool({
      name: "tesla_vehicle_charging_history",
      arguments: { start_time: "2026-01-01T00:00:00-08:00", page_size: 10, sort_order: "DESC" },
    });
    const [warranty, history] = tesla.fleetRequests.filter((request) => request.path.startsWith("/api/1/dx/"));
    expect(warranty?.search).toBe(`?vin=${tesla.vin}`);
    expect(new URLSearchParams(history?.search)).toEqual(
      new URLSearchParams({
        vin: tesla.vin,
        startTime: "2026-01-01T00:00:00-08:00",
        pageSize: "10",
        sortOrder: "DESC",
      }),
    );
    await client.close();
  });

  it("sends REST-only vehicle commands with Tesla's body and reports a refusal", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const sent = (await client.callTool({
      name: "tesla_navigation_send_coordinates",
      arguments: { latitude: 37.5, longitude: -122.25, confirm: true },
    })) as ToolResult;
    expect(sent.isError).toBeFalsy();
    const request = tesla.fleetRequests.find((entry) => entry.path.endsWith("/command/navigation_gps_request"));
    expect(JSON.parse(request?.body ?? "")).toEqual({ lat: 37.5, lon: -122.25, order: 0 });

    tesla.commandResult = { result: false, reason: "not_supported" };
    const refused = (await client.callTool({
      name: "tesla_play_sound",
      arguments: { sound: "locate_ping", confirm: true },
    })) as ToolResult;
    expect(refused.structuredContent).toMatchObject({ error: "command_failed", carReason: "not_supported" });
    const boombox = tesla.fleetRequests.find((entry) => entry.path.endsWith("/command/remote_boombox"));
    expect(JSON.parse(boombox?.body ?? "")).toEqual({ sound: 2000 });
    await client.close();
  });

  it("removes a driver only with confirm", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const refused = (await client.callTool({
      name: "tesla_vehicle_driver_remove",
      arguments: { share_user_id: "42" },
    })) as ToolResult;
    expect(refused.structuredContent).toMatchObject({ error: "confirmation_required" });
    expect(tesla.fleetRequests.some((request) => request.method === "DELETE")).toBe(false);
    const removed = (await client.callTool({
      name: "tesla_vehicle_driver_remove",
      arguments: { share_user_id: "42", confirm: true },
    })) as ToolResult;
    expect(removed.isError).toBeFalsy();
    const request = tesla.fleetRequests.find((entry) => entry.method === "DELETE");
    expect([request?.path, request?.search]).toEqual([
      `/api/1/vehicles/${tesla.vehicleId}/drivers`,
      "?share_user_id=42",
    ]);
    await client.close();
  });
});

describe("energy tools", () => {
  it("finds the account's only energy site and keeps its id exact", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({ name: "tesla_energy_live_status", arguments: {} })) as ToolResult;
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ energySiteId: ENERGY_SITE_ID, data: { endpoint: "live_status" } });
    expect(tesla.fleetRequests.map((request) => request.path)).toContain(
      `/api/1/energy_sites/${ENERGY_SITE_ID}/live_status`,
    );
    const products = (await client.callTool({ name: "tesla_account_products", arguments: {} })) as ToolResult;
    expect(JSON.stringify(products.structuredContent?.data)).toContain(`"energy_site_id":"${ENERGY_SITE_ID}"`);
    await client.close();
  });

  it("changes a setting only with confirm, with Tesla's body, and audits it", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client, owner } = await connect();
    const refused = (await client.callTool({
      name: "tesla_energy_set_backup_reserve",
      arguments: { percent: 20 },
    })) as ToolResult;
    expect(refused.structuredContent).toMatchObject({ error: "confirmation_required" });
    const dry = (await client.callTool({
      name: "tesla_energy_set_backup_reserve",
      arguments: { percent: 20, confirm: true, dryRun: true },
    })) as ToolResult;
    expect(dry.structuredContent).toMatchObject({ dryRun: true });
    expect(tesla.fleetRequests).toHaveLength(0);

    const set = (await client.callTool({
      name: "tesla_energy_set_backup_reserve",
      arguments: { percent: 20, confirm: true },
    })) as ToolResult;
    expect(set.structuredContent).toMatchObject({
      summary: "The backup reserve is 20%.",
      energySiteId: ENERGY_SITE_ID,
    });
    const write = tesla.fleetRequests.find((request) => request.method === "POST");
    expect(write?.path).toBe(`/api/1/energy_sites/${ENERGY_SITE_ID}/backup`);
    expect(JSON.parse(write?.body ?? "")).toEqual({ backup_reserve_percent: 20 });
    const [latest] = await owner.auditRecent(1);
    expect(latest).toMatchObject({
      action: "energy_set_backup_reserve",
      outcome: "ok",
      detail: `site ${ENERGY_SITE_ID}`,
    });
    await client.close();
  });

  it("sends each energy setting in Tesla's shape", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const calls = [
      [
        "tesla_energy_set_operation_mode",
        { mode: "self_consumption" },
        "/operation",
        { default_real_mode: "self_consumption" },
      ],
      ["tesla_energy_set_storm_watch", { enabled: false }, "/storm_mode", { enabled: false }],
      [
        "tesla_energy_set_grid_import_export",
        { customer_preferred_export_rule: "pv_only" },
        "/grid_import_export",
        { customer_preferred_export_rule: "pv_only" },
      ],
      [
        "tesla_energy_set_off_grid_vehicle_charging_reserve",
        { percent: 40 },
        "/off_grid_vehicle_charging_reserve",
        { off_grid_vehicle_charging_reserve_percent: 40 },
      ],
      [
        "tesla_energy_set_time_of_use",
        { tariff_content_v2: { version: 1, seasons: {} } },
        "/time_of_use_settings",
        { tou_settings: { tariff_content_v2: { version: 1, seasons: {} } } },
      ],
    ] as const;
    for (const [name, args, suffix, body] of calls) {
      const result = (await client.callTool({ name, arguments: { ...args, confirm: true } })) as ToolResult;
      expect(result.isError, name).toBeFalsy();
      const request = tesla.fleetRequests.find((entry) => entry.path.endsWith(suffix));
      expect(JSON.parse(request?.body ?? ""), name).toEqual(body);
    }
    const empty = (await client.callTool({
      name: "tesla_energy_set_grid_import_export",
      arguments: { confirm: true },
    })) as ToolResult;
    expect(empty.structuredContent).toMatchObject({ error: "invalid_request" });
    await client.close();
  });

  it("refuses a site that is not on the account without writing anything", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    const result = (await client.callTool({
      name: "tesla_energy_set_storm_watch",
      arguments: { energy_site_id: "123", enabled: true, confirm: true },
    })) as ToolResult;
    expect(result.structuredContent).toMatchObject({ error: "energy_site_not_found" });
    expect(tesla.fleetRequests.some((request) => request.method === "POST")).toBe(false);
    await client.close();
  });

  it("passes history ranges through as Tesla's query", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    await client.callTool({
      name: "tesla_energy_history",
      arguments: { period: "week", start_date: "2026-01-01T00:00:00Z", time_zone: "America/Los_Angeles" },
    });
    const request = tesla.fleetRequests.find((entry) => entry.path.endsWith("/calendar_history"));
    expect(new URLSearchParams(request?.search)).toEqual(
      new URLSearchParams({
        kind: "energy",
        period: "week",
        start_date: "2026-01-01T00:00:00Z",
        time_zone: "America/Los_Angeles",
      }),
    );
    await client.close();
  });
});

describe("account tools", () => {
  it("reads the user endpoints", async () => {
    const tesla = new FakeTesla();
    tesla.install();
    const { client } = await connect();
    for (const [name, path] of [
      ["tesla_account_me", "/api/1/users/me"],
      ["tesla_account_region", "/api/1/users/region"],
      ["tesla_account_orders", "/api/1/users/orders"],
      ["tesla_account_feature_config", "/api/1/users/feature_config"],
    ] as const) {
      const result = (await client.callTool({ name, arguments: {} })) as ToolResult;
      expect(result.structuredContent?.data, name).toEqual({ endpoint: path });
    }
    await client.close();
  });
});
