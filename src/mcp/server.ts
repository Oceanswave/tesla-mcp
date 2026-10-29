import { type CallToolResult, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import type { Env } from "../env";
import type { AuditRow, EndpointSuccess, OwnerFailure, OwnerResult, OwnerState } from "../owner/state";
import {
  describeScopes,
  endpointScopes,
  FLEET_ENDPOINTS,
  type ScopeRequirement,
  signedCommandScopes,
} from "../tesla/endpoints";
import { CATALOG, PING_TOOL, summaryText, type ToolSpec } from "./catalog";
import { type DangerousAction, dangerousCommandsEnabled, gateTools } from "./dangerous";

export const SERVER_VERSION = "0.1.0";

type OwnerStub = DurableObjectStub<OwnerState>;

type ToolDefinition = {
  name: string;
  description: string;
  inputSchema: z.ZodObject;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
  /** Set for tools behind the dangerous-command gate. */
  dangerousAction?: DangerousAction;
  /** Tesla OAuth scopes the call needs; absent for tools that never call
   * Tesla with the owner's token on their own behalf. */
  scopes?: ScopeRequirement;
  handler: (input: Record<string, unknown>) => Promise<CallToolResult>;
};

const READ = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const COMMAND = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };
const READ_SCOPES: ScopeRequirement = { anyOf: ["vehicle_device_data"] };
const COMMAND_SCOPES: ScopeRequirement = { anyOf: ["vehicle_cmds"] };

const vehicleId = z
  .string()
  .regex(/^(?:\d{1,20}|[A-HJ-NPR-Za-hj-npr-z0-9]{17})$/)
  .optional()
  .describe(
    "The car's id or VIN from tesla_vehicles_list. Leave out to use the default car (DEFAULT_VIN) or the account's only car.",
  );
const confirm = z
  .boolean()
  .optional()
  .describe("Must be true. Only set it after the user has clearly asked for this action.");
const dryRun = z
  .boolean()
  .optional()
  .describe("When true, check the request and describe what would happen without contacting the car.");
const energySiteId = z
  .string()
  .regex(/^\d{1,20}$/)
  .optional()
  .describe("Tesla energy_site_id from tesla_account_products. Leave out when the account has one energy site.");

function result(value: Record<string, unknown>, isError = false): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value,
    ...(isError ? { isError: true } : {}),
  };
}

function failure(error: OwnerFailure | { code: "internal_error"; message: string }): CallToolResult {
  return result(
    {
      summary: error.message,
      error: error.code,
      ...("reason" in error && error.reason ? { reason: error.reason } : {}),
      ...("carReason" in error && error.carReason ? { carReason: error.carReason } : {}),
    },
    true,
  );
}

/** Every state-changing tool goes through this gate: no confirm, no action;
 * dryRun describes and sends nothing. Both outcomes are audited. */
async function commandGate(
  owner: OwnerStub,
  action: string,
  input: Record<string, unknown>,
  describe: string,
  run: () => Promise<CallToolResult>,
): Promise<CallToolResult> {
  const requested = typeof input.vehicle_id === "string" ? input.vehicle_id : null;
  // The audit log keeps Fleet ids only; a VIN stays out of it.
  const vehicle = requested && /^\d+$/.test(requested) ? requested : null;
  if (input.confirm !== true) {
    await owner.recordAudit({
      source: "tool",
      action,
      vehicleId: vehicle,
      outcome: "denied",
      detail: "confirm_required",
    });
    return result(
      {
        summary: `Not done. To ${describe}, ask the user to confirm and call again with confirm set to true.`,
        error: "confirmation_required",
      },
      true,
    );
  }
  if (input.dryRun === true) {
    await owner.recordAudit({ source: "tool", action, vehicleId: vehicle, outcome: "ok", detail: "dry_run" });
    return result({
      summary: `Dry run: this would ${describe}. Nothing was sent to Tesla.`,
      dryRun: true,
      action,
      vehicleId: requested ?? "default",
      ...(typeof input.energy_site_id === "string" ? { energySiteId: input.energy_site_id } : {}),
    });
  }
  return run();
}

/** The inputs a spec adds beyond the shared ones, as command parameters. */
function specParams(spec: ToolSpec, input: Record<string, unknown>): Record<string, unknown> {
  if (spec.params) return spec.params(input);
  const params: Record<string, unknown> = {};
  for (const key of Object.keys(spec.input ?? {})) if (input[key] !== undefined) params[key] = input[key];
  return params;
}

function withScopes(description: string, scopes: ScopeRequirement): string {
  return `${description} Tesla scope: ${describeScopes(scopes)}.`;
}

/** Turn a catalog spec into a tool: shared inputs, annotations, and, for
 * anything that changes a vehicle or energy product, the confirmation gate. */
function catalogTool(owner: OwnerStub, spec: ToolSpec): ToolDefinition {
  const target = spec.kind === "signed" ? "vehicle" : FLEET_ENDPOINTS[spec.endpoint].target;
  const mutates = spec.kind === "signed" || FLEET_ENDPOINTS[spec.endpoint].mutates;
  const scopes = spec.kind === "signed" ? signedCommandScopes(spec.command) : endpointScopes(spec.endpoint, {});
  const inputSchema = z
    .object({
      ...(target === "vehicle" ? { vehicle_id: vehicleId } : {}),
      ...(target === "energy_site" ? { energy_site_id: energySiteId } : {}),
      ...spec.input,
      ...(mutates ? { confirm, dryRun } : {}),
    })
    .strict();
  const annotations = mutates
    ? { ...COMMAND, destructiveHint: spec.destructive === true, idempotentHint: spec.idempotent !== false }
    : READ;
  const auditAction = spec.kind === "signed" ? spec.command : spec.endpoint;
  const where = (input: Record<string, unknown>) => ({
    vehicleId: input.vehicle_id as string | undefined,
    energySiteId: input.energy_site_id as string | undefined,
  });

  const run = async (input: Record<string, unknown>): Promise<CallToolResult> => {
    const params = specParams(spec, input);
    if (spec.kind === "signed") {
      const sent = await owner.signedVehicleCommand({
        command: spec.command,
        params,
        vehicleId: where(input).vehicleId,
      });
      if (!sent.ok) return failure(sent.error);
      return result({ summary: summaryText(spec.done, input), vehicleId: sent.data.vehicleId });
    }
    // The stub's mapped type cannot express `unknown` JSON; structured clone
    // returns exactly what OwnerState produced.
    const called = (await owner.fleetEndpoint(spec.endpoint, {
      ...where(input),
      params,
    })) as OwnerResult<EndpointSuccess>;
    if (!called.ok) return failure(called.error);
    const { data, vehicleId: resolvedVehicle, energySiteId: resolvedSite } = called.data;
    return result({
      summary: summaryText(spec.done, input),
      ...(resolvedVehicle ? { vehicleId: resolvedVehicle } : {}),
      ...(resolvedSite ? { energySiteId: resolvedSite } : {}),
      data: data ?? null,
    });
  };

  return {
    name: spec.name,
    description: withScopes(
      mutates ? `${spec.description} Requires confirm set to true after the user asks.` : spec.description,
      spec.kind === "endpoint" && spec.endpoint === "vehicle_data" ? { ...scopes, also: "vehicle_location" } : scopes,
    ).replace(", plus vehicle_location.", " (plus vehicle_location for location_data)."),
    inputSchema,
    annotations,
    ...(spec.dangerousAction ? { dangerousAction: spec.dangerousAction } : {}),
    scopes,
    handler: mutates
      ? (input) => {
          const action = spec.kind === "signed" ? spec.action : (spec.action ?? spec.name);
          return commandGate(owner, auditAction, input, summaryText(action, input), () => run(input));
        }
      : run,
  };
}

export function toolDefinitions(owner: OwnerStub): ToolDefinition[] {
  return [
    {
      name: "tesla_vehicles_list",
      description:
        "List the cars on the owner's Tesla account with their id, VIN, name, and whether each is online, asleep, or offline. Does not wake any car. Tesla scope: vehicle_device_data.",
      inputSchema: z.object({}).strict(),
      annotations: READ,
      scopes: READ_SCOPES,
      handler: async () => {
        const listed = await owner.listVehicles();
        if (!listed.ok) return failure(listed.error);
        const vehicles = listed.data.map((vehicle) => ({
          id: vehicle.id,
          vin: vehicle.vin,
          name: vehicle.displayName,
          state: vehicle.state,
        }));
        const summary = vehicles.length
          ? vehicles.map((vehicle) => `${vehicle.name ?? "Unnamed car"} is ${vehicle.state}`).join(". ")
          : "No cars on this account.";
        return result({ summary, vehicles });
      },
    },
    {
      name: "tesla_vehicle_status",
      description:
        "Get the car's current status: online or asleep, and when online whether it is locked, which doors, trunks, or windows are open, battery percent, range, charging state, inside and outside temperature, climate, Sentry Mode, and odometer. Never wakes the car; if it is asleep, says so. Tesla scope: vehicle_device_data.",
      inputSchema: z.object({ vehicle_id: vehicleId }).strict(),
      annotations: READ,
      scopes: READ_SCOPES,
      handler: async (input) => {
        const status = await owner.vehicleStatus(input.vehicle_id as string | undefined);
        if (!status.ok) return failure(status.error);
        const { vehicle, state, status: details } = status.data;
        const name = vehicle.displayName ?? "The car";
        let summary = `${name} is ${state}.`;
        if (details) {
          const parts = [
            details.locked === null ? null : details.locked ? "locked" : "unlocked",
            details.batteryPercent === null ? null : `battery ${details.batteryPercent}%`,
            details.chargingState ? `charging state ${details.chargingState}` : null,
          ].filter(Boolean);
          summary = `${name} is online${parts.length ? `, ${parts.join(", ")}` : ""}.`;
        } else if (state !== "online") {
          summary += " Status details need the car to be awake.";
        }
        return result({ summary, vehicle, state, status: details });
      },
    },
    {
      name: "tesla_wake",
      description:
        "Wake the car so it can report status or take commands. Requires confirm set to true after the user asks. Waking uses a little battery; the car usually comes online within 30 seconds. Tesla scope: vehicle_cmds.",
      inputSchema: z.object({ vehicle_id: vehicleId, confirm, dryRun }).strict(),
      annotations: COMMAND,
      scopes: COMMAND_SCOPES,
      handler: (input) =>
        commandGate(owner, "wake", input, "wake the car", async () => {
          const woke = await owner.wake({ vehicleId: input.vehicle_id as string | undefined });
          if (!woke.ok) return failure(woke.error);
          return result({
            summary:
              woke.data.state === "online"
                ? "The car is awake."
                : "Wake request sent. The car should be online in about 30 seconds.",
            vehicleId: woke.data.vehicleId,
            state: woke.data.state,
          });
        }),
    },
    {
      name: "tesla_lock",
      description:
        "Lock the car's doors with a signed command. Wakes the car if it is asleep, waits for it to come online, retries, and reads the lock state back; can take a few minutes when the car is asleep. Requires confirm set to true after the user asks. Locking an already locked car is fine. On failure, `reason` says why (for example pairing_required, wake_timeout, still_unlocked). Tesla scope: vehicle_cmds.",
      inputSchema: z.object({ vehicle_id: vehicleId, confirm, dryRun }).strict(),
      annotations: COMMAND,
      scopes: COMMAND_SCOPES,
      handler: (input) =>
        commandGate(owner, "lock", input, "lock the car", async () => {
          const locked = await owner.lock({ vehicleId: input.vehicle_id as string | undefined });
          if (!locked.ok) return failure(locked.error);
          const { detail, confirmed } = locked.data;
          let summary =
            detail === "already_locked"
              ? "The car was already locked."
              : detail === "locked_after_wake"
                ? "The car woke up and is now locked."
                : "The car is locked.";
          if (!confirmed) summary += " Tesla accepted the command, but the car's lock state could not be read back.";
          return result({
            summary,
            locked: true,
            confirmed,
            vehicleId: locked.data.vehicleId,
            detail,
            attempts: locked.data.attempts,
            woke: locked.data.woke,
          });
        }),
    },
    {
      name: "tesla_auth_status",
      description:
        "Report whether the server's Tesla sign-in works: authState is ok, reauth_required (Tesla rejected the sign-in; the owner must sign in again at /login), or not_configured. When ok, scopes lists the OAuth scopes the stored sign-in grants (null when unknown). Reads stored state only; never contacts Tesla or wakes the car.",
      inputSchema: z.object({}).strict(),
      annotations: { ...READ, openWorldHint: false },
      handler: async () => {
        const status = await owner.authStatus();
        return result({ summary: status.message ?? "Tesla sign-in is working.", ...status });
      },
    },
    {
      name: "tesla_audit_recent",
      description:
        "Show the most recent entries in the audit log of commands, wakes, and sign-in events, newest first.",
      inputSchema: z
        .object({
          limit: z.number().int().min(1).max(100).optional().describe("How many entries, 1 to 100. Default 20."),
        })
        .strict(),
      annotations: { ...READ, openWorldHint: false },
      handler: async (input) => {
        const rows: AuditRow[] = await owner.auditRecent((input.limit as number | undefined) ?? 20);
        const latest = rows[0];
        return result({
          summary: latest
            ? `${rows.length} entries. Latest: ${latest.action} ${latest.outcome} at ${latest.ts}.`
            : "The audit log is empty.",
          entries: rows,
        });
      },
    },
    {
      ...PING_TOOL,
      description: withScopes(PING_TOOL.description, signedCommandScopes("ping")),
      inputSchema: z.object({ vehicle_id: vehicleId }).strict(),
      annotations: READ,
      scopes: signedCommandScopes("ping"),
      handler: async (input) => {
        const pinged = await owner.signedVehicleCommand({
          command: "ping",
          vehicleId: input.vehicle_id as string | undefined,
        });
        if (!pinged.ok) return failure(pinged.error);
        return result({
          summary: "The car is online and accepted a signed command.",
          vehicleId: pinged.data.vehicleId,
        });
      },
    },
    ...CATALOG.map((spec) => catalogTool(owner, spec)),
  ];
}

export function createMcpServer(env: Env, owner: OwnerStub): McpServer {
  const server = new McpServer({ name: "tesla-mcp", version: SERVER_VERSION });
  for (const tool of gateTools(toolDefinitions(owner), dangerousCommandsEnabled(env))) {
    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: tool.inputSchema, annotations: tool.annotations },
      async (input: Record<string, unknown>) => {
        try {
          return await tool.handler(input);
        } catch (error) {
          // The class name only: messages can carry upstream text.
          console.error(`[tesla-mcp] ${tool.name} failed: ${error instanceof Error ? error.name : typeof error}`);
          return failure({
            code: "internal_error",
            message: "Something went wrong on the server. Nothing more was sent.",
          });
        }
      },
    );
  }
  return server;
}
