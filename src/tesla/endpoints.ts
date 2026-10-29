// The Fleet API REST endpoints this Worker calls, beyond the core list,
// vehicle, vehicle_data, and wake_up calls in fleet.ts.
//
// An explicit allowlist, like SIGNED_COMMANDS: every path is built here from
// a fixed template and checked parameters. Callers name an endpoint; they can
// never supply a path, method, or raw body.

import type { DangerousAction } from "../mcp/dangerous";

/** OAuth scopes Tesla defines for third-party tokens. */
export const FLEET_SCOPES = [
  "openid",
  "offline_access",
  "user_data",
  "vehicle_device_data",
  "vehicle_location",
  "vehicle_cmds",
  "vehicle_charging_cmds",
  "energy_device_data",
  "energy_cmds",
] as const;

export type FleetScope = (typeof FLEET_SCOPES)[number];

/** The scopes the self-hosting guide (README step 1) asks the app to request.
 * Documentation only: the Worker never asks for scopes itself (it refreshes
 * a token whose scopes were fixed at sign-in). */
export const SETUP_SCOPES = [
  "openid",
  "offline_access",
  "vehicle_device_data",
  "vehicle_cmds",
] as const satisfies readonly FleetScope[];

export const VEHICLE_DATA_ENDPOINTS = [
  "charge_state",
  "climate_state",
  "closures_state",
  "drive_state",
  "gui_settings",
  "location_data",
  "charge_schedule_data",
  "preconditioning_schedule_data",
  "vehicle_config",
  "vehicle_state",
  "vehicle_data_combo",
] as const;

export const CALENDAR_PERIODS = ["day", "week", "month", "year", "lifetime"] as const;
export const OPERATION_MODES = ["self_consumption", "autonomous"] as const;
export const EXPORT_RULES = ["pv_only", "battery_ok", "never"] as const;
export const BOOMBOX_SOUNDS = { fart: 0, locate_ping: 2000 } as const;

export type EndpointTarget = "vehicle" | "energy_site" | "account";

export type EndpointContext = {
  /** Fleet vehicle id, for vehicle endpoints. */
  vehicleId?: string;
  vin?: string;
  energySiteId?: string;
  params: Readonly<Record<string, unknown>>;
};

export type FleetRequest = {
  method: "GET" | "POST" | "DELETE";
  path: string;
  body?: Record<string, unknown>;
};

export type FleetEndpoint = {
  target: EndpointTarget;
  /** Any one of these scopes is enough (Tesla's per-endpoint scope lists). */
  scopes: readonly FleetScope[];
  /** True when the call changes a vehicle, energy product, or account. */
  mutates: boolean;
  /** A vehicle REST command: the response is { result, reason }. */
  vehicleCommand?: true;
  dangerousAction?: DangerousAction;
  build: (context: EndpointContext) => FleetRequest;
};

export class EndpointParamError extends Error {
  constructor(readonly param: string) {
    super(`invalid_param_${param}`);
    this.name = "EndpointParamError";
  }
}

const ID = /^\d{1,20}$/;

function id(value: string | undefined, name: string): string {
  if (!value || !ID.test(value)) throw new EndpointParamError(name);
  return value;
}

function vehiclePath(context: EndpointContext, suffix = ""): string {
  return `/api/1/vehicles/${id(context.vehicleId, "vehicle_id")}${suffix}`;
}

function sitePath(context: EndpointContext, suffix: string): string {
  return `/api/1/energy_sites/${id(context.energySiteId, "energy_site_id")}${suffix}`;
}

function vin(context: EndpointContext): string {
  const value = context.vin;
  if (!value || !/^[A-HJ-NPR-Z0-9]{17}$/.test(value)) throw new EndpointParamError("vin");
  return value;
}

function query(path: string, values: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) if (value !== undefined) search.set(key, String(value));
  const text = search.toString();
  return text ? `${path}?${text}` : path;
}

function optionalString(params: EndpointContext["params"], name: string, pattern: RegExp): string | undefined {
  const value = params[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !pattern.test(value)) throw new EndpointParamError(name);
  return value;
}

function requiredString(params: EndpointContext["params"], name: string, pattern: RegExp): string {
  const value = optionalString(params, name, pattern);
  if (value === undefined) throw new EndpointParamError(name);
  return value;
}

function optionalInteger(
  params: EndpointContext["params"],
  name: string,
  min: number,
  max: number,
): number | undefined {
  const value = params[name];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new EndpointParamError(name);
  }
  return value;
}

function requiredInteger(params: EndpointContext["params"], name: string, min: number, max: number): number {
  const value = optionalInteger(params, name, min, max);
  if (value === undefined) throw new EndpointParamError(name);
  return value;
}

function requiredNumber(params: EndpointContext["params"], name: string, min: number, max: number): number {
  const value = params[name];
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
    throw new EndpointParamError(name);
  }
  return value;
}

function oneOf<T extends string>(params: EndpointContext["params"], name: string, options: readonly T[]): T {
  const value = params[name];
  if (typeof value !== "string" || !(options as readonly string[]).includes(value)) throw new EndpointParamError(name);
  return value as T;
}

function bool(params: EndpointContext["params"], name: string): boolean {
  const value = params[name];
  if (typeof value !== "boolean") throw new EndpointParamError(name);
  return value;
}

// RFC 3339 timestamps with an explicit offset, as Tesla's history endpoints
// expect (for example 2026-01-01T00:00:00-08:00).
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/;
const TIME_ZONE = /^[A-Za-z]+(?:[/_+-][A-Za-z0-9]+)*$/;

function calendarHistory(kind: "energy" | "backup") {
  return (context: EndpointContext): FleetRequest => ({
    method: "GET",
    path: query(sitePath(context, "/calendar_history"), {
      kind,
      period: kind === "energy" ? oneOf(context.params, "period", CALENDAR_PERIODS) : undefined,
      start_date: optionalString(context.params, "start_date", RFC3339),
      end_date: optionalString(context.params, "end_date", RFC3339),
      time_zone: optionalString(context.params, "time_zone", TIME_ZONE),
    }),
  });
}

function vehicleData(context: EndpointContext): FleetRequest {
  const endpoints = context.params.endpoints;
  if (
    !Array.isArray(endpoints) ||
    !endpoints.length ||
    endpoints.some((name) => !(VEHICLE_DATA_ENDPOINTS as readonly unknown[]).includes(name)) ||
    new Set(endpoints).size !== endpoints.length
  ) {
    throw new EndpointParamError("endpoints");
  }
  return { method: "GET", path: query(vehiclePath(context, "/vehicle_data"), { endpoints: endpoints.join(";") }) };
}

function get(target: EndpointTarget, scopes: readonly FleetScope[], path: (context: EndpointContext) => string) {
  return {
    target,
    scopes,
    mutates: false,
    build: (context: EndpointContext) => ({ method: "GET" as const, path: path(context) }),
  };
}

function vehicleCommand(
  name: string,
  body: (params: EndpointContext["params"]) => Record<string, unknown>,
): FleetEndpoint {
  return {
    target: "vehicle",
    scopes: ["vehicle_cmds"],
    mutates: true,
    vehicleCommand: true,
    build: (context) => ({
      method: "POST",
      path: vehiclePath(context, `/command/${name}`),
      body: body(context.params),
    }),
  };
}

function energyWrite(
  suffix: string,
  body: (params: EndpointContext["params"]) => Record<string, unknown>,
): FleetEndpoint {
  return {
    target: "energy_site",
    scopes: ["energy_cmds"],
    mutates: true,
    build: (context) => ({ method: "POST", path: sitePath(context, suffix), body: body(context.params) }),
  };
}

const VEHICLE_READ: readonly FleetScope[] = ["vehicle_device_data"];
const ENERGY_READ: readonly FleetScope[] = ["energy_device_data"];
const USER_READ: readonly FleetScope[] = ["user_data"];
// A Google Maps place id ("ChIJ..."), as Tesla's waypoint and share flows use.
const PLACE_ID = /^[A-Za-z0-9_-]{10,256}$/;
const MAX_TARIFF_BYTES = 32_768;

export const FLEET_ENDPOINTS = {
  // Vehicle data. None of these wake the car: Fleet answers 408 while it is
  // asleep, and vehicle_data_cached never contacts it.
  vehicle_data: {
    target: "vehicle",
    // location_data additionally needs vehicle_location.
    scopes: VEHICLE_READ,
    mutates: false,
    build: vehicleData,
  },
  vehicle_data_cached: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/vehicle_data_cached")),
  mobile_enabled: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/mobile_enabled")),
  nearby_charging_sites: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/nearby_charging_sites")),
  recent_alerts: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/recent_alerts")),
  release_notes: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/release_notes")),
  service_data: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/service_data")),
  drivers: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/drivers")),
  share_invites: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/invitations")),
  fleet_telemetry_config: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/fleet_telemetry_config")),
  fleet_telemetry_errors: get("vehicle", VEHICLE_READ, (context) => vehiclePath(context, "/fleet_telemetry_errors")),
  // A POST that only reads: Tesla takes the VINs in the body.
  fleet_status: {
    target: "vehicle",
    scopes: VEHICLE_READ,
    mutates: false,
    build: (context) => ({ method: "POST", path: "/api/1/vehicles/fleet_status", body: { vins: [vin(context)] } }),
  },
  vehicle_options: get("vehicle", VEHICLE_READ, (context) =>
    query("/api/1/dx/vehicles/options", { vin: vin(context) }),
  ),
  warranty_details: get("vehicle", VEHICLE_READ, (context) =>
    query("/api/1/dx/warranty/details", { vin: vin(context) }),
  ),
  eligible_subscriptions: get("vehicle", VEHICLE_READ, (context) =>
    query("/api/1/dx/vehicles/subscriptions/eligibility", { vin: vin(context) }),
  ),
  eligible_upgrades: get("vehicle", VEHICLE_READ, (context) =>
    query("/api/1/dx/vehicles/upgrades/eligibility", { vin: vin(context) }),
  ),
  charging_history: {
    target: "vehicle",
    scopes: ["vehicle_charging_cmds"],
    mutates: false,
    build: (context) => ({
      method: "GET",
      path: query("/api/1/dx/charging/history", {
        vin: vin(context),
        startTime: optionalString(context.params, "start_time", RFC3339),
        endTime: optionalString(context.params, "end_time", RFC3339),
        pageNo: optionalInteger(context.params, "page", 1, 10_000),
        pageSize: optionalInteger(context.params, "page_size", 1, 50),
        sortBy: optionalString(context.params, "sort_by", /^(chargeStartDateTime|totalEnergyDispensed)$/),
        sortOrder: optionalString(context.params, "sort_order", /^(ASC|DESC)$/),
      }),
    }),
  },

  // Vehicle access and configuration changes.
  driver_remove: {
    target: "vehicle",
    scopes: ["vehicle_cmds"],
    mutates: true,
    build: (context) => ({
      method: "DELETE",
      path: query(vehiclePath(context, "/drivers"), {
        share_user_id: optionalString(context.params, "share_user_id", ID),
      }),
    }),
  },
  share_invite_create: {
    target: "vehicle",
    scopes: ["vehicle_cmds"],
    mutates: true,
    dangerousAction: "share_access",
    build: (context) => ({ method: "POST", path: vehiclePath(context, "/invitations"), body: {} }),
  },
  share_invite_revoke: {
    target: "vehicle",
    scopes: ["vehicle_cmds"],
    mutates: true,
    build: (context) => ({
      method: "POST",
      path: vehiclePath(context, `/invitations/${requiredString(context.params, "invite_id", ID)}/revoke`),
      body: {},
    }),
  },
  fleet_telemetry_config_delete: {
    target: "vehicle",
    scopes: VEHICLE_READ,
    mutates: true,
    build: (context) => ({ method: "DELETE", path: vehiclePath(context, "/fleet_telemetry_config") }),
  },

  // Vehicle commands Tesla's vehicle-command library cannot sign (no Vehicle
  // Command Protocol message exists for them); Fleet relays them itself.
  navigation_request: vehicleCommand("navigation_request", (params) => ({
    type: "share_ext_content_raw",
    locale: "en-US",
    timestamp_ms: String(Date.now()),
    value: { "android.intent.extra.TEXT": requiredString(params, "destination", /^[^\u0000-\u001f\u007f]{1,512}$/) },
  })),
  navigation_gps_request: vehicleCommand("navigation_gps_request", (params) => ({
    lat: requiredNumber(params, "latitude", -90, 90),
    lon: requiredNumber(params, "longitude", -180, 180),
    order: optionalInteger(params, "order", 0, 100) ?? 0,
  })),
  navigation_sc_request: vehicleCommand("navigation_sc_request", (params) => ({
    id: requiredInteger(params, "supercharger_id", 0, Number.MAX_SAFE_INTEGER),
    order: optionalInteger(params, "order", 0, 100) ?? 0,
  })),
  navigation_waypoints_request: vehicleCommand("navigation_waypoints_request", (params) => {
    const waypoints = params.place_ids;
    if (
      !Array.isArray(waypoints) ||
      waypoints.length < 1 ||
      waypoints.length > 20 ||
      waypoints.some((place) => typeof place !== "string" || !PLACE_ID.test(place))
    ) {
      throw new EndpointParamError("place_ids");
    }
    return { waypoints: waypoints.map((place) => `refId:${place}`).join(",") };
  }),
  remote_boombox: vehicleCommand("remote_boombox", (params) => ({
    sound: BOOMBOX_SOUNDS[oneOf(params, "sound", Object.keys(BOOMBOX_SOUNDS) as (keyof typeof BOOMBOX_SOUNDS)[])],
  })),

  // Energy products (Powerwall, solar, Wall Connector).
  energy_live_status: get("energy_site", ENERGY_READ, (context) => sitePath(context, "/live_status")),
  energy_site_info: get("energy_site", ENERGY_READ, (context) => sitePath(context, "/site_info")),
  energy_site_status: get("energy_site", ENERGY_READ, (context) => sitePath(context, "/site_status")),
  energy_backup_time_remaining: get("energy_site", ENERGY_READ, (context) =>
    sitePath(context, "/backup_time_remaining"),
  ),
  energy_history: { target: "energy_site", scopes: ENERGY_READ, mutates: false, build: calendarHistory("energy") },
  energy_backup_history: {
    target: "energy_site",
    scopes: ENERGY_READ,
    mutates: false,
    build: calendarHistory("backup"),
  },
  energy_charge_history: {
    target: "energy_site",
    scopes: ENERGY_READ,
    mutates: false,
    build: (context) => ({
      method: "GET",
      path: query(sitePath(context, "/telemetry_history"), {
        kind: "charge",
        start_date: optionalString(context.params, "start_date", RFC3339),
        end_date: optionalString(context.params, "end_date", RFC3339),
        time_zone: optionalString(context.params, "time_zone", TIME_ZONE),
      }),
    }),
  },
  energy_charger_live_status: get("energy_site", ENERGY_READ, (context) => sitePath(context, "/charger_live_status")),
  energy_tariff_rate: get("energy_site", ENERGY_READ, (context) => sitePath(context, "/tariff_rate")),
  energy_set_backup_reserve: energyWrite("/backup", (params) => ({
    backup_reserve_percent: requiredInteger(params, "percent", 0, 100),
  })),
  energy_set_operation_mode: energyWrite("/operation", (params) => ({
    default_real_mode: oneOf(params, "mode", OPERATION_MODES),
  })),
  energy_set_storm_mode: energyWrite("/storm_mode", (params) => ({ enabled: bool(params, "enabled") })),
  energy_set_grid_import_export: energyWrite("/grid_import_export", (params) => {
    const body: Record<string, unknown> = {};
    if (params.disallow_charge_from_grid_with_solar_installed !== undefined) {
      body.disallow_charge_from_grid_with_solar_installed = bool(
        params,
        "disallow_charge_from_grid_with_solar_installed",
      );
    }
    if (params.customer_preferred_export_rule !== undefined) {
      body.customer_preferred_export_rule = oneOf(params, "customer_preferred_export_rule", EXPORT_RULES);
    }
    if (!Object.keys(body).length) throw new EndpointParamError("customer_preferred_export_rule");
    return body;
  }),
  energy_set_off_grid_vehicle_charging_reserve: energyWrite("/off_grid_vehicle_charging_reserve", (params) => ({
    off_grid_vehicle_charging_reserve_percent: requiredInteger(params, "percent", 0, 100),
  })),
  energy_set_time_of_use: energyWrite("/time_of_use_settings", (params) => {
    const tariff = params.tariff_content_v2;
    if (!tariff || typeof tariff !== "object" || Array.isArray(tariff)) {
      throw new EndpointParamError("tariff_content_v2");
    }
    if (JSON.stringify(tariff).length > MAX_TARIFF_BYTES) throw new EndpointParamError("tariff_content_v2");
    return { tou_settings: { tariff_content_v2: tariff } };
  }),

  // Account.
  products: get("account", ["vehicle_device_data", "energy_device_data"], () => "/api/1/products"),
  user_me: get("account", USER_READ, () => "/api/1/users/me"),
  user_region: get("account", USER_READ, () => "/api/1/users/region"),
  user_orders: get("account", USER_READ, () => "/api/1/users/orders"),
  user_feature_config: get("account", USER_READ, () => "/api/1/users/feature_config"),
} satisfies Record<string, FleetEndpoint>;

export type FleetEndpointName = keyof typeof FLEET_ENDPOINTS;

export function isFleetEndpointName(value: unknown): value is FleetEndpointName {
  return typeof value === "string" && Object.hasOwn(FLEET_ENDPOINTS, value);
}

/** What a call needs: any one scope of `anyOf`, plus `also` when set. */
export type ScopeRequirement = { anyOf: readonly FleetScope[]; also?: FleetScope };

/** location_data in vehicle_data also needs vehicle_location. */
export function endpointScopes(name: FleetEndpointName, params: EndpointContext["params"]): ScopeRequirement {
  const anyOf = FLEET_ENDPOINTS[name].scopes;
  if (name === "vehicle_data" && Array.isArray(params.endpoints) && params.endpoints.includes("location_data")) {
    return { anyOf, also: "vehicle_location" };
  }
  return { anyOf };
}

export function describeScopes(requirement: ScopeRequirement): string {
  const base = requirement.anyOf.join(" or ");
  return requirement.also ? `${base}, plus ${requirement.also}` : base;
}

/** Charging commands are accepted with either vehicle scope. */
const CHARGING_COMMANDS = new Set([
  "charge_start",
  "charge_stop",
  "charge_standard",
  "charge_max_range",
  "set_charge_limit",
  "set_charging_amps",
  "charge_port_door_open",
  "charge_port_door_close",
  "set_scheduled_charging",
  "set_scheduled_departure",
  "clear_scheduled_departure",
  "add_charge_schedule",
  "remove_charge_schedule",
  "batch_remove_charge_schedules",
]);

export function signedCommandScopes(command: string): ScopeRequirement {
  return { anyOf: CHARGING_COMMANDS.has(command) ? ["vehicle_cmds", "vehicle_charging_cmds"] : ["vehicle_cmds"] };
}
