// Tesla Fleet API (REST) calls. Signed vehicle commands go through
// TeslaVcpSession; this module covers the plain JSON endpoints.

import { defaultFetch, type FetchFn, fetchUpstream, readBoundedText } from "./http";
import { validFleetBaseUrl } from "./vcp/session";

const FLEET_TIMEOUT_MS = 20_000;
const MAX_FLEET_BODY_BYTES = 262_144;

export type FleetErrorCode =
  | "unauthorized"
  | "forbidden"
  | "vehicle_unavailable"
  | "not_found"
  | "rate_limited"
  | "upstream_error"
  | "bad_response";

export class FleetError extends Error {
  constructor(
    readonly code: FleetErrorCode,
    readonly status: number | null,
  ) {
    super(`tesla_fleet_${code}${status === null ? "" : `_${status}`}`);
    this.name = "FleetError";
  }
}

export type VehicleSummary = {
  id: string;
  vin: string;
  displayName: string | null;
  state: string;
};

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function shortString(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length <= max ? value : null;
}

export function validVehicleId(value: unknown): value is string {
  return typeof value === "string" && /^\d{1,20}$/.test(value);
}

function parseVehicle(value: unknown): VehicleSummary {
  const vehicle = record(value);
  const id = vehicle?.id_s ?? (typeof vehicle?.id === "number" ? String(vehicle.id) : null);
  const vin = shortString(vehicle?.vin, 17);
  const state = shortString(vehicle?.state, 32);
  if (!vehicle || !validVehicleId(id) || !vin || !state) {
    throw new FleetError("bad_response", null);
  }
  return { id, vin, displayName: shortString(vehicle.display_name, 128), state };
}

export class FleetClient {
  private readonly baseUrl: string;

  constructor(
    baseUrl: string,
    private readonly fetchFn: FetchFn = defaultFetch,
  ) {
    this.baseUrl = validFleetBaseUrl(baseUrl);
  }

  async listVehicles(accessToken: string): Promise<VehicleSummary[]> {
    const response = await this.request(accessToken, "GET", "/api/1/vehicles");
    if (!Array.isArray(response) || response.length > 100) throw new FleetError("bad_response", null);
    return response.map(parseVehicle);
  }

  async getVehicle(accessToken: string, vehicleId: string): Promise<VehicleSummary> {
    return parseVehicle(await this.request(accessToken, "GET", `/api/1/vehicles/${this.id(vehicleId)}`));
  }

  /** Never wakes the car: Fleet answers 408 when it is asleep. Location is
   * not requested. */
  async vehicleData(accessToken: string, vehicleId: string): Promise<Record<string, unknown>> {
    const endpoints = encodeURIComponent("charge_state;climate_state;vehicle_state");
    const data = record(
      await this.request(
        accessToken,
        "GET",
        `/api/1/vehicles/${this.id(vehicleId)}/vehicle_data?endpoints=${endpoints}`,
      ),
    );
    if (!data) throw new FleetError("bad_response", null);
    return data;
  }

  async wakeUp(accessToken: string, vehicleId: string): Promise<{ state: string }> {
    const response = record(await this.request(accessToken, "POST", `/api/1/vehicles/${this.id(vehicleId)}/wake_up`));
    const state = shortString(response?.state, 32);
    if (!state) throw new FleetError("bad_response", null);
    return { state };
  }

  private id(vehicleId: string): string {
    if (!validVehicleId(vehicleId)) throw new FleetError("not_found", null);
    return vehicleId;
  }

  private async request(accessToken: string, method: "GET" | "POST", path: string): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchUpstream(
        this.fetchFn,
        `${this.baseUrl}${path}`,
        {
          method,
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/json",
            ...(method === "POST" ? { "Content-Type": "application/json" } : {}),
          },
          ...(method === "POST" ? { body: "{}" } : {}),
        },
        FLEET_TIMEOUT_MS,
      );
    } catch {
      throw new FleetError("upstream_error", null);
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => {});
      const status = response.status;
      if (status === 401) throw new FleetError("unauthorized", status);
      if (status === 403) throw new FleetError("forbidden", status);
      if (status === 404) throw new FleetError("not_found", status);
      if (status === 408) throw new FleetError("vehicle_unavailable", status);
      if (status === 429) throw new FleetError("rate_limited", status);
      throw new FleetError("upstream_error", status);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readBoundedText(response, MAX_FLEET_BODY_BYTES));
    } catch {
      throw new FleetError("bad_response", null);
    }
    const body = record(parsed);
    if (!body || !("response" in body)) throw new FleetError("bad_response", null);
    return body.response;
  }
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function bool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function str(value: unknown): string | null {
  return shortString(value, 64);
}

/** Pick the status fields the MCP tool reports. Location is never copied. */
export function summarizeVehicleData(data: Record<string, unknown>) {
  const charge = record(data.charge_state) ?? {};
  const climate = record(data.climate_state) ?? {};
  const vehicle = record(data.vehicle_state) ?? {};
  const open = (value: unknown): boolean | null => {
    const n = num(value);
    return n === null ? null : n !== 0;
  };
  return {
    locked: bool(vehicle.locked),
    doorsOpen: {
      driverFront: open(vehicle.df),
      passengerFront: open(vehicle.pf),
      driverRear: open(vehicle.dr),
      passengerRear: open(vehicle.pr),
    },
    frunkOpen: open(vehicle.ft),
    trunkOpen: open(vehicle.rt),
    windowsOpen: {
      driverFront: open(vehicle.fd_window),
      passengerFront: open(vehicle.fp_window),
      driverRear: open(vehicle.rd_window),
      passengerRear: open(vehicle.rp_window),
    },
    sentryMode: bool(vehicle.sentry_mode),
    odometerMiles: num(vehicle.odometer),
    batteryPercent: num(charge.battery_level),
    rangeMiles: num(charge.battery_range),
    chargingState: str(charge.charging_state),
    chargeLimitPercent: num(charge.charge_limit_soc),
    insideTempC: num(climate.inside_temp),
    outsideTempC: num(climate.outside_temp),
    climateOn: bool(climate.is_climate_on),
  };
}

export type VehicleStatusSummary = ReturnType<typeof summarizeVehicleData>;
