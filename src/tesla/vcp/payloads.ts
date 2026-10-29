// Payload builders for the signed commands in SIGNED_COMMANDS (protocol.ts).
//
// Each builder mirrors the message Tesla's vehicle-command library builds for
// the same command (pkg/vehicle at the commit pinned in conformance/run.sh),
// field for field. Proto3 omits zero scalars outside a oneof, so these do too;
// a oneof member is always written, zero or not. Builders take untrusted
// parameters and throw CommandParamError on anything out of range.

import { concatBytes } from "../../bytes";
import {
  encodeBoolField,
  encodeDoubleField,
  encodeFloatField,
  encodeInt32Field,
  encodeLengthDelimited,
  encodeSint32Field,
  encodeStringField,
  encodeUint64Field,
  encodeVarintField,
} from "./proto";

export type CommandParams = Readonly<Record<string, unknown>>;

export class CommandParamError extends Error {
  constructor(readonly param: string) {
    super(`invalid_param_${param}`);
    this.name = "CommandParamError";
  }
}

const EMPTY = new Uint8Array();

// ---------------------------------------------------------------------------
// Parameter checks
// ---------------------------------------------------------------------------

function integer(params: CommandParams, name: string, min: number, max: number): number {
  const value = params[name];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new CommandParamError(name);
  }
  return value;
}

function decimal(params: CommandParams, name: string, min: number, max: number): number {
  const value = params[name];
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
    throw new CommandParamError(name);
  }
  return value;
}

function flag(params: CommandParams, name: string, fallback?: boolean): boolean {
  const value = params[name] ?? fallback;
  if (typeof value !== "boolean") throw new CommandParamError(name);
  return value;
}

function choice<T extends string>(params: CommandParams, name: string, options: readonly T[]): T {
  const value = params[name];
  if (typeof value !== "string" || !(options as readonly string[]).includes(value)) {
    throw new CommandParamError(name);
  }
  return value as T;
}

/** Tesla's IsValidPIN: exactly four ASCII digits. */
function pin(params: CommandParams, name: string): string {
  const value = params[name];
  if (typeof value !== "string" || !/^[0-9]{4}$/.test(value)) throw new CommandParamError(name);
  return value;
}

// Proto3 implicit presence: zero values outside a oneof are not written.
function optBool(field: number, value: boolean): Uint8Array {
  return value ? encodeBoolField(field, true) : EMPTY;
}

function optInt(field: number, value: number): Uint8Array {
  return value ? encodeInt32Field(field, value) : EMPTY;
}

function optEnum(field: number, value: number): Uint8Array {
  return value ? encodeVarintField(field, value) : EMPTY;
}

function optFloat(field: number, value: number): Uint8Array {
  return value ? encodeFloatField(field, value) : EMPTY;
}

function optString(field: number, value: string): Uint8Array {
  return value ? encodeStringField(field, value) : EMPTY;
}

/** common.proto Void, as a oneof member. */
function voidField(field: number): Uint8Array {
  return encodeLengthDelimited(field, EMPTY);
}

// ---------------------------------------------------------------------------
// VCSEC (vcsec.proto UnsignedMessage)
// ---------------------------------------------------------------------------

// RKEAction_E. UnsignedMessage.RKEAction is a oneof member, so UNLOCK (0) is
// written explicitly as 10 00, exactly as Tesla's Go client sends it.
export const RKE_ACTION = { UNLOCK: 0, LOCK: 1, REMOTE_DRIVE: 20, AUTO_SECURE_VEHICLE: 29 } as const;

const CLOSURE = { REAR_TRUNK: 5, FRONT_TRUNK: 6, TONNEAU: 8 } as const;
const CLOSURE_MOVE = { MOVE: 1, STOP: 2, OPEN: 3, CLOSE: 4 } as const;

/** UnsignedMessage { RKEAction_E RKEAction = 2 } (pkg/vehicle executeRKEAction). */
export function rkeAction(action: number): Uint8Array {
  return encodeVarintField(2, action);
}

/** UnsignedMessage { ClosureMoveRequest closureMoveRequest = 4 } with one
 * closure set (pkg/vehicle executeClosureAction). */
function closureMove(closure: number, move: number): Uint8Array {
  return encodeLengthDelimited(4, encodeVarintField(closure, move));
}

export const vcsecPayloads = {
  door_lock: () => rkeAction(RKE_ACTION.LOCK),
  door_unlock: () => rkeAction(RKE_ACTION.UNLOCK),
  remote_start_drive: () => rkeAction(RKE_ACTION.REMOTE_DRIVE),
  auto_secure_vehicle: () => rkeAction(RKE_ACTION.AUTO_SECURE_VEHICLE),
  // OpenTrunk and OpenFrunk send MOVE, not OPEN.
  trunk_open: () => closureMove(CLOSURE.REAR_TRUNK, CLOSURE_MOVE.MOVE),
  trunk_close: () => closureMove(CLOSURE.REAR_TRUNK, CLOSURE_MOVE.CLOSE),
  frunk_open: () => closureMove(CLOSURE.FRONT_TRUNK, CLOSURE_MOVE.MOVE),
  tonneau_open: () => closureMove(CLOSURE.TONNEAU, CLOSURE_MOVE.OPEN),
  tonneau_close: () => closureMove(CLOSURE.TONNEAU, CLOSURE_MOVE.CLOSE),
  tonneau_stop: () => closureMove(CLOSURE.TONNEAU, CLOSURE_MOVE.STOP),
} as const satisfies Record<string, (params: CommandParams) => Uint8Array>;

// ---------------------------------------------------------------------------
// CarServer (car_server.proto Action)
// ---------------------------------------------------------------------------

/** Action { VehicleAction vehicleAction = 2 { <oneof member> = field } }. */
function vehicleAction(field: number, body: Uint8Array = EMPTY): Uint8Array {
  return encodeLengthDelimited(2, encodeLengthDelimited(field, body));
}

export const SEAT_HEATER_POSITIONS = [
  "front_left",
  "front_right",
  "rear_left",
  "rear_left_back",
  "rear_center",
  "rear_right",
  "rear_right_back",
  "third_row_left",
  "third_row_right",
] as const;
export const HEAT_LEVELS = ["off", "low", "medium", "high"] as const;
export const FRONT_SEATS = ["front_left", "front_right"] as const;
export const COP_TEMPERATURES = ["low", "medium", "high"] as const;
export const CLIMATE_KEEPER_MODES = ["off", "on", "dog", "camp"] as const;
export const SCHEDULE_DAYS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"] as const;
export const DEPARTURE_POLICIES = ["off", "all_week", "weekdays"] as const;

// HvacSeatHeaterAction oneofs: levels are Void fields 2-5 (OFF..HIGH), seats
// Void fields 7-15 (FRONT_LEFT..THIRD_ROW_RIGHT), in SeatPosition order.
function seatHeaterAction(seat: number, level: number): Uint8Array {
  return encodeLengthDelimited(1, concatBytes(voidField(2 + level), voidField(7 + seat)));
}

function seatHeaterEntries(params: CommandParams): Uint8Array {
  const seats = params.seats;
  if (!Array.isArray(seats) || seats.length < 1 || seats.length > SEAT_HEATER_POSITIONS.length) {
    throw new CommandParamError("seats");
  }
  const seen = new Set<string>();
  return concatBytes(
    ...seats.map((entry: unknown) => {
      if (!entry || typeof entry !== "object") throw new CommandParamError("seats");
      const record = entry as CommandParams;
      const seat = choice(record, "seat", SEAT_HEATER_POSITIONS);
      if (seen.has(seat)) throw new CommandParamError("seats");
      seen.add(seat);
      return seatHeaterAction(
        SEAT_HEATER_POSITIONS.indexOf(seat),
        HEAT_LEVELS.indexOf(choice(record, "level", HEAT_LEVELS)),
      );
    }),
  );
}

/** days_of_week: Tesla's bitmask, Sunday = 1 through Saturday = 64. */
function dayMask(params: CommandParams): number {
  const days = params.days_of_week;
  if (!Array.isArray(days) || days.length < 1 || days.length > 7) throw new CommandParamError("days_of_week");
  let mask = 0;
  for (const day of days) {
    const index = SCHEDULE_DAYS.indexOf(day as (typeof SCHEDULE_DAYS)[number]);
    if (index < 0 || mask & (1 << index)) throw new CommandParamError("days_of_week");
    mask |= 1 << index;
  }
  return mask;
}

function scheduleName(params: CommandParams): string {
  const value = params.name ?? "";
  if (typeof value !== "string" || value.length > 64 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new CommandParamError("name");
  }
  return value;
}

/** Schedule ids are epoch seconds in Tesla's app and proxy. */
function scheduleId(params: CommandParams): number {
  return integer(params, "id", 1, Number.MAX_SAFE_INTEGER);
}

const MINUTES_PER_DAY = 24 * 60;

function departurePolicy(params: CommandParams, name: string): Uint8Array | null {
  const policy = choice(params, name, DEPARTURE_POLICIES);
  // PreconditioningTimes / OffPeakChargingTimes { all_week = 1; weekdays = 2 }
  if (policy === "off") return null;
  return voidField(policy === "all_week" ? 1 : 2);
}

function scheduleRemoval(params: CommandParams): Uint8Array {
  const home = flag(params, "home", false);
  const work = flag(params, "work", false);
  const other = flag(params, "other", false);
  if (!home && !work && !other) throw new CommandParamError("home");
  return concatBytes(optBool(1, home), optBool(2, work), optBool(3, other));
}

export const carServerPayloads = {
  // Climate (pkg/vehicle climate.go)
  auto_conditioning_start: () => vehicleAction(10, encodeBoolField(1, true)),
  auto_conditioning_stop: () => vehicleAction(10),
  set_temps: (params: CommandParams) =>
    vehicleAction(
      14,
      concatBytes(
        // ChangeClimateTemp also sets level = Temperature { TEMP_MAX }.
        encodeLengthDelimited(5, voidField(3)),
        optFloat(6, decimal(params, "driver_temp_celsius", 15, 28)),
        optFloat(7, decimal(params, "passenger_temp_celsius", 15, 28)),
      ),
    ),
  set_preconditioning_max: (params: CommandParams) =>
    vehicleAction(12, concatBytes(optBool(1, flag(params, "on")), optBool(2, flag(params, "manual_override", false)))),
  set_bioweapon_mode: (params: CommandParams) =>
    vehicleAction(35, concatBytes(optBool(1, flag(params, "on")), optBool(2, flag(params, "manual_override", false)))),
  set_cabin_overheat_protection: (params: CommandParams) =>
    vehicleAction(50, concatBytes(optBool(1, flag(params, "on")), optBool(2, flag(params, "fan_only", false)))),
  // ClimateState.CopActivationTemp: Low = 1, Medium = 2, High = 3.
  set_cop_temp: (params: CommandParams) =>
    vehicleAction(66, encodeVarintField(1, COP_TEMPERATURES.indexOf(choice(params, "level", COP_TEMPERATURES)) + 1)),
  set_climate_keeper_mode: (params: CommandParams) =>
    vehicleAction(
      44,
      concatBytes(
        optEnum(1, CLIMATE_KEEPER_MODES.indexOf(choice(params, "mode", CLIMATE_KEEPER_MODES))),
        optBool(2, flag(params, "manual_override", false)),
      ),
    ),
  remote_seat_heater_request: (params: CommandParams) => vehicleAction(36, seatHeaterEntries(params)),
  // HvacSeatCoolerLevel_E is the heat level + 1; positions FrontLeft = 1,
  // FrontRight = 2.
  remote_seat_cooler_request: (params: CommandParams) =>
    vehicleAction(
      49,
      encodeLengthDelimited(
        1,
        concatBytes(
          encodeVarintField(1, HEAT_LEVELS.indexOf(choice(params, "level", HEAT_LEVELS)) + 1),
          encodeVarintField(2, FRONT_SEATS.indexOf(choice(params, "seat", FRONT_SEATS)) + 1),
        ),
      ),
    ),
  remote_auto_seat_climate_request: (params: CommandParams) =>
    vehicleAction(
      48,
      encodeLengthDelimited(
        1,
        concatBytes(
          optBool(1, flag(params, "on")),
          encodeVarintField(2, FRONT_SEATS.indexOf(choice(params, "seat", FRONT_SEATS)) + 1),
        ),
      ),
    ),
  remote_steering_wheel_heater_request: (params: CommandParams) => vehicleAction(13, optBool(1, flag(params, "on"))),

  // Charging (pkg/vehicle charge.go). ChargingStartStopAction oneof:
  // start = 2, start_standard = 3, start_max_range = 4, stop = 5.
  charge_start: () => vehicleAction(6, voidField(2)),
  charge_stop: () => vehicleAction(6, voidField(5)),
  charge_standard: () => vehicleAction(6, voidField(3)),
  charge_max_range: () => vehicleAction(6, voidField(4)),
  set_charge_limit: (params: CommandParams) =>
    vehicleAction(5, encodeInt32Field(1, integer(params, "percent", 50, 100))),
  set_charging_amps: (params: CommandParams) =>
    vehicleAction(43, encodeInt32Field(1, integer(params, "charging_amps", 1, 80))),
  charge_port_door_open: () => vehicleAction(62),
  charge_port_door_close: () => vehicleAction(61),
  set_scheduled_charging: (params: CommandParams) =>
    vehicleAction(
      41,
      concatBytes(
        optBool(1, flag(params, "enabled")),
        optInt(2, integer(params, "time_minutes", 0, MINUTES_PER_DAY - 1)),
      ),
    ),
  set_scheduled_departure: (params: CommandParams) => {
    const preconditioning = departurePolicy(params, "preconditioning");
    const offPeak = departurePolicy(params, "off_peak_charging");
    return vehicleAction(
      42,
      concatBytes(
        encodeBoolField(1, true),
        optInt(2, integer(params, "departure_minutes", 0, MINUTES_PER_DAY)),
        preconditioning ? encodeLengthDelimited(3, preconditioning) : EMPTY,
        offPeak ? encodeLengthDelimited(4, offPeak) : EMPTY,
        optInt(5, integer(params, "off_peak_end_minutes", 0, MINUTES_PER_DAY)),
      ),
    );
  },
  clear_scheduled_departure: () => vehicleAction(42),
  add_charge_schedule: (params: CommandParams) => {
    const startEnabled = flag(params, "start_enabled");
    const endEnabled = flag(params, "end_enabled");
    if (!startEnabled && !endEnabled) throw new CommandParamError("start_enabled");
    return vehicleAction(
      97,
      concatBytes(
        encodeUint64Field(1, scheduleId(params)),
        optString(2, scheduleName(params)),
        encodeInt32Field(3, dayMask(params)),
        optBool(4, startEnabled),
        optInt(5, startEnabled ? integer(params, "start_time_minutes", 0, MINUTES_PER_DAY - 1) : 0),
        optBool(6, endEnabled),
        optInt(7, endEnabled ? integer(params, "end_time_minutes", 0, MINUTES_PER_DAY - 1) : 0),
        optBool(8, flag(params, "one_time", false)),
        optBool(9, flag(params, "enabled", true)),
        optFloat(10, decimal(params, "latitude", -90, 90)),
        optFloat(11, decimal(params, "longitude", -180, 180)),
      ),
    );
  },
  remove_charge_schedule: (params: CommandParams) => vehicleAction(98, encodeUint64Field(1, scheduleId(params))),
  batch_remove_charge_schedules: (params: CommandParams) => vehicleAction(108, scheduleRemoval(params)),
  add_precondition_schedule: (params: CommandParams) =>
    vehicleAction(
      99,
      concatBytes(
        encodeUint64Field(1, scheduleId(params)),
        optString(2, scheduleName(params)),
        encodeInt32Field(3, dayMask(params)),
        optInt(4, integer(params, "precondition_time_minutes", 0, MINUTES_PER_DAY - 1)),
        optBool(5, flag(params, "one_time", false)),
        optBool(6, flag(params, "enabled", true)),
        optFloat(7, decimal(params, "latitude", -90, 90)),
        optFloat(8, decimal(params, "longitude", -180, 180)),
      ),
    ),
  remove_precondition_schedule: (params: CommandParams) => vehicleAction(100, encodeUint64Field(1, scheduleId(params))),
  batch_remove_precondition_schedules: (params: CommandParams) => vehicleAction(107, scheduleRemoval(params)),
  set_low_power_mode: (params: CommandParams) => vehicleAction(130, optBool(1, flag(params, "enabled"))),
  keep_accessory_power_mode: (params: CommandParams) => vehicleAction(138, optBool(1, flag(params, "enabled"))),

  // Media (pkg/vehicle infotainment.go). MediaUpdateVolume oneof:
  // volume_delta (sint32) = 1, volume_absolute_float = 3.
  adjust_volume: (params: CommandParams) => vehicleAction(16, encodeFloatField(3, decimal(params, "volume", 0, 10))),
  media_volume_up: () => vehicleAction(16, encodeSint32Field(1, 1)),
  media_volume_down: () => vehicleAction(16, encodeSint32Field(1, -1)),
  media_toggle_playback: () => vehicleAction(15),
  media_next_fav: () => vehicleAction(17),
  media_prev_fav: () => vehicleAction(18),
  media_next_track: () => vehicleAction(19),
  media_prev_track: () => vehicleAction(20),

  // Alerts and closures (pkg/vehicle actions.go)
  honk_horn: () => vehicleAction(27),
  flash_lights: () => vehicleAction(26),
  // VehicleControlWindowAction oneof: vent = 3, close = 4.
  window_vent: () => vehicleAction(34, voidField(3)),
  window_close: () => vehicleAction(34, voidField(4)),
  // VehicleControlSunroofOpenCloseAction action oneof: vent = 3, close = 4.
  sunroof_vent: () => vehicleAction(32, voidField(3)),
  sunroof_close: () => vehicleAction(32, voidField(4)),

  // Security (pkg/vehicle security.go)
  set_sentry_mode: (params: CommandParams) => vehicleAction(30, optBool(1, flag(params, "on"))),
  set_valet_mode: (params: CommandParams) => {
    const on = flag(params, "on");
    // Tesla requires a PIN to turn valet mode on; turning it off may omit it.
    const password = on || params.pin !== undefined ? pin(params, "pin") : "";
    return vehicleAction(31, concatBytes(optBool(1, on), optString(2, password)));
  },
  reset_valet_pin: () => vehicleAction(28),
  set_pin_to_drive: (params: CommandParams) =>
    vehicleAction(77, concatBytes(optBool(1, flag(params, "on")), optString(2, pin(params, "pin")))),
  reset_pin_to_drive_pin: () => vehicleAction(78),
  clear_pin_to_drive_admin: () => vehicleAction(89),
  speed_limit_activate: (params: CommandParams) =>
    vehicleAction(9, concatBytes(encodeBoolField(1, true), encodeStringField(2, pin(params, "pin")))),
  speed_limit_deactivate: (params: CommandParams) => vehicleAction(9, encodeStringField(2, pin(params, "pin"))),
  speed_limit_set_limit: (params: CommandParams) =>
    vehicleAction(8, encodeDoubleField(1, decimal(params, "limit_mph", 50, 120))),
  speed_limit_clear_pin: (params: CommandParams) => vehicleAction(7, encodeStringField(1, pin(params, "pin"))),
  speed_limit_clear_pin_admin: () => vehicleAction(79),
  // VehicleState.GuestMode { bool GuestModeActive = 1 }
  guest_mode: (params: CommandParams) => vehicleAction(65, optBool(1, flag(params, "enabled"))),
  erase_user_data: () => vehicleAction(72),
  trigger_homelink: (params: CommandParams) =>
    vehicleAction(
      33,
      encodeLengthDelimited(
        1,
        concatBytes(
          optFloat(1, decimal(params, "latitude", -90, 90)),
          optFloat(2, decimal(params, "longitude", -180, 180)),
        ),
      ),
    ),

  // Software and settings
  schedule_software_update: (params: CommandParams) =>
    vehicleAction(29, optInt(1, integer(params, "offset_seconds", 0, 7 * 86_400))),
  cancel_software_update: () => vehicleAction(25),
  set_vehicle_name: (params: CommandParams) => {
    const name = params.name;
    if (typeof name !== "string" || !name.trim() || name.length > 64 || /[\u0000-\u001f\u007f]/.test(name)) {
      throw new CommandParamError("name");
    }
    return vehicleAction(54, encodeStringField(1, name));
  },
  // Ping { int32 ping_id = 1 }: Tesla's Ping always sends id 1.
  ping: () => vehicleAction(46, encodeInt32Field(1, 1)),
} as const satisfies Record<string, (params: CommandParams) => Uint8Array>;
