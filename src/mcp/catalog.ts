// The tool catalog beyond the core tools in server.ts: one declarative spec
// per tool. server.ts turns each spec into an MCP tool, adding the shared
// vehicle_id / energy_site_id, confirm, and dryRun inputs, the confirmation
// gate for anything that changes a vehicle or energy product, and the
// dangerous-command gate.
//
// Naming: tesla_<subject>_<verb or setting>, snake_case. Energy tools start
// with tesla_energy_, account tools with tesla_account_.

import { z } from "zod";
import {
  BOOMBOX_SOUNDS,
  CALENDAR_PERIODS,
  EXPORT_RULES,
  type FleetEndpointName,
  OPERATION_MODES,
  VEHICLE_DATA_ENDPOINTS,
} from "../tesla/endpoints";
import {
  CLIMATE_KEEPER_MODES,
  COP_TEMPERATURES,
  DEPARTURE_POLICIES,
  FRONT_SEATS,
  HEAT_LEVELS,
  SCHEDULE_DAYS,
  SEAT_HEATER_POSITIONS,
} from "../tesla/vcp/payloads";
import type { SignedCommandName } from "../tesla/vcp/protocol";
import type { DangerousAction } from "./dangerous";

type Input = Record<string, unknown>;

type Common = {
  name: string;
  description: string;
  /** Extra inputs; vehicle_id / energy_site_id / confirm / dryRun are added. */
  input?: z.ZodRawShape;
  dangerousAction?: DangerousAction;
  /** Removes or erases something. */
  destructive?: boolean;
  /** Repeating the call has no further effect (default true). */
  idempotent?: boolean;
};

export type SignedToolSpec = Common & {
  kind: "signed";
  command: SignedCommandName;
  /** Command parameters from the tool input; default: the extra inputs. */
  params?: (input: Input) => Input;
  /** Completes "Not done. To ..." and "Dry run: this would ...". */
  action: string | ((input: Input) => string);
  done: string | ((input: Input) => string);
};

export type EndpointToolSpec = Common & {
  kind: "endpoint";
  endpoint: FleetEndpointName;
  params?: (input: Input) => Input;
  /** Required when the endpoint changes something. */
  action?: string | ((input: Input) => string);
  done: string | ((input: Input) => string);
};

export type ToolSpec = SignedToolSpec | EndpointToolSpec;

// ---------------------------------------------------------------------------
// Shared input schemas
// ---------------------------------------------------------------------------

const on = z.boolean().describe("true to turn it on, false to turn it off.");
const enabled = z.boolean().describe("true to enable, false to disable.");
const manualOverride = z
  .boolean()
  .optional()
  .describe("Keep running even when the car would normally stop it (for example at low battery). Default false.");
const pin = z
  .string()
  .regex(/^\d{4}$/)
  .describe("Four-digit PIN.");
const latitude = z.number().min(-90).max(90).describe("Latitude in degrees.");
const longitude = z.number().min(-180).max(180).describe("Longitude in degrees.");
const minutesAfterMidnight = (what: string) =>
  z.number().int().min(0).max(1439).describe(`${what}, in minutes after local midnight (0-1439).`);
const scheduleId = z
  .number()
  .int()
  .min(1)
  .max(Number.MAX_SAFE_INTEGER)
  .describe("Schedule id, from charge_schedule_data or preconditioning_schedule_data in tesla_vehicle_data.");
const optionalScheduleId = scheduleId
  .optional()
  .describe("Schedule id to create or replace. Leave out to create a new schedule (the current time is used).");
const scheduleName = z.string().max(64).optional().describe("Optional label shown in the Tesla app.");
const days = z
  .array(z.enum(SCHEDULE_DAYS))
  .min(1)
  .max(7)
  .describe('Days the schedule runs, for example ["monday", "friday"].');
const rfc3339 = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/)
  .describe("RFC 3339 time with offset, for example 2026-01-01T00:00:00-08:00.");
const timeZone = z
  .string()
  .regex(/^[A-Za-z]+(?:[/_+-][A-Za-z0-9]+)*$/)
  .describe("IANA time zone, for example America/Los_Angeles.");
const percent = z.number().int().min(0).max(100);

/** Seconds since the epoch: Tesla's schedule ids are creation timestamps. */
function withScheduleId(input: Input): Input {
  return { ...input, id: input.id ?? Math.floor(Date.now() / 1000) };
}

function signed(
  name: string,
  command: SignedCommandName,
  action: SignedToolSpec["action"],
  done: SignedToolSpec["done"],
  description: string,
  extra: Partial<SignedToolSpec> = {},
): SignedToolSpec {
  return { kind: "signed", name, command, action, done, description, ...extra };
}

function read(
  name: string,
  endpoint: FleetEndpointName,
  done: string,
  description: string,
  extra: Partial<EndpointToolSpec> = {},
): EndpointToolSpec {
  return { kind: "endpoint", name, endpoint, done, description, ...extra };
}

function change(
  name: string,
  endpoint: FleetEndpointName,
  action: EndpointToolSpec["action"],
  done: EndpointToolSpec["done"],
  description: string,
  extra: Partial<EndpointToolSpec> = {},
): EndpointToolSpec {
  return { kind: "endpoint", name, endpoint, action, done, description, ...extra };
}

const NEEDS_CLIMATE = " The car's climate (or Climate Keeper) must be on.";

// ---------------------------------------------------------------------------
// Signed vehicle commands (Vehicle Command Protocol)
// ---------------------------------------------------------------------------

const SIGNED_TOOLS: SignedToolSpec[] = [
  // Doors and closures
  signed("tesla_unlock", "door_unlock", "unlock the car", "The car is unlocked.", "Unlock the car's doors.", {
    dangerousAction: "unlock",
  }),
  signed(
    "tesla_remote_start",
    "remote_start_drive",
    "enable keyless driving for two minutes",
    "Keyless driving is enabled; the car can be driven for the next two minutes.",
    "Enable keyless driving (remote start) for two minutes. Requires the car's Keyless Driving setting.",
    { dangerousAction: "remote_start" },
  ),
  signed(
    "tesla_auto_secure",
    "auto_secure_vehicle",
    "close the doors and lock the car",
    "The car is closing its doors and locking.",
    "Close the powered doors and lock the car (Model X falcon-wing and front doors).",
  ),
  signed(
    "tesla_trunk_open",
    "trunk_open",
    "open the rear trunk",
    "The rear trunk is opening.",
    "Open the rear trunk.",
    {
      dangerousAction: "trunk_open",
    },
  ),
  signed(
    "tesla_trunk_close",
    "trunk_close",
    "close the rear trunk",
    "The rear trunk is closing.",
    "Close a powered rear trunk. Not every vehicle can close the trunk remotely.",
  ),
  signed(
    "tesla_frunk_open",
    "frunk_open",
    "open the front trunk",
    "The front trunk is open.",
    "Open the front trunk (frunk). It cannot be closed remotely.",
    { dangerousAction: "frunk_open" },
  ),
  signed(
    "tesla_tonneau_open",
    "tonneau_open",
    "open the tonneau cover",
    "The tonneau is opening.",
    "Open the powered tonneau cover (Cybertruck).",
    {
      dangerousAction: "tonneau_open",
    },
  ),
  signed(
    "tesla_tonneau_close",
    "tonneau_close",
    "close the tonneau cover",
    "The tonneau is closing.",
    "Close the powered tonneau cover (Cybertruck).",
  ),
  signed(
    "tesla_tonneau_stop",
    "tonneau_stop",
    "stop the tonneau cover",
    "The tonneau stopped.",
    "Stop a moving tonneau cover (Cybertruck).",
  ),
  signed(
    "tesla_windows_vent",
    "window_vent",
    "vent all windows",
    "The windows are venting.",
    "Vent (slightly open) all windows. The car must be parked.",
    { dangerousAction: "windows_open" },
  ),
  signed(
    "tesla_windows_close",
    "window_close",
    "close all windows",
    "The windows are closing.",
    "Close all windows. The car must be parked.",
  ),
  signed(
    "tesla_sunroof_vent",
    "sunroof_vent",
    "vent the sunroof",
    "The sunroof is venting.",
    "Vent the sunroof, on cars with a powered sunroof.",
    {
      dangerousAction: "sunroof_open",
    },
  ),
  signed(
    "tesla_sunroof_close",
    "sunroof_close",
    "close the sunroof",
    "The sunroof is closing.",
    "Close the sunroof, on cars with a powered sunroof.",
  ),
  signed("tesla_honk_horn", "honk_horn", "honk the horn", "The horn honked.", "Honk the horn once.", {
    idempotent: false,
  }),
  signed(
    "tesla_flash_lights",
    "flash_lights",
    "flash the headlights",
    "The lights flashed.",
    "Flash the headlights once.",
    {
      idempotent: false,
    },
  ),

  // Climate
  signed(
    "tesla_climate_start",
    "auto_conditioning_start",
    "turn on climate control",
    "Climate control is on.",
    "Turn on climate control (precondition the cabin) at the current settings.",
  ),
  signed(
    "tesla_climate_stop",
    "auto_conditioning_stop",
    "turn off climate control",
    "Climate control is off.",
    "Turn off climate control.",
  ),
  signed(
    "tesla_climate_set_temperatures",
    "set_temps",
    (input) =>
      `set the cabin to ${input.driver_temp_celsius} °C (driver) and ${input.passenger_temp_celsius} °C (passenger)`,
    "The cabin temperatures are set.",
    "Set the driver and passenger cabin temperatures, in Celsius (15-28).",
    {
      input: {
        driver_temp_celsius: z.number().min(15).max(28).describe("Driver side, °C."),
        passenger_temp_celsius: z.number().min(15).max(28).describe("Passenger side, °C."),
      },
    },
  ),
  signed(
    "tesla_climate_set_preconditioning_max",
    "set_preconditioning_max",
    (input) => `turn ${input.on ? "on" : "off"} Defrost (max preconditioning)`,
    "Defrost mode is updated.",
    "Turn Defrost (maximum preconditioning) on or off.",
    { input: { on, manual_override: manualOverride } },
  ),
  signed(
    "tesla_climate_set_bioweapon_mode",
    "set_bioweapon_mode",
    (input) => `turn ${input.on ? "on" : "off"} Bioweapon Defense Mode`,
    "Bioweapon Defense Mode is updated.",
    "Turn Bioweapon Defense Mode on or off, on cars with a HEPA filter.",
    { input: { on, manual_override: manualOverride } },
  ),
  signed(
    "tesla_climate_set_cabin_overheat_protection",
    "set_cabin_overheat_protection",
    (input) => `turn ${input.on ? "on" : "off"} Cabin Overheat Protection${input.fan_only ? " (fan only)" : ""}`,
    "Cabin Overheat Protection is updated.",
    "Turn Cabin Overheat Protection on or off, optionally fan only (no A/C).",
    { input: { on, fan_only: z.boolean().optional().describe("Use only the fan, no A/C. Default false.") } },
  ),
  signed(
    "tesla_climate_set_cabin_overheat_temperature",
    "set_cop_temp",
    (input) => `set the Cabin Overheat Protection temperature to ${input.level}`,
    "The Cabin Overheat Protection temperature is set.",
    "Set the temperature at which Cabin Overheat Protection starts: low, medium, or high. Does not turn it on.",
    { input: { level: z.enum(COP_TEMPERATURES) } },
  ),
  signed(
    "tesla_climate_set_keeper_mode",
    "set_climate_keeper_mode",
    (input) => `set Climate Keeper to ${input.mode}`,
    "Climate Keeper is set.",
    "Set Climate Keeper: off, on (Keep), dog (Dog Mode), or camp (Camp Mode).",
    { input: { mode: z.enum(CLIMATE_KEEPER_MODES), manual_override: manualOverride } },
  ),
  signed(
    "tesla_seat_heater_set",
    "remote_seat_heater_request",
    (input) =>
      `set seat heaters: ${(input.seats as { seat: string; level: string }[])
        .map((entry) => `${entry.seat} ${entry.level}`)
        .join(", ")}`,
    "The seat heaters are set.",
    `Set seat heater levels for one or more seats.${NEEDS_CLIMATE}`,
    {
      input: {
        seats: z
          .array(z.object({ seat: z.enum(SEAT_HEATER_POSITIONS), level: z.enum(HEAT_LEVELS) }).strict())
          .min(1)
          .max(SEAT_HEATER_POSITIONS.length)
          .describe('Seats and levels, for example [{"seat": "front_left", "level": "high"}]. Each seat once.'),
      },
    },
  ),
  signed(
    "tesla_seat_cooler_set",
    "remote_seat_cooler_request",
    (input) => `set the ${input.seat} seat cooler to ${input.level}`,
    "The seat cooler is set.",
    `Set a front seat's ventilation (cooling) level, on cars with ventilated seats.${NEEDS_CLIMATE}`,
    { input: { seat: z.enum(FRONT_SEATS), level: z.enum(HEAT_LEVELS) } },
  ),
  signed(
    "tesla_seat_auto_climate_set",
    "remote_auto_seat_climate_request",
    (input) => `turn ${input.on ? "on" : "off"} automatic seat climate for the ${input.seat} seat`,
    "Automatic seat climate is updated.",
    `Turn automatic seat heating and cooling on or off for a front seat.${NEEDS_CLIMATE}`,
    { input: { seat: z.enum(FRONT_SEATS), on } },
  ),
  signed(
    "tesla_steering_wheel_heater_set",
    "remote_steering_wheel_heater_request",
    (input) => `turn the steering wheel heater ${input.on ? "on" : "off"}`,
    "The steering wheel heater is updated.",
    `Turn the steering wheel heater on or off.${NEEDS_CLIMATE}`,
    { input: { on } },
  ),

  // Charging
  signed(
    "tesla_charge_start",
    "charge_start",
    "start charging",
    "Charging started.",
    "Start charging. The car must be plugged in.",
  ),
  signed("tesla_charge_stop", "charge_stop", "stop charging", "Charging stopped.", "Stop charging."),
  signed(
    "tesla_charge_standard",
    "charge_standard",
    "set the charge limit to standard",
    "The charge limit is set to standard.",
    "Set the charge limit to the car's standard (daily) level.",
  ),
  signed(
    "tesla_charge_max_range",
    "charge_max_range",
    "set the charge limit to maximum range",
    "The charge limit is set to maximum range.",
    "Set the charge limit to maximum range (100%), for trips.",
  ),
  signed(
    "tesla_charge_set_limit",
    "set_charge_limit",
    (input) => `set the charge limit to ${input.percent}%`,
    (input) => `The charge limit is ${input.percent}%.`,
    "Set the charge limit, 50 to 100 percent.",
    { input: { percent: z.number().int().min(50).max(100).describe("Charge limit, percent.") } },
  ),
  signed(
    "tesla_charge_set_amps",
    "set_charging_amps",
    (input) => `set the charging current to ${input.charging_amps} A`,
    (input) => `The charging current is ${input.charging_amps} A.`,
    "Set the charging current in amps (1-80). The car caps it at what the charger and car allow.",
    { input: { charging_amps: z.number().int().min(1).max(80).describe("Amps.") } },
  ),
  signed(
    "tesla_charge_port_open",
    "charge_port_door_open",
    "open the charge port door (and release a latched cable)",
    "The charge port is open.",
    "Open the charge port door. If a cable is plugged in, this also unlatches it.",
    { dangerousAction: "charge_port_open" },
  ),
  signed(
    "tesla_charge_port_close",
    "charge_port_door_close",
    "close the charge port door",
    "The charge port is closed.",
    "Close the charge port door.",
  ),
  signed(
    "tesla_charge_set_scheduled_charging",
    "set_scheduled_charging",
    (input) =>
      input.enabled
        ? `schedule charging to start at minute ${input.time_minutes} after midnight`
        : "turn off scheduled charging",
    "Scheduled charging is updated.",
    "Set or turn off the single scheduled charging start time. Tesla recommends tesla_charge_schedule_add on firmware 2024.26 and later.",
    {
      input: {
        enabled,
        time_minutes: minutesAfterMidnight("Start time")
          .optional()
          .describe("Start time in minutes after midnight. Required when enabled."),
      },
      params: (input) => ({ enabled: input.enabled, time_minutes: input.enabled ? input.time_minutes : 0 }),
    },
  ),
  signed(
    "tesla_charge_set_scheduled_departure",
    "set_scheduled_departure",
    (input) => `set a scheduled departure at minute ${input.departure_minutes} after midnight`,
    "Scheduled departure is set.",
    "Set the scheduled departure: the car preconditions and/or charges off-peak to be ready by this time. Tesla recommends tesla_precondition_schedule_add on firmware 2024.26 and later.",
    {
      input: {
        departure_minutes: z
          .number()
          .int()
          .min(0)
          .max(1440)
          .describe("Departure time, minutes after midnight (0-1440)."),
        preconditioning: z.enum(DEPARTURE_POLICIES).describe("Precondition the cabin: off, all_week, or weekdays."),
        off_peak_charging: z.enum(DEPARTURE_POLICIES).describe("Charge off-peak: off, all_week, or weekdays."),
        off_peak_end_minutes: z
          .number()
          .int()
          .min(0)
          .max(1440)
          .optional()
          .describe("When off-peak rates end, minutes after midnight. Default 0."),
      },
      params: (input) => ({ ...input, off_peak_end_minutes: input.off_peak_end_minutes ?? 0 }),
    },
  ),
  signed(
    "tesla_charge_clear_scheduled_departure",
    "clear_scheduled_departure",
    "turn off scheduled departure",
    "Scheduled departure is off.",
    "Turn off scheduled departure.",
  ),
  signed(
    "tesla_charge_schedule_add",
    "add_charge_schedule",
    (input) => `add a charge schedule on ${(input.days_of_week as string[]).join(", ")}`,
    "The charge schedule is saved.",
    "Add or replace a charge schedule (firmware 2024.26+). The schedule applies at the given location. Give a start time, an end time, or both.",
    {
      input: {
        id: optionalScheduleId,
        name: scheduleName,
        days_of_week: days,
        start_enabled: z.boolean().describe("Start charging at start_time_minutes."),
        start_time_minutes: minutesAfterMidnight("Start time").optional(),
        end_enabled: z.boolean().describe("Stop charging at end_time_minutes."),
        end_time_minutes: minutesAfterMidnight("End time").optional(),
        one_time: z.boolean().optional().describe("Run once instead of weekly. Default false."),
        enabled: z.boolean().optional().describe("Default true."),
        latitude,
        longitude,
      },
      params: withScheduleId,
    },
  ),
  signed(
    "tesla_charge_schedule_remove",
    "remove_charge_schedule",
    (input) => `remove charge schedule ${input.id}`,
    "The charge schedule is removed.",
    "Remove one charge schedule by id.",
    { input: { id: scheduleId }, destructive: true },
  ),
  signed(
    "tesla_charge_schedules_remove",
    "batch_remove_charge_schedules",
    (input) =>
      `remove all charge schedules for ${["home", "work", "other"].filter((key) => input[key]).join(", ")} locations`,
    "The charge schedules are removed.",
    "Remove all charge schedules at home, work, and/or other locations.",
    {
      input: {
        home: z.boolean().optional(),
        work: z.boolean().optional(),
        other: z.boolean().optional().describe("Locations other than home and work."),
      },
      destructive: true,
    },
  ),
  signed(
    "tesla_precondition_schedule_add",
    "add_precondition_schedule",
    (input) => `add a precondition schedule on ${(input.days_of_week as string[]).join(", ")}`,
    "The precondition schedule is saved.",
    "Add or replace a cabin preconditioning schedule (firmware 2024.26+), applied at the given location.",
    {
      input: {
        id: optionalScheduleId,
        name: scheduleName,
        days_of_week: days,
        precondition_time_minutes: minutesAfterMidnight("Departure time"),
        one_time: z.boolean().optional().describe("Run once instead of weekly. Default false."),
        enabled: z.boolean().optional().describe("Default true."),
        latitude,
        longitude,
      },
      params: withScheduleId,
    },
  ),
  signed(
    "tesla_precondition_schedule_remove",
    "remove_precondition_schedule",
    (input) => `remove precondition schedule ${input.id}`,
    "The precondition schedule is removed.",
    "Remove one preconditioning schedule by id.",
    { input: { id: scheduleId }, destructive: true },
  ),
  signed(
    "tesla_precondition_schedules_remove",
    "batch_remove_precondition_schedules",
    (input) =>
      `remove all precondition schedules for ${["home", "work", "other"].filter((key) => input[key]).join(", ")} locations`,
    "The precondition schedules are removed.",
    "Remove all preconditioning schedules at home, work, and/or other locations.",
    {
      input: {
        home: z.boolean().optional(),
        work: z.boolean().optional(),
        other: z.boolean().optional().describe("Locations other than home and work."),
      },
      destructive: true,
    },
  ),

  // Power
  signed(
    "tesla_low_power_mode_set",
    "set_low_power_mode",
    (input) => `turn Low Power Mode ${input.enabled ? "on" : "off"}`,
    "Low Power Mode is updated.",
    "Turn Low Power Mode on or off (Cybertruck).",
    { input: { enabled } },
  ),
  signed(
    "tesla_keep_accessory_power_set",
    "keep_accessory_power_mode",
    (input) => `turn Keep Accessory Power ${input.enabled ? "on" : "off"}`,
    "Keep Accessory Power is updated.",
    "Turn Keep Accessory Power on or off (keeps 12 V outlets and accessories powered).",
    { input: { enabled } },
  ),

  // Media
  signed(
    "tesla_media_set_volume",
    "adjust_volume",
    (input) => `set the volume to ${input.volume}`,
    (input) => `The volume is ${input.volume}.`,
    "Set the media volume, 0 to 10. Someone must be in the car.",
    { input: { volume: z.number().min(0).max(10).describe("Volume, 0-10.") } },
  ),
  signed(
    "tesla_media_volume_up",
    "media_volume_up",
    "turn the volume up",
    "Volume up.",
    "Turn the media volume up one step.",
    {
      idempotent: false,
    },
  ),
  signed(
    "tesla_media_volume_down",
    "media_volume_down",
    "turn the volume down",
    "Volume down.",
    "Turn the media volume down one step.",
    {
      idempotent: false,
    },
  ),
  signed(
    "tesla_media_toggle_playback",
    "media_toggle_playback",
    "toggle media playback",
    "Playback toggled.",
    "Play or pause media.",
    {
      idempotent: false,
    },
  ),
  signed(
    "tesla_media_next_track",
    "media_next_track",
    "skip to the next track",
    "Next track.",
    "Skip to the next track.",
    {
      idempotent: false,
    },
  ),
  signed(
    "tesla_media_previous_track",
    "media_prev_track",
    "go to the previous track",
    "Previous track.",
    "Go to the previous track.",
    {
      idempotent: false,
    },
  ),
  signed(
    "tesla_media_next_favorite",
    "media_next_fav",
    "go to the next favorite",
    "Next favorite.",
    "Go to the next favorite station.",
    {
      idempotent: false,
    },
  ),
  signed(
    "tesla_media_previous_favorite",
    "media_prev_fav",
    "go to the previous favorite",
    "Previous favorite.",
    "Go to the previous favorite station.",
    { idempotent: false },
  ),

  // Security and access
  signed(
    "tesla_sentry_mode_on",
    "set_sentry_mode",
    "turn Sentry Mode on",
    "Sentry Mode is on.",
    "Turn Sentry Mode on.",
    { params: () => ({ on: true }) },
  ),
  signed(
    "tesla_sentry_mode_off",
    "set_sentry_mode",
    "turn Sentry Mode off",
    "Sentry Mode is off.",
    "Turn Sentry Mode off.",
    { params: () => ({ on: false }), dangerousAction: "sentry_off" },
  ),
  signed(
    "tesla_valet_mode_on",
    "set_valet_mode",
    "turn Valet Mode on",
    "Valet Mode is on.",
    "Turn Valet Mode on with a four-digit PIN.",
    { input: { pin }, params: (input) => ({ on: true, pin: input.pin }), dangerousAction: "valet_mode" },
  ),
  signed(
    "tesla_valet_mode_off",
    "set_valet_mode",
    "turn Valet Mode off",
    "Valet Mode is off.",
    "Turn Valet Mode off.",
    {
      input: { pin: pin.optional().describe("The Valet Mode PIN, if the car asks for it.") },
      params: (input) => ({ on: false, ...(input.pin === undefined ? {} : { pin: input.pin }) }),
      dangerousAction: "valet_mode",
    },
  ),
  signed(
    "tesla_valet_pin_reset",
    "reset_valet_pin",
    "clear the Valet Mode PIN",
    "The Valet Mode PIN is cleared.",
    "Clear the Valet Mode PIN. Valet Mode must be off.",
    { dangerousAction: "valet_mode" },
  ),
  signed(
    "tesla_pin_to_drive_set",
    "set_pin_to_drive",
    (input) => `turn PIN to Drive ${input.on ? "on" : "off"}`,
    "PIN to Drive is updated.",
    "Turn PIN to Drive on (with a new four-digit PIN) or off (with the current PIN).",
    { input: { on, pin }, dangerousAction: "pin_to_drive" },
  ),
  signed(
    "tesla_pin_to_drive_reset",
    "reset_pin_to_drive_pin",
    "reset the PIN to Drive PIN",
    "The PIN to Drive PIN is reset.",
    "Reset the PIN to Drive PIN (owner and fleet manager only).",
    { dangerousAction: "pin_to_drive" },
  ),
  signed(
    "tesla_pin_to_drive_clear_admin",
    "clear_pin_to_drive_admin",
    "clear PIN to Drive as an administrator",
    "PIN to Drive is cleared.",
    "Turn off PIN to Drive and clear its PIN without the PIN (owner and fleet manager only).",
    { dangerousAction: "pin_to_drive" },
  ),
  signed(
    "tesla_speed_limit_activate",
    "speed_limit_activate",
    "turn Speed Limit Mode on",
    "Speed Limit Mode is on.",
    "Turn Speed Limit Mode on with its four-digit PIN.",
    { input: { pin }, dangerousAction: "speed_limit" },
  ),
  signed(
    "tesla_speed_limit_deactivate",
    "speed_limit_deactivate",
    "turn Speed Limit Mode off",
    "Speed Limit Mode is off.",
    "Turn Speed Limit Mode off with its four-digit PIN.",
    { input: { pin }, dangerousAction: "speed_limit" },
  ),
  signed(
    "tesla_speed_limit_set",
    "speed_limit_set_limit",
    (input) => `set the Speed Limit Mode limit to ${input.limit_mph} mph`,
    (input) => `The speed limit is ${input.limit_mph} mph.`,
    "Set the Speed Limit Mode maximum speed, 50 to 120 mph.",
    {
      input: { limit_mph: z.number().min(50).max(120).describe("Maximum speed, mph.") },
      dangerousAction: "speed_limit",
    },
  ),
  signed(
    "tesla_speed_limit_clear_pin",
    "speed_limit_clear_pin",
    "clear the Speed Limit Mode PIN",
    "The Speed Limit Mode PIN is cleared.",
    "Clear the Speed Limit Mode PIN (also turns Speed Limit Mode off).",
    { input: { pin }, dangerousAction: "speed_limit" },
  ),
  signed(
    "tesla_speed_limit_clear_pin_admin",
    "speed_limit_clear_pin_admin",
    "clear the Speed Limit Mode PIN as an administrator",
    "The Speed Limit Mode PIN is cleared.",
    "Clear the Speed Limit Mode PIN without the PIN (owner and fleet manager only; firmware 2023.38+).",
    { dangerousAction: "speed_limit" },
  ),
  signed(
    "tesla_guest_mode_set",
    "guest_mode",
    (input) => `turn Guest Mode ${input.enabled ? "on" : "off"}`,
    "Guest Mode is updated.",
    "Turn Guest Mode on or off. Guest Mode restricts PIN to Drive, Speed Limit Mode, glovebox PIN, keys, and the car's name, and lets a key-card user set up Tesla app access by QR code.",
    { input: { enabled }, dangerousAction: "guest_mode" },
  ),
  signed(
    "tesla_erase_user_data",
    "erase_user_data",
    "erase the guest's user data from the car",
    "The user data is erased.",
    "Erase user data (profiles, settings, linked accounts) from the car. The car must be parked and in Guest Mode.",
    { dangerousAction: "erase_user_data", destructive: true },
  ),
  signed(
    "tesla_homelink_trigger",
    "trigger_homelink",
    "trigger HomeLink (for example a garage door)",
    "HomeLink was triggered.",
    "Trigger HomeLink (garage door or gate). The car must be near the programmed location given here.",
    { input: { latitude, longitude }, dangerousAction: "homelink", idempotent: false },
  ),

  // Software and settings
  signed(
    "tesla_software_update_schedule",
    "schedule_software_update",
    (input) => `install the downloaded software update in ${input.offset_seconds} seconds`,
    "The software update is scheduled.",
    "Schedule installing a downloaded software update after a delay in seconds (0 = now). The car cannot be driven while it installs.",
    {
      input: { offset_seconds: z.number().int().min(0).max(604_800).describe("Delay in seconds, up to 7 days.") },
      dangerousAction: "software_update",
    },
  ),
  signed(
    "tesla_software_update_cancel",
    "cancel_software_update",
    "cancel the scheduled software update",
    "The software update is canceled.",
    "Cancel a scheduled software update that has not started installing.",
  ),
  signed(
    "tesla_vehicle_set_name",
    "set_vehicle_name",
    (input) => `rename the car to ${JSON.stringify(input.name)}`,
    (input) => `The car is now named ${JSON.stringify(input.name)}.`,
    "Rename the car. Not available in Guest Mode.",
    {
      input: {
        name: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[^\u0000-\u001f\u007f]+$/)
          .describe("New name, up to 64 characters."),
      },
    },
  ),
];

/** Ping sends a signed no-op: it changes nothing, so it is a read tool. */
export const PING_TOOL = {
  name: "tesla_vehicle_ping",
  description:
    "Check that the car is online and accepts this server's signed commands (its virtual key is paired) by sending a signed no-op. Changes nothing and does not wake the car; an asleep car reports vehicle_asleep.",
};

// ---------------------------------------------------------------------------
// Fleet REST endpoints
// ---------------------------------------------------------------------------

const ENDPOINT_TOOLS: EndpointToolSpec[] = [
  // Vehicle data
  read(
    "tesla_vehicle_data",
    "vehicle_data",
    "Vehicle data.",
    "Live vehicle data from the categories you name (vehicle_data). Never wakes the car: an asleep car reports vehicle_asleep. location_data returns the car's location and needs the vehicle_location scope; it is only sent when asked for.",
    {
      input: {
        endpoints: z
          .array(z.enum(VEHICLE_DATA_ENDPOINTS))
          .min(1)
          .max(VEHICLE_DATA_ENDPOINTS.length)
          .describe('Categories, for example ["charge_state", "climate_state"]. Each at most once.'),
      },
    },
  ),
  read(
    "tesla_vehicle_data_cached",
    "vehicle_data_cached",
    "Cached vehicle data.",
    "The last data the car reported, even while it is asleep or offline (never contacts the car). Can be hours old: check each block's timestamp. No location, drive, or media data.",
  ),
  read(
    "tesla_vehicle_mobile_enabled",
    "mobile_enabled",
    "Mobile access.",
    "Whether mobile (remote) access is enabled in the car.",
  ),
  read(
    "tesla_vehicle_nearby_charging_sites",
    "nearby_charging_sites",
    "Nearby charging sites.",
    "Superchargers and destination chargers near the car's current location, with availability. The car must be online.",
  ),
  read("tesla_vehicle_recent_alerts", "recent_alerts", "Recent alerts.", "Recent alerts the car has raised."),
  read(
    "tesla_vehicle_release_notes",
    "release_notes",
    "Release notes.",
    "Release notes for the car's installed firmware.",
  ),
  read(
    "tesla_vehicle_service_data",
    "service_data",
    "Service data.",
    "The car's service status (for example an open service visit).",
  ),
  read(
    "tesla_vehicle_fleet_status",
    "fleet_status",
    "Fleet status.",
    "Firmware version, whether signed commands are required, Fleet Telemetry version, and the number of keys.",
  ),
  read("tesla_vehicle_options", "vehicle_options", "Vehicle options.", "The car's option and configuration details."),
  read("tesla_vehicle_warranty", "warranty_details", "Warranty details.", "Warranty information for the car."),
  read(
    "tesla_vehicle_eligible_subscriptions",
    "eligible_subscriptions",
    "Eligible subscriptions.",
    "Subscriptions the car is eligible for (for example Premium Connectivity).",
  ),
  read(
    "tesla_vehicle_eligible_upgrades",
    "eligible_upgrades",
    "Eligible upgrades.",
    "Software upgrades the car is eligible for.",
  ),
  read(
    "tesla_vehicle_charging_history",
    "charging_history",
    "Charging history.",
    "Paid charging history (Supercharger sessions, fees) for the car. Needs the vehicle_charging_cmds scope.",
    {
      input: {
        start_time: rfc3339.optional(),
        end_time: rfc3339.optional(),
        page: z.number().int().min(1).max(10_000).optional().describe("Page number, from 1."),
        page_size: z.number().int().min(1).max(50).optional(),
        sort_by: z.enum(["chargeStartDateTime", "totalEnergyDispensed"]).optional(),
        sort_order: z.enum(["ASC", "DESC"]).optional(),
      },
    },
  ),
  read(
    "tesla_vehicle_fleet_telemetry_config",
    "fleet_telemetry_config",
    "Fleet Telemetry configuration.",
    "The car's Fleet Telemetry streaming configuration for this app: whether it is synced and whether the config limit is reached.",
  ),
  read(
    "tesla_vehicle_fleet_telemetry_errors",
    "fleet_telemetry_errors",
    "Fleet Telemetry errors.",
    "Recent Fleet Telemetry errors the car reported for this app's configuration.",
  ),
  change(
    "tesla_vehicle_fleet_telemetry_config_delete",
    "fleet_telemetry_config_delete",
    "remove this app's Fleet Telemetry configuration from the car",
    "The Fleet Telemetry configuration is removed.",
    "Remove this app's Fleet Telemetry streaming configuration from the car.",
    { destructive: true },
  ),

  // Sharing and drivers
  read(
    "tesla_vehicle_drivers_list",
    "drivers",
    "Drivers.",
    "Drivers who have access to the car through sharing (owner only).",
  ),
  change(
    "tesla_vehicle_driver_remove",
    "driver_remove",
    (input) =>
      input.share_user_id
        ? `remove driver ${input.share_user_id} from the car`
        : "remove this account's own access to the car",
    "The driver's access is removed.",
    "Remove a shared driver's access to the car. Without share_user_id, removes this account's own shared access.",
    {
      input: {
        share_user_id: z
          .string()
          .regex(/^\d{1,20}$/)
          .optional()
          .describe("The driver's share user id, from tesla_vehicle_drivers_list."),
      },
      destructive: true,
    },
  ),
  read("tesla_vehicle_share_invites_list", "share_invites", "Share invites.", "Active invitations to share the car."),
  change(
    "tesla_vehicle_share_invite_create",
    "share_invite_create",
    "create a single-use share link that grants driver access to the car",
    "A share invite is created.",
    "Create a single-use invitation link (valid 24 hours) that gives whoever redeems it driver access to the car in the Tesla app, including location and remote commands.",
    { dangerousAction: "share_access", idempotent: false },
  ),
  change(
    "tesla_vehicle_share_invite_revoke",
    "share_invite_revoke",
    (input) => `revoke share invite ${input.invite_id}`,
    "The share invite is revoked.",
    "Revoke a share invitation so its link no longer works.",
    {
      input: {
        invite_id: z
          .string()
          .regex(/^\d{1,20}$/)
          .describe("Invite id, from tesla_vehicle_share_invites_list."),
      },
      destructive: true,
    },
  ),

  // Navigation and sound (Fleet relays these; there is no signed message).
  change(
    "tesla_navigation_send_destination",
    "navigation_request",
    (input) => `send ${JSON.stringify(input.destination)} to the car's navigation`,
    "The destination is sent to the car.",
    "Send an address or place name to the car's navigation, as sharing it from the Tesla app does.",
    {
      input: {
        destination: z
          .string()
          .min(1)
          .max(512)
          .regex(/^[^\u0000-\u001f\u007f]+$/)
          .describe("Address or place name."),
      },
    },
  ),
  change(
    "tesla_navigation_send_coordinates",
    "navigation_gps_request",
    (input) => `start navigation to ${input.latitude}, ${input.longitude}`,
    "Navigation started.",
    "Start navigation to coordinates. order sets this stop's position in a multi-stop trip.",
    {
      input: {
        latitude,
        longitude,
        order: z.number().int().min(0).max(100).optional().describe("Stop order, from 0. Default 0."),
      },
    },
  ),
  change(
    "tesla_navigation_send_supercharger",
    "navigation_sc_request",
    (input) => `start navigation to Supercharger ${input.supercharger_id}`,
    "Navigation to the Supercharger started.",
    "Start navigation to a Supercharger by id (for example from tesla_vehicle_nearby_charging_sites).",
    {
      input: {
        supercharger_id: z.number().int().min(0).describe("Supercharger id."),
        order: z.number().int().min(0).max(100).optional().describe("Stop order, from 0. Default 0."),
      },
    },
  ),
  change(
    "tesla_navigation_send_waypoints",
    "navigation_waypoints_request",
    (input) => `send ${(input.place_ids as string[]).length} waypoints to the car's navigation`,
    "The waypoints are sent to the car.",
    "Send a multi-stop route to the car's navigation as Google Maps place ids, in order.",
    {
      input: {
        place_ids: z
          .array(z.string().regex(/^[A-Za-z0-9_-]{10,256}$/))
          .min(1)
          .max(20)
          .describe('Google Maps place ids ("ChIJ..."), in stop order.'),
      },
    },
  ),
  change(
    "tesla_play_sound",
    "remote_boombox",
    (input) => `play the ${input.sound} sound on the external speaker`,
    "The sound played.",
    "Play a sound on the external speaker (Boombox): locate_ping or fart. Not available on every car or region.",
    { input: { sound: z.enum(Object.keys(BOOMBOX_SOUNDS) as [keyof typeof BOOMBOX_SOUNDS]) }, idempotent: false },
  ),

  // Energy products
  read(
    "tesla_energy_live_status",
    "energy_live_status",
    "Live status.",
    "Live power flows (solar, battery, grid, home), battery percent, grid status, and Storm Watch state.",
  ),
  read(
    "tesla_energy_site_info",
    "energy_site_info",
    "Site info.",
    "Site configuration: installed assets, backup reserve, operation mode, tariff, and supported features.",
  ),
  read(
    "tesla_energy_site_status",
    "energy_site_status",
    "Site status.",
    "Battery percent and power, site name, and Storm Watch state.",
  ),
  read(
    "tesla_energy_backup_time_remaining",
    "energy_backup_time_remaining",
    "Backup time remaining.",
    "Estimated hours the battery can power the home in an outage at the current load.",
  ),
  read(
    "tesla_energy_history",
    "energy_history",
    "Energy history.",
    "Energy produced, consumed, imported, and exported, aggregated by period (Wh).",
    {
      input: {
        period: z.enum(CALENDAR_PERIODS),
        start_date: rfc3339.optional(),
        end_date: rfc3339.optional(),
        time_zone: timeZone.optional(),
      },
    },
  ),
  read(
    "tesla_energy_backup_history",
    "energy_backup_history",
    "Backup history.",
    "Past grid outages (backup events) and their duration.",
    {
      input: { start_date: rfc3339.optional(), end_date: rfc3339.optional(), time_zone: timeZone.optional() },
    },
  ),
  read(
    "tesla_energy_charge_history",
    "energy_charge_history",
    "Wall Connector charge history.",
    "Wall Connector charging sessions and energy (Wh).",
    {
      input: { start_date: rfc3339.optional(), end_date: rfc3339.optional(), time_zone: timeZone.optional() },
    },
  ),
  read(
    "tesla_energy_charger_live_status",
    "energy_charger_live_status",
    "Charger live status.",
    "Live state and power of the site's Wall Connectors.",
  ),
  read(
    "tesla_energy_tariff_rate",
    "energy_tariff_rate",
    "Tariff.",
    "The site's utility rate plan: time-of-use periods and buy and sell prices.",
  ),
  change(
    "tesla_energy_set_backup_reserve",
    "energy_set_backup_reserve",
    (input) => `set the backup reserve to ${input.percent}%`,
    (input) => `The backup reserve is ${input.percent}%.`,
    "Set the battery's backup reserve: the percent kept for outages.",
    { input: { percent: percent.describe("Backup reserve, percent.") } },
  ),
  change(
    "tesla_energy_set_operation_mode",
    "energy_set_operation_mode",
    (input) => `set the operation mode to ${input.mode}`,
    (input) => `The operation mode is ${input.mode}.`,
    "Set the operation mode: self_consumption (self-powered) or autonomous (time-based control).",
    { input: { mode: z.enum(OPERATION_MODES) } },
  ),
  change(
    "tesla_energy_set_storm_watch",
    "energy_set_storm_mode",
    (input) => `turn Storm Watch ${input.enabled ? "on" : "off"}`,
    "Storm Watch is updated.",
    "Turn Storm Watch on or off (charge fully ahead of severe weather).",
    { input: { enabled } },
  ),
  change(
    "tesla_energy_set_grid_import_export",
    "energy_set_grid_import_export",
    "change grid charging and export settings",
    "Grid import and export settings are updated.",
    "Allow or disallow charging the battery from the grid, and set what may be exported to the grid: pv_only, battery_ok, or never. Give at least one.",
    {
      input: {
        disallow_charge_from_grid_with_solar_installed: z.boolean().optional().describe("true stops grid charging."),
        customer_preferred_export_rule: z.enum(EXPORT_RULES).optional(),
      },
    },
  ),
  change(
    "tesla_energy_set_off_grid_vehicle_charging_reserve",
    "energy_set_off_grid_vehicle_charging_reserve",
    (input) => `set the off-grid vehicle charging reserve to ${input.percent}%`,
    (input) => `The off-grid vehicle charging reserve is ${input.percent}%.`,
    "During an outage, stop charging vehicles from the battery below this percent.",
    { input: { percent: percent.describe("Reserve, percent.") } },
  ),
  change(
    "tesla_energy_set_time_of_use",
    "energy_set_time_of_use",
    "replace the site's time-of-use tariff",
    "The time-of-use tariff is updated.",
    "Replace the site's time-of-use tariff with tariff_content_v2 (Tesla's tariff structure: seasons, energy_charges, sell_tariff, currency). Tesla validates it.",
    {
      input: {
        tariff_content_v2: z
          .record(z.string(), z.unknown())
          .describe("Tesla tariff_content_v2 object, as returned in tesla_energy_site_info."),
      },
    },
  ),

  // Account
  read(
    "tesla_account_products",
    "products",
    "Products.",
    "Every vehicle and energy product on the account, with energy_site_id values for the energy tools.",
  ),
  read(
    "tesla_account_me",
    "user_me",
    "Account.",
    "The signed-in account's profile summary. Needs the user_data scope.",
  ),
  read(
    "tesla_account_region",
    "user_region",
    "Region.",
    "The account's region and its Fleet API base URL. Needs the user_data scope.",
  ),
  read(
    "tesla_account_orders",
    "user_orders",
    "Orders.",
    "The account's active vehicle orders. Needs the user_data scope.",
  ),
  read(
    "tesla_account_feature_config",
    "user_feature_config",
    "Feature configuration.",
    "Feature flags Tesla sets for the account. Needs the user_data scope.",
  ),
];

export const CATALOG: readonly ToolSpec[] = [...SIGNED_TOOLS, ...ENDPOINT_TOOLS];

export function summaryText(value: string | ((input: Input) => string), input: Input): string {
  return typeof value === "string" ? value : value(input);
}
