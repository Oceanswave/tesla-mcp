// Every signed command's payload must be byte-identical to what Tesla's Go
// client builds for the same call. The expected bytes in
// test/vectors/vcp-commands.json were produced by Tesla's own code at the
// commit pinned in conformance/run.sh, which re-checks them in CI
// (go-conformance, conformance/go/tesla_mcp_commands_test.go).

import { describe, expect, it } from "vitest";
import { bytesFromHex, bytesToHex } from "../src/bytes";
import { CommandParamError } from "../src/tesla/vcp/payloads";
import { encodeLengthDelimited, encodeStringField, encodeVarintField } from "../src/tesla/vcp/proto";
import {
  DOMAIN_INFOTAINMENT,
  DOMAIN_VEHICLE_SECURITY,
  FLAG_ENCRYPT_RESPONSE,
  isSignedCommandName,
  parseCarServerResult,
  SIGNED_COMMANDS,
} from "../src/tesla/vcp/protocol";
import COMMANDS from "./vectors/vcp-commands.json";

describe("signed command payloads match Tesla's vehicle-command", () => {
  for (const vector of COMMANDS.vectors) {
    it(`${vector.id}`, () => {
      expect(isSignedCommandName(vector.command)).toBe(true);
      if (!isSignedCommandName(vector.command)) return;
      const spec = SIGNED_COMMANDS[vector.command];
      expect(spec.domain).toBe(vector.domain);
      expect(bytesToHex(spec.payload(vector.params))).toBe(vector.payload);
    });
  }

  it("has a Tesla vector for every signed command, and nothing else", () => {
    const covered = new Set(COMMANDS.vectors.map((vector) => vector.command));
    expect([...covered].sort()).toEqual(Object.keys(SIGNED_COMMANDS).sort());
    expect(new Set(COMMANDS.vectors.map((vector) => vector.id)).size).toBe(COMMANDS.vectors.length);
  });

  it("uses VCSEC without flags and infotainment with an encrypted reply", () => {
    for (const spec of Object.values(SIGNED_COMMANDS)) {
      if (spec.domain === DOMAIN_VEHICLE_SECURITY) expect(spec.flags).toBe(0);
      else expect([spec.domain, spec.flags]).toEqual([DOMAIN_INFOTAINMENT, FLAG_ENCRYPT_RESPONSE]);
    }
  });

  it("is an allowlist: unknown names and inherited properties are not commands", () => {
    for (const name of ["", "get", "post", "toString", "__proto__", "constructor", "door_lock "]) {
      expect(isSignedCommandName(name)).toBe(false);
    }
  });
});

describe("signed command parameters are checked before anything is built", () => {
  const rejects = (command: keyof typeof SIGNED_COMMANDS, params: Record<string, unknown>, param: string) => {
    let caught: unknown;
    try {
      SIGNED_COMMANDS[command].payload(params);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CommandParamError);
    expect((caught as CommandParamError).param).toBe(param);
  };

  it("rejects out-of-range numbers", () => {
    rejects("set_charge_limit", { percent: 49 }, "percent");
    rejects("set_charge_limit", { percent: 101 }, "percent");
    rejects("set_charge_limit", { percent: 80.5 }, "percent");
    rejects("set_charge_limit", { percent: "80" }, "percent");
    rejects("set_charging_amps", { charging_amps: 0 }, "charging_amps");
    rejects("set_temps", { driver_temp_celsius: 40, passenger_temp_celsius: 20 }, "driver_temp_celsius");
    rejects("set_temps", { driver_temp_celsius: 20, passenger_temp_celsius: Number.NaN }, "passenger_temp_celsius");
    rejects("adjust_volume", { volume: 11 }, "volume");
    rejects("speed_limit_set_limit", { limit_mph: 49 }, "limit_mph");
    rejects("set_scheduled_charging", { enabled: true, time_minutes: 1440 }, "time_minutes");
    rejects("schedule_software_update", { offset_seconds: -1 }, "offset_seconds");
    rejects("trigger_homelink", { latitude: 91, longitude: 0 }, "latitude");
  });

  it("rejects missing or malformed PINs", () => {
    rejects("set_valet_mode", { on: true }, "pin");
    rejects("set_valet_mode", { on: true, pin: "12345" }, "pin");
    rejects("set_pin_to_drive", { on: true, pin: "12a4" }, "pin");
    rejects("speed_limit_activate", { pin: 1234 }, "pin");
  });

  it("rejects unknown enum values and bad seat lists", () => {
    rejects("set_cop_temp", { level: "max" }, "level");
    rejects("set_climate_keeper_mode", { mode: "pet" }, "mode");
    rejects("remote_seat_cooler_request", { seat: "rear_left", level: "low" }, "seat");
    rejects("remote_seat_heater_request", { seats: [] }, "seats");
    rejects("remote_seat_heater_request", { seats: [{ seat: "front_left", level: "max" }] }, "level");
    rejects(
      "remote_seat_heater_request",
      {
        seats: [
          { seat: "front_left", level: "low" },
          { seat: "front_left", level: "high" },
        ],
      },
      "seats",
    );
    rejects("set_scheduled_departure", { departure_minutes: 60, preconditioning: "daily" }, "preconditioning");
  });

  it("rejects bad schedules", () => {
    const schedule = {
      id: 1,
      days_of_week: ["monday"],
      start_enabled: true,
      start_time_minutes: 60,
      end_enabled: false,
      latitude: 1,
      longitude: 2,
    };
    rejects("add_charge_schedule", { ...schedule, days_of_week: [] }, "days_of_week");
    rejects("add_charge_schedule", { ...schedule, days_of_week: ["monday", "monday"] }, "days_of_week");
    rejects("add_charge_schedule", { ...schedule, days_of_week: ["funday"] }, "days_of_week");
    rejects("add_charge_schedule", { ...schedule, start_enabled: false }, "start_enabled");
    rejects("add_charge_schedule", { ...schedule, id: 0 }, "id");
    rejects("add_charge_schedule", { ...schedule, name: "a\nb" }, "name");
    rejects("batch_remove_charge_schedules", {}, "home");
  });

  it("rejects vehicle names that are empty, long, or contain control characters", () => {
    rejects("set_vehicle_name", { name: "" }, "name");
    rejects("set_vehicle_name", { name: "   " }, "name");
    rejects("set_vehicle_name", { name: "x".repeat(65) }, "name");
    rejects("set_vehicle_name", { name: "a\u0007b" }, "name");
  });
});

describe("CarServer responses", () => {
  const status = (result: number, reason?: string) =>
    encodeLengthDelimited(
      1,
      new Uint8Array([
        ...(result ? encodeVarintField(1, result) : []),
        ...(reason === undefined ? [] : encodeLengthDelimited(2, encodeStringField(1, reason))),
      ]),
    );

  it("treats an empty response or OPERATIONSTATUS_OK as success", () => {
    expect(parseCarServerResult(new Uint8Array())).toEqual({ status: "ok" });
    expect(parseCarServerResult(status(0))).toEqual({ status: "ok" });
  });

  it("reports OPERATIONSTATUS_ERROR with the car's reason", () => {
    expect(parseCarServerResult(status(1, "is_charging"))).toEqual({ status: "error", reason: "is_charging" });
    expect(parseCarServerResult(status(1))).toEqual({ status: "error", reason: "unspecified" });
  });

  it("drops reasons that are long or not printable, and never trusts garbage", () => {
    expect(parseCarServerResult(status(1, "x".repeat(81)))).toEqual({ status: "error", reason: "unspecified" });
    expect(parseCarServerResult(status(1, "bad\u0000text"))).toEqual({ status: "error", reason: "unspecified" });
    expect(parseCarServerResult(status(7))).toEqual({ status: "unknown" });
    expect(parseCarServerResult(bytesFromHex("0aff"))).toEqual({ status: "unknown" });
  });
});
