// The dangerous-command gate. Any tool that can unlock, open, start, or
// otherwise weaken the car's security names one of these actions and is only
// registered when DANGEROUS_COMMANDS_ENABLED is exactly "true". OwnerState
// checks the same flag again before it sends any of these commands, so a tool
// registered by mistake still cannot act.

import type { SignedCommandName } from "../tesla/vcp/protocol";

export const DANGEROUS_ACTIONS = [
  "unlock",
  "remote_start",
  "trunk_open",
  "frunk_open",
  "tonneau_open",
  "windows_open",
  "sunroof_open",
  "charge_port_open",
  "sentry_off",
  "valet_mode",
  "pin_to_drive",
  "speed_limit",
  "guest_mode",
  "homelink",
  "erase_user_data",
  "software_update",
  "share_access",
] as const;

export type DangerousAction = (typeof DANGEROUS_ACTIONS)[number];

/** Signed commands that are dangerous whatever their parameters. Sentry Mode
 * is dangerous only when turned off; see dangerousSignedCommand. */
const DANGEROUS_SIGNED_COMMANDS: Partial<Record<SignedCommandName, DangerousAction>> = {
  door_unlock: "unlock",
  remote_start_drive: "remote_start",
  trunk_open: "trunk_open",
  frunk_open: "frunk_open",
  tonneau_open: "tonneau_open",
  window_vent: "windows_open",
  sunroof_vent: "sunroof_open",
  // Opening the port also releases a latched charge cable.
  charge_port_door_open: "charge_port_open",
  set_valet_mode: "valet_mode",
  reset_valet_pin: "valet_mode",
  set_pin_to_drive: "pin_to_drive",
  reset_pin_to_drive_pin: "pin_to_drive",
  clear_pin_to_drive_admin: "pin_to_drive",
  speed_limit_activate: "speed_limit",
  speed_limit_deactivate: "speed_limit",
  speed_limit_set_limit: "speed_limit",
  speed_limit_clear_pin: "speed_limit",
  speed_limit_clear_pin_admin: "speed_limit",
  guest_mode: "guest_mode",
  erase_user_data: "erase_user_data",
  trigger_homelink: "homelink",
  // An installing update leaves the car undrivable for its duration.
  schedule_software_update: "software_update",
};

export function dangerousSignedCommand(
  command: SignedCommandName,
  params: Readonly<Record<string, unknown>>,
): DangerousAction | undefined {
  if (command === "set_sentry_mode") return params.on === true ? undefined : "sentry_off";
  return DANGEROUS_SIGNED_COMMANDS[command];
}

export function dangerousCommandsEnabled(env: { DANGEROUS_COMMANDS_ENABLED?: string }): boolean {
  return env.DANGEROUS_COMMANDS_ENABLED === "true";
}

/** Drop every definition tagged with a dangerous action unless enabled. */
export function gateTools<T extends { dangerousAction?: DangerousAction }>(tools: readonly T[], enabled: boolean): T[] {
  return tools.filter((tool) => enabled || tool.dangerousAction === undefined);
}
