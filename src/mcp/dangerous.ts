// The dangerous-command gate. Any tool that can unlock, open, start, or
// otherwise weaken the car's security names one of these actions and is only
// registered when DANGEROUS_COMMANDS_ENABLED is exactly "true". The MVP
// implements none of them; this list and the gate exist so they cannot be
// added later without it.

export const DANGEROUS_ACTIONS = [
  "unlock",
  "remote_start",
  "trunk_open",
  "frunk_open",
  "windows_open",
  "valet_mode",
  "pin_to_drive",
  "speed_limit",
  "homelink",
  "erase_user_data",
] as const;

export type DangerousAction = (typeof DANGEROUS_ACTIONS)[number];

export function dangerousCommandsEnabled(env: { DANGEROUS_COMMANDS_ENABLED?: string }): boolean {
  return env.DANGEROUS_COMMANDS_ENABLED === "true";
}

/** Drop every definition tagged with a dangerous action unless enabled. */
export function gateTools<T extends { dangerousAction?: DangerousAction }>(tools: readonly T[], enabled: boolean): T[] {
  return tools.filter((tool) => enabled || tool.dangerousAction === undefined);
}
