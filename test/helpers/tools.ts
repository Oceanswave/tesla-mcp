// Shared expectations about the tool surface.

/** Every tool behind DANGEROUS_COMMANDS_ENABLED, written out so adding or
 * ungating one is a deliberate test change. */
export const DANGEROUS_TOOLS = [
  "tesla_charge_port_open",
  "tesla_erase_user_data",
  "tesla_frunk_open",
  "tesla_guest_mode_set",
  "tesla_homelink_trigger",
  "tesla_pin_to_drive_clear_admin",
  "tesla_pin_to_drive_reset",
  "tesla_pin_to_drive_set",
  "tesla_remote_start",
  "tesla_sentry_mode_off",
  "tesla_software_update_schedule",
  "tesla_speed_limit_activate",
  "tesla_speed_limit_clear_pin",
  "tesla_speed_limit_clear_pin_admin",
  "tesla_speed_limit_deactivate",
  "tesla_speed_limit_set",
  "tesla_sunroof_vent",
  "tesla_tonneau_open",
  "tesla_trunk_open",
  "tesla_unlock",
  "tesla_valet_mode_off",
  "tesla_valet_mode_on",
  "tesla_valet_pin_reset",
  "tesla_vehicle_share_invite_create",
  "tesla_windows_vent",
];
