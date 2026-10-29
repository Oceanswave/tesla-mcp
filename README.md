# tesla-mcp

A private [Model Context Protocol](https://modelcontextprotocol.io) server for one Tesla owner, running on
Cloudflare Workers. It gives an assistant, or any Streamable HTTP MCP client or script, plain tools for the owner's
Tesla vehicles, energy products (Powerwall, solar, Wall Connector), and account: status and data, climate, charging,
closures, media, security settings, navigation, and energy settings. The server has no schedules or routines of its
own: anything recurring, such as a nightly lock, is run by the caller (see
[Locking on a schedule](#locking-on-a-schedule)).

Vehicle commands are sent as signed Vehicle Command Protocol messages (VCSEC for locks and closures, infotainment for
the rest), so they work on vehicles that require Tesla's command signing. The signer is a WebCrypto port checked byte
for byte against Tesla's Go implementation: every command payload, both domains' handshakes and signatures, and the
encrypted replies. [GAP.md](GAP.md) maps every Tesla capability to a tool, or says why there is none.

**Status: owner-only MVP.** One owner, one static bearer token, one Tesla account. Multi-user sign-in with Tesla
OAuth is planned; the auth and storage seams are already in place for it.

## Tools

126 tools. **101** are registered by default; the **25** marked dangerous exist only when
`DANGEROUS_COMMANDS_ENABLED` is `"true"`. Every _command_ needs `confirm: true` and accepts `dryRun: true`; _read_
tools take neither and never wake the car. Vehicle tools take an optional `vehicle_id` and energy tools an optional
`energy_site_id` (left out, the account's only car or site is used). Each tool's description names the Tesla OAuth
scope it needs; see [Scopes](#scopes).

### Core

| Tool                   | Kind    | What it does                                                                                                                                                                                                                                |
| ---------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tesla_vehicles_list`  | read    | List the cars on the owner's Tesla account with their id, name, and whether each is online, asleep, or offline.                                                                                                                             |
| `tesla_vehicle_status` | read    | Get the car's current status: online or asleep, and when online whether it is locked, which doors, trunks, or windows are open, battery percent, range, charging state, inside and outside temperature, climate, Sentry Mode, and odometer. |
| `tesla_wake`           | command | Wake the car so it can report status or take commands.                                                                                                                                                                                      |
| `tesla_lock`           | command | Lock the car's doors with a signed command.                                                                                                                                                                                                 |
| `tesla_auth_status`    | read    | Report whether the server's Tesla sign-in works (authState ok, reauth_required, or not_configured) and, when ok, the OAuth scopes the sign-in grants.                                                                                       |
| `tesla_audit_recent`   | read    | Show the most recent entries in the audit log of commands, wakes, and sign-in events, newest first.                                                                                                                                         |
| `tesla_vehicle_ping`   | read    | Check that the car is online and accepts this server's signed commands (its virtual key is paired) by sending a signed no-op.                                                                                                               |

### Doors, closures, and alerts

| Tool                  | Kind                   | What it does                                                                    |
| --------------------- | ---------------------- | ------------------------------------------------------------------------------- |
| `tesla_unlock`        | command, **dangerous** | Unlock the car's doors.                                                         |
| `tesla_remote_start`  | command, **dangerous** | Enable keyless driving (remote start) for two minutes.                          |
| `tesla_auto_secure`   | command                | Close the powered doors and lock the car (Model X falcon-wing and front doors). |
| `tesla_trunk_open`    | command, **dangerous** | Open the rear trunk.                                                            |
| `tesla_trunk_close`   | command                | Close a powered rear trunk.                                                     |
| `tesla_frunk_open`    | command, **dangerous** | Open the front trunk (frunk).                                                   |
| `tesla_tonneau_open`  | command, **dangerous** | Open the powered tonneau cover (Cybertruck).                                    |
| `tesla_tonneau_close` | command                | Close the powered tonneau cover (Cybertruck).                                   |
| `tesla_tonneau_stop`  | command                | Stop a moving tonneau cover (Cybertruck).                                       |
| `tesla_windows_vent`  | command, **dangerous** | Vent (slightly open) all windows.                                               |
| `tesla_windows_close` | command                | Close all windows.                                                              |
| `tesla_sunroof_vent`  | command, **dangerous** | Vent the sunroof, on cars with a powered sunroof.                               |
| `tesla_sunroof_close` | command                | Close the sunroof, on cars with a powered sunroof.                              |
| `tesla_honk_horn`     | command                | Honk the horn once.                                                             |
| `tesla_flash_lights`  | command                | Flash the headlights once.                                                      |

### Climate and seats

| Tool                                           | Kind    | What it does                                                                         |
| ---------------------------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `tesla_climate_start`                          | command | Turn on climate control (precondition the cabin) at the current settings.            |
| `tesla_climate_stop`                           | command | Turn off climate control.                                                            |
| `tesla_climate_set_temperatures`               | command | Set the driver and passenger cabin temperatures, in Celsius (15-28).                 |
| `tesla_climate_set_preconditioning_max`        | command | Turn Defrost (maximum preconditioning) on or off.                                    |
| `tesla_climate_set_bioweapon_mode`             | command | Turn Bioweapon Defense Mode on or off, on cars with a HEPA filter.                   |
| `tesla_climate_set_cabin_overheat_protection`  | command | Turn Cabin Overheat Protection on or off, optionally fan only (no A/C).              |
| `tesla_climate_set_cabin_overheat_temperature` | command | Set the temperature at which Cabin Overheat Protection starts: low, medium, or high. |
| `tesla_climate_set_keeper_mode`                | command | Set Climate Keeper: off, on (Keep), dog (Dog Mode), or camp (Camp Mode).             |
| `tesla_seat_heater_set`                        | command | Set seat heater levels for one or more seats.                                        |
| `tesla_seat_cooler_set`                        | command | Set a front seat's ventilation (cooling) level, on cars with ventilated seats.       |
| `tesla_seat_auto_climate_set`                  | command | Turn automatic seat heating and cooling on or off for a front seat.                  |
| `tesla_steering_wheel_heater_set`              | command | Turn the steering wheel heater on or off.                                            |

### Charging and schedules

| Tool                                     | Kind                   | What it does                                                                                         |
| ---------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------- |
| `tesla_charge_start`                     | command                | Start charging.                                                                                      |
| `tesla_charge_stop`                      | command                | Stop charging.                                                                                       |
| `tesla_charge_standard`                  | command                | Set the charge limit to the car's standard (daily) level.                                            |
| `tesla_charge_max_range`                 | command                | Set the charge limit to maximum range (100%), for trips.                                             |
| `tesla_charge_set_limit`                 | command                | Set the charge limit, 50 to 100 percent.                                                             |
| `tesla_charge_set_amps`                  | command                | Set the charging current in amps (1-80).                                                             |
| `tesla_charge_port_open`                 | command, **dangerous** | Open the charge port door.                                                                           |
| `tesla_charge_port_close`                | command                | Close the charge port door.                                                                          |
| `tesla_charge_set_scheduled_charging`    | command                | Set or turn off the single scheduled charging start time.                                            |
| `tesla_charge_set_scheduled_departure`   | command                | Set the scheduled departure: the car preconditions and/or charges off-peak to be ready by this time. |
| `tesla_charge_clear_scheduled_departure` | command                | Turn off scheduled departure.                                                                        |
| `tesla_charge_schedule_add`              | command                | Add or replace a charge schedule (firmware 2024.26+).                                                |
| `tesla_charge_schedule_remove`           | command                | Remove one charge schedule by id.                                                                    |
| `tesla_charge_schedules_remove`          | command                | Remove all charge schedules at home, work, and/or other locations.                                   |
| `tesla_precondition_schedule_add`        | command                | Add or replace a cabin preconditioning schedule (firmware 2024.26+), applied at the given location.  |
| `tesla_precondition_schedule_remove`     | command                | Remove one preconditioning schedule by id.                                                           |
| `tesla_precondition_schedules_remove`    | command                | Remove all preconditioning schedules at home, work, and/or other locations.                          |

### Media and power

| Tool                             | Kind    | What it does                                                                      |
| -------------------------------- | ------- | --------------------------------------------------------------------------------- |
| `tesla_low_power_mode_set`       | command | Turn Low Power Mode on or off (Cybertruck).                                       |
| `tesla_keep_accessory_power_set` | command | Turn Keep Accessory Power on or off (keeps 12 V outlets and accessories powered). |
| `tesla_media_set_volume`         | command | Set the media volume, 0 to 10.                                                    |
| `tesla_media_volume_up`          | command | Turn the media volume up one step.                                                |
| `tesla_media_volume_down`        | command | Turn the media volume down one step.                                              |
| `tesla_media_toggle_playback`    | command | Play or pause media.                                                              |
| `tesla_media_next_track`         | command | Skip to the next track.                                                           |
| `tesla_media_previous_track`     | command | Go to the previous track.                                                         |
| `tesla_media_next_favorite`      | command | Go to the next favorite station.                                                  |
| `tesla_media_previous_favorite`  | command | Go to the previous favorite station.                                              |

### Security, access, and settings

| Tool                                | Kind                   | What it does                                                                                      |
| ----------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------- |
| `tesla_sentry_mode_on`              | command                | Turn Sentry Mode on.                                                                              |
| `tesla_sentry_mode_off`             | command, **dangerous** | Turn Sentry Mode off.                                                                             |
| `tesla_valet_mode_on`               | command, **dangerous** | Turn Valet Mode on with a four-digit PIN.                                                         |
| `tesla_valet_mode_off`              | command, **dangerous** | Turn Valet Mode off.                                                                              |
| `tesla_valet_pin_reset`             | command, **dangerous** | Clear the Valet Mode PIN.                                                                         |
| `tesla_pin_to_drive_set`            | command, **dangerous** | Turn PIN to Drive on (with a new four-digit PIN) or off (with the current PIN).                   |
| `tesla_pin_to_drive_reset`          | command, **dangerous** | Reset the PIN to Drive PIN (owner and fleet manager only).                                        |
| `tesla_pin_to_drive_clear_admin`    | command, **dangerous** | Turn off PIN to Drive and clear its PIN without the PIN (owner and fleet manager only).           |
| `tesla_speed_limit_activate`        | command, **dangerous** | Turn Speed Limit Mode on with its four-digit PIN.                                                 |
| `tesla_speed_limit_deactivate`      | command, **dangerous** | Turn Speed Limit Mode off with its four-digit PIN.                                                |
| `tesla_speed_limit_set`             | command, **dangerous** | Set the Speed Limit Mode maximum speed, 50 to 120 mph.                                            |
| `tesla_speed_limit_clear_pin`       | command, **dangerous** | Clear the Speed Limit Mode PIN (also turns Speed Limit Mode off).                                 |
| `tesla_speed_limit_clear_pin_admin` | command, **dangerous** | Clear the Speed Limit Mode PIN without the PIN (owner and fleet manager only; firmware 2023.38+). |
| `tesla_guest_mode_set`              | command, **dangerous** | Turn Guest Mode on or off.                                                                        |
| `tesla_erase_user_data`             | command, **dangerous** | Erase user data (profiles, settings, linked accounts) from the car.                               |
| `tesla_homelink_trigger`            | command, **dangerous** | Trigger HomeLink (garage door or gate).                                                           |
| `tesla_software_update_schedule`    | command, **dangerous** | Schedule installing a downloaded software update after a delay in seconds (0 = now).              |
| `tesla_software_update_cancel`      | command                | Cancel a scheduled software update that has not started installing.                               |
| `tesla_vehicle_set_name`            | command                | Rename the car.                                                                                   |

### Vehicle data, sharing, and Fleet Telemetry

| Tool                                          | Kind                   | What it does                                                                                                                                                          |
| --------------------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tesla_vehicle_data`                          | read                   | Live vehicle data from the categories you name (vehicle_data).                                                                                                        |
| `tesla_vehicle_data_cached`                   | read                   | The last data the car reported, even while it is asleep or offline (never contacts the car).                                                                          |
| `tesla_vehicle_mobile_enabled`                | read                   | Whether mobile (remote) access is enabled in the car.                                                                                                                 |
| `tesla_vehicle_nearby_charging_sites`         | read                   | Superchargers and destination chargers near the car's current location, with availability.                                                                            |
| `tesla_vehicle_recent_alerts`                 | read                   | Recent alerts the car has raised.                                                                                                                                     |
| `tesla_vehicle_release_notes`                 | read                   | Release notes for the car's installed firmware.                                                                                                                       |
| `tesla_vehicle_service_data`                  | read                   | The car's service status (for example an open service visit).                                                                                                         |
| `tesla_vehicle_fleet_status`                  | read                   | Firmware version, whether signed commands are required, Fleet Telemetry version, and the number of keys.                                                              |
| `tesla_vehicle_options`                       | read                   | The car's option and configuration details.                                                                                                                           |
| `tesla_vehicle_warranty`                      | read                   | Warranty information for the car.                                                                                                                                     |
| `tesla_vehicle_eligible_subscriptions`        | read                   | Subscriptions the car is eligible for (for example Premium Connectivity).                                                                                             |
| `tesla_vehicle_eligible_upgrades`             | read                   | Software upgrades the car is eligible for.                                                                                                                            |
| `tesla_vehicle_charging_history`              | read                   | Paid charging history (Supercharger sessions, fees) for the car.                                                                                                      |
| `tesla_vehicle_fleet_telemetry_config`        | read                   | The car's Fleet Telemetry streaming configuration for this app: whether it is synced and whether the config limit is reached.                                         |
| `tesla_vehicle_fleet_telemetry_errors`        | read                   | Recent Fleet Telemetry errors the car reported for this app's configuration.                                                                                          |
| `tesla_vehicle_fleet_telemetry_config_delete` | command                | Remove this app's Fleet Telemetry streaming configuration from the car.                                                                                               |
| `tesla_vehicle_drivers_list`                  | read                   | Drivers who have access to the car through sharing (owner only).                                                                                                      |
| `tesla_vehicle_driver_remove`                 | command                | Remove a shared driver's access to the car.                                                                                                                           |
| `tesla_vehicle_share_invites_list`            | read                   | Active invitations to share the car.                                                                                                                                  |
| `tesla_vehicle_share_invite_create`           | command, **dangerous** | Create a single-use invitation link (valid 24 hours) that gives whoever redeems it driver access to the car in the Tesla app, including location and remote commands. |
| `tesla_vehicle_share_invite_revoke`           | command                | Revoke a share invitation so its link no longer works.                                                                                                                |

### Navigation and sound

| Tool                                 | Kind    | What it does                                                                                     |
| ------------------------------------ | ------- | ------------------------------------------------------------------------------------------------ |
| `tesla_navigation_send_destination`  | command | Send an address or place name to the car's navigation, as sharing it from the Tesla app does.    |
| `tesla_navigation_send_coordinates`  | command | Start navigation to coordinates.                                                                 |
| `tesla_navigation_send_supercharger` | command | Start navigation to a Supercharger by id (for example from tesla_vehicle_nearby_charging_sites). |
| `tesla_navigation_send_waypoints`    | command | Send a multi-stop route to the car's navigation as Google Maps place ids, in order.              |
| `tesla_play_sound`                   | command | Play a sound on the external speaker (Boombox): locate_ping or fart.                             |

### Energy (Powerwall, solar, Wall Connector)

| Tool                                                 | Kind    | What it does                                                                                                                             |
| ---------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `tesla_energy_live_status`                           | read    | Live power flows (solar, battery, grid, home), battery percent, grid status, and Storm Watch state.                                      |
| `tesla_energy_site_info`                             | read    | Site configuration: installed assets, backup reserve, operation mode, tariff, and supported features.                                    |
| `tesla_energy_site_status`                           | read    | Battery percent and power, site name, and Storm Watch state.                                                                             |
| `tesla_energy_backup_time_remaining`                 | read    | Estimated hours the battery can power the home in an outage at the current load.                                                         |
| `tesla_energy_history`                               | read    | Energy produced, consumed, imported, and exported, aggregated by period (Wh).                                                            |
| `tesla_energy_backup_history`                        | read    | Past grid outages (backup events) and their duration.                                                                                    |
| `tesla_energy_charge_history`                        | read    | Wall Connector charging sessions and energy (Wh).                                                                                        |
| `tesla_energy_charger_live_status`                   | read    | Live state and power of the site's Wall Connectors.                                                                                      |
| `tesla_energy_tariff_rate`                           | read    | The site's utility rate plan: time-of-use periods and buy and sell prices.                                                               |
| `tesla_energy_set_backup_reserve`                    | command | Set the battery's backup reserve: the percent kept for outages.                                                                          |
| `tesla_energy_set_operation_mode`                    | command | Set the operation mode: self_consumption (self-powered) or autonomous (time-based control).                                              |
| `tesla_energy_set_storm_watch`                       | command | Turn Storm Watch on or off (charge fully ahead of severe weather).                                                                       |
| `tesla_energy_set_grid_import_export`                | command | Allow or disallow charging the battery from the grid, and set what may be exported to the grid: pv_only, battery_ok, or never.           |
| `tesla_energy_set_off_grid_vehicle_charging_reserve` | command | During an outage, stop charging vehicles from the battery below this percent.                                                            |
| `tesla_energy_set_time_of_use`                       | command | Replace the site's time-of-use tariff with tariff_content_v2 (Tesla's tariff structure: seasons, energy_charges, sell_tariff, currency). |

### Account

| Tool                           | Kind | What it does                                                                                      |
| ------------------------------ | ---- | ------------------------------------------------------------------------------------------------- |
| `tesla_account_products`       | read | Every vehicle and energy product on the account, with energy_site_id values for the energy tools. |
| `tesla_account_me`             | read | The signed-in account's profile summary.                                                          |
| `tesla_account_region`         | read | The account's region and its Fleet API base URL.                                                  |
| `tesla_account_orders`         | read | The account's active vehicle orders.                                                              |
| `tesla_account_feature_config` | read | Feature flags Tesla sets for the account.                                                         |

## Safety model

- **Confirmation required.** Every state-changing tool refuses to act unless called with `confirm: true`, and
  accepts `dryRun: true` to describe the action without contacting the car. Refusals are audited.
- **Dangerous commands are off by default.** Unlock, remote start, opening the trunk, frunk, tonneau, windows,
  sunroof, or charge port, turning Sentry Mode off, Valet Mode, PIN to Drive, Speed Limit Mode, Guest Mode, data
  erase, HomeLink, scheduling a software update, and creating a share invite are only registered when
  `DANGEROUS_COMMANDS_ENABLED` is exactly `"true"` (default `"false"`). The server checks the same flag again before
  sending any of them.
- **Never wakes implicitly.** Reads report "asleep" instead of waking the car, and commands to an asleep car fail
  with `vehicle_asleep`. Only `tesla_wake` and `tesla_lock` wake it.
- **Explicit allowlists.** The signer only builds the commands in `SIGNED_COMMANDS`, and REST calls only go to the
  endpoints in `src/tesla/endpoints.ts`, from fixed path templates. It is not a generic proxy.
- **Secrets stay secret.** Tesla tokens are stored AES-256-GCM encrypted in a Durable Object. Tokens, keys, and
  raw Tesla responses are never logged or written to the audit log.
- **Fail closed.** No `MCP_BEARER_TOKEN` means every `/mcp` request is refused. A command key that does not match
  the published public key refuses to sign.

## Locking

`tesla_lock` (with `confirm: true`) is the one lock, for assistants and scripts alike. If the car is asleep or
offline it is woken and polled until online (up to about 90 seconds), and the lock is retried, up to 4 attempts
within 7 minutes. Failures Tesla marks as not retryable stop at once. If a lock response is lost, the car's lock state
is checked instead of sending the lock again. After Tesla accepts the lock, the car's lock state is read back; a car
that still reports unlocked gets another attempt. The result says `locked`, `confirmed` (the car itself reported
locked), `woke`, and `attempts`. A failure carries `error` and a specific `reason` such as `pairing_required`,
`wake_timeout`, `still_unlocked`, or `reauth_required`.

## Locking on a schedule

The server runs nothing on its own. To lock the car every night (or on any other schedule), let your own scheduler
(cron, a systemd timer, an assistant's routine, a CI job) call the MCP tools at `https://<your-domain>/mcp` with
`Authorization: Bearer <MCP_BEARER_TOKEN>`:
1. Optionally call `tesla_auth_status`. If `authState` is `reauth_required`, alert the owner to sign in again
   (below) instead of trying to lock.
2. Call `tesla_lock` with `{"confirm": true}` (and `vehicle_id` if the account has more than one car). Allow the
   call up to about 8 minutes: an asleep car is woken and retried within the 7-minute budget.
3. Treat `locked: true` as success; `confirmed: false` means Tesla accepted the lock but the car's state could not
   be read back. On `isError`, alert on `error` and `reason` (for example `reauth_required`, `pairing_required`,
   `wake_timeout`, `still_unlocked`). Do not loop on failures: the tool has already retried.

Every call is in the audit log (`tesla_audit_recent`).

## Scopes

Browser sign-in (`/login`) asks Tesla for all nine scopes the tools use, with `prompt_missing_scopes=true` so an
earlier, narrower grant is widened:
`openid offline_access vehicle_device_data vehicle_cmds vehicle_location vehicle_charging_cmds user_data energy_device_data energy_cmds`.
Your developer app must allow each of them (tick them in the developer portal), or Tesla grants fewer. Tesla may
also let the owner untick some on its consent page. `tesla_auth_status` lists the scopes the stored sign-in
actually has. `openid offline_access vehicle_device_data vehicle_cmds` covers every vehicle tool except
`tesla_vehicle_charging_history` and location data. The rest need:

| Scope                   | Tools                                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| `vehicle_location`      | `tesla_vehicle_data` with `location_data`                                                          |
| `vehicle_charging_cmds` | `tesla_vehicle_charging_history`                                                                   |
| `user_data`             | `tesla_account_me`, `tesla_account_region`, `tesla_account_orders`, `tesla_account_feature_config` |
| `energy_device_data`    | the `tesla_energy_*` read tools                                                                    |
| `energy_cmds`           | the `tesla_energy_set_*` tools                                                                     |

Without them those tools fail with `forbidden` and name the missing scope. A refresh token from elsewhere
(`TESLA_BOOTSTRAP_REFRESH_TOKEN`) keeps whatever scopes it was issued with. [GAP.md](GAP.md) has the full mapping.

## Self-hosting

You need a Tesla developer account, a Cloudflare account, and a domain you control (Tesla fetches your public key
from it). Node 22 or newer.
1. **Create a Tesla developer application** at [developer.tesla.com](https://developer.tesla.com). Set the allowed
   origin to `https://<your-domain>` and the redirect URI to `https://<your-domain>/callback` (add the redirect URI
   of every host you will open `/login` on). Tick the scopes listed under [Scopes](#scopes): vehicle information,
   vehicle location, vehicle commands, vehicle charging management, profile information, energy product
   information, and energy product commands.

2. **Generate a P-256 command key** somewhere outside this repository (`*.pem` and `keys/` are gitignored, but keep
   the private key off disk where you can):

   ```sh
   openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
   openssl ec -in private-key.pem -pubout -out public-key.pem
   ```

3. **Publish the public key.** Put the contents of `public-key.pem` in `TESLA_PUBLIC_KEY_PEM` in `wrangler.jsonc`
   (newlines as `\n`). After deploying, it is served at
   `https://<your-domain>/.well-known/appspecific/com.tesla.3p.public-key.pem`. If your account is outside North
   America, change `TESLA_FLEET_BASE_URL` to your region's Fleet API host.

4. **Set secrets** (see `.dev.vars.example` for what each one is):

   ```sh
   npx wrangler secret put MCP_BEARER_TOKEN
   npx wrangler secret put TESLA_CLIENT_ID
   npx wrangler secret put TESLA_CLIENT_SECRET
   openssl pkcs8 -topk8 -nocrypt -in private-key.pem -outform DER | base64 | tr -d '\n' \
     | npx wrangler secret put TESLA_COMMAND_PRIVATE_KEY_PKCS8_B64
   openssl rand -base64 32 | npx wrangler secret put TOKEN_ENCRYPTION_KEY
   npx wrangler secret put TESLA_REDIRECT_URI              # optional, see step 7
   npx wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN   # optional, see step 7
   npx wrangler secret put TESLA_VEHICLE_ID                # optional
   ```

5. **Deploy** with `npm ci && npx wrangler deploy`, then attach your domain to the Worker (Workers & Pages → your
   Worker → Domains & Routes → Custom domain). You can smoke-test `/healthz` on your workers.dev URL first, but
   Tesla registration needs your own domain.

6. **Register as a Tesla partner** for your domain (once per region), using a partner token:

   ```sh
   PARTNER_TOKEN=$(curl -s -X POST https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token \
     -d grant_type=client_credentials -d client_id="$TESLA_CLIENT_ID" -d client_secret="$TESLA_CLIENT_SECRET" \
     -d scope="openid vehicle_device_data vehicle_cmds" \
     -d audience=https://fleet-api.prd.na.vn.cloud.tesla.com | jq -r .access_token)
   curl -s -X POST https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/partner_accounts \
     -H "Authorization: Bearer $PARTNER_TOKEN" -H 'Content-Type: application/json' \
     -d '{"domain":"<your-domain>"}'
   ```

7. **Sign in with Tesla.** Open `https://<your-domain>/login` in a browser, sign in to Tesla, and approve the
   scopes. Tesla sends you back to `/callback`, which exchanges the code, stores the tokens encrypted (replacing
   any stored ones), and shows `Tesla sign-in updated, scopes: ...` with the scopes Tesla granted. The link from
   `/login` works once, for ten minutes. The redirect URI sent to Tesla is this origin's `/callback`; set
   `TESLA_REDIRECT_URI` to pin one exact value (it must match the developer app's redirect URI exactly). Tesla
   rotates refresh tokens and the Worker keeps the newest, so do not share this sign-in with another Tesla tool:
   whichever one refreshes second is locked out.

   `/login` is public, so once an account is signed in, `/callback` only accepts the same Tesla account (by the
   access token's `sub`); a sign-in with any other account is refused and changes nothing. To move the server to
   another account, set a refresh token for it with `TESLA_BOOTSTRAP_REFRESH_TOKEN` (below).

   Instead of the browser, you can complete Tesla's authorization-code flow elsewhere and store the refresh token
   with `npx wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN`. It seeds the encrypted token store once per
   distinct value; a browser sign-in supersedes the value set at the time.

   **Signing in again (`reauth_required`).** If Tesla rejects the stored sign-in (a revoked or expired refresh
   token), every tool fails with `reauth_required`, a code-only error is logged, and no further refreshes are tried.
   Open `https://<your-domain>/login` again. Alternatively, run `npx wrangler secret put
   TESLA_BOOTSTRAP_REFRESH_TOKEN` with a new refresh token: any value that has not been seeded before replaces the
   stored tokens on the next request; setting the same value again does nothing.

8. **Pair the virtual key with the car.** On the phone with the Tesla app, open `https://tesla.com/_ak/<your-domain>`
   and approve the key. Signed commands fail with "pairing required" until this is done.

9. **Connect your MCP client** to `https://<your-domain>/mcp` with the header
   `Authorization: Bearer <MCP_BEARER_TOKEN>`.

## Development

```sh
npm ci
npm run check       # typecheck, Biome lint, tests
npm run deploy:dry  # bundle without deploying
```

Tests run in the Workers runtime against a simulated Tesla (Fleet API, OAuth, energy sites, and a vehicle that runs
real VCSEC and infotainment sessions: ECDH handshakes, signature checks, and encrypted replies). All test credentials
are generated at runtime. The Python cross-check of the VCSEC lock in `test/vcp-vectors.test.ts` comes from
`scripts/vcsec_vectors.py`.

`bash conformance/run.sh` (needs Go and git) checks the shared vectors against Tesla's official Go implementation at
a pinned commit of `teslamotors/vehicle-command`:
- `test/vectors/vcsec-lock.json` and `test/vectors/infotainment-honk.json`: key derivation, the handshake, signing,
  the response request hash, and AES-GCM reply decryption, in both domains, through Tesla's Signer and Verifier.
- `test/vectors/vcp-commands.json`: the payload of every signed command, byte for byte, as Tesla's own
  `pkg/vehicle` methods build it.

CI runs it as the `go-conformance` job. Without a local Go, `docker run --rm -v "$PWD":/repo:ro -w /repo
golang:1.27.3 bash conformance/run.sh` works too.

## License

MIT. See [LICENSE](LICENSE).
