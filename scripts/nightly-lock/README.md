# Nightly lock (outside caller)

Our own routine, kept out of the server: every night at 22:00 America/New_York, a systemd timer on rockybot runs
`lock-car.mjs`. The script:
1. calls `tesla_lock` with `confirm: true` (the server wakes the car if needed, waits for it to come online, retries,
   and reads the lock state back),
2. calls `tesla_vehicle_status` and checks that the car reports `locked`,
3. exits non-zero with a clear message if any step fails.

The server knows nothing about this schedule. To change the time, skip a night, or add a second car, edit the
timer here, not the Worker.

## Files

| File                         | What it is                                                         |
| ---------------------------- | ------------------------------------------------------------------ |
| `lock-car.mjs`               | The caller. Node 22 or newer, no dependencies.                     |
| `tesla-nightly-lock.service` | systemd user service that runs the script once.                    |
| `tesla-nightly-lock.timer`   | systemd user timer: `*-*-* 22:00:00 America/New_York`, persistent. |

## Install on rockybot

```sh
# 1. The bearer token (the Worker's MCP_BEARER_TOKEN), readable only by you.
#    Paste it at the prompt (bash syntax); it is not echoed and never lands in shell history.
( umask 077; read -rs -p "MCP bearer token: " t && printf '%s\n' "$t" > ~/.tesla-mcp-bearer; echo )

# 2. A checkout of this repository at ~/tesla-mcp (the service runs the script from there).
git clone https://github.com/Oceanswave/tesla-mcp ~/tesla-mcp

# 3. Install and start the timer. Adjust ExecStart if `command -v node` is not /usr/bin/node.
mkdir -p ~/.config/systemd/user
cp ~/tesla-mcp/scripts/nightly-lock/tesla-nightly-lock.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tesla-nightly-lock.timer

# 4. Let user timers run while you are logged out.
sudo loginctl enable-linger "$USER"
```

## Check it

```sh
export TESLA_MCP_URL=https://tesla-mcp.baristalabs.io/mcp
node ~/tesla-mcp/scripts/nightly-lock/lock-car.mjs --check     # bearer token and Tesla sign-in; never wakes the car
node ~/tesla-mcp/scripts/nightly-lock/lock-car.mjs --dry-run   # the server describes the lock; nothing is sent
systemctl --user list-timers tesla-nightly-lock.timer           # next run
systemctl --user start tesla-nightly-lock.service               # a real lock, now
journalctl --user -u tesla-nightly-lock.service -n 20           # what happened
```

Exit codes: `0` locked and confirmed; `1` the lock or the confirmation failed (the message says why, for example
`reauth_required`, `pairing_required`, `wake_timeout`, or "reports UNLOCKED"); `2` a setup problem (no URL, no token
file, server unreachable, or the bearer token refused). A failed run leaves the service in the `failed` state.
To get alerted, add `OnFailure=<your-notify-unit>.service` under `[Unit]` in the service.

## When it says `reauth_required`

Tesla no longer accepts the stored sign-in (for example, the refresh token was revoked). One step fixes it: get a
new Tesla refresh token for the account and, in a checkout of this repository, run

```sh
npx wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN
```

and paste the token at the prompt. The next request uses it (any value not seeded before replaces the stored
tokens). Confirm with `lock-car.mjs --check`. Do not give the same refresh token to another Tesla tool: Tesla
rotates refresh tokens on use, so whichever tool refreshes second is locked out.

## Phase A and phase B

**Phase A (now).** The Worker's built-in 22:00 alarm (`NIGHTLY_LOCK_ENABLED="true"`) still runs, and this timer runs
too. Both lock requests go through the same command lane in the server. The second one locks a car that is already
locked, which is harmless. The built-in alarm is the safety net while this caller proves itself.

**Phase B (follow-up PR, after this timer has locked the car and exited 0 on 7 nights in a row; check with
`journalctl`).** First set `NIGHTLY_LOCK_ENABLED` to `"false"` and deploy: the next cron tick deletes the alarm.
After a few more good nights, a second change removes the alarm code, the cron trigger, `tesla_nightly_lock_status`,
and the `NIGHTLY_LOCK_*` vars.

**After phase B, the 10 PM lock happens like this:** at 22:00 America/New_York, systemd on rockybot starts
`tesla-nightly-lock.service`. The service runs `node ~/tesla-mcp/scripts/nightly-lock/lock-car.mjs`, which sends
`tools/call tesla_lock {"confirm": true}` to `https://tesla-mcp.baristalabs.io/mcp` with the bearer token from
`~/.tesla-mcp-bearer`. The Worker wakes, polls, retries, and confirms the lock. The script then reads
`tesla_vehicle_status` and exits 0 only if the car reports locked. Nothing inside the Worker runs on a schedule. If
rockybot is off at 22:00, `Persistent=true` runs the lock as soon as it is back.
