#!/usr/bin/env node
// Lock the car through tesla-mcp, then check that it reports locked.
//
// This is the owner's routine, kept outside the server: a systemd timer runs
// it at 22:00 America/New_York (see README.md next to this file). The server
// only offers plain tools; when and how often to lock is decided here.
//
//   node lock-car.mjs            lock, then confirm with tesla_vehicle_status
//   node lock-car.mjs --dry-run  ask the server to describe the lock; sends nothing to the car
//   node lock-car.mjs --check    list the cars (checks the bearer token and Tesla sign-in; never wakes the car)
//
// Settings (environment):
//   TESLA_MCP_URL          required, the MCP endpoint, e.g. https://<your-domain>/mcp
//   TESLA_MCP_BEARER_FILE  file holding the bearer token (default ~/.tesla-mcp-bearer)
//   TESLA_VEHICLE_ID       optional, the car to lock when the account has more than one
//
// Exit codes: 0 locked and confirmed, 1 the lock or the confirmation failed,
// 2 a setup problem (missing URL or token, server unreachable, token refused).
// The bearer token is never printed.

import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const LOCK_TIMEOUT_MS = 10 * 60_000; // the server stops starting new attempts after 7 minutes
const READ_TIMEOUT_MS = 60_000;
const REAUTH_FIX =
  "Fix: get a new Tesla refresh token, run `npx wrangler secret put TESLA_BOOTSTRAP_REFRESH_TOKEN` in the " +
  "tesla-mcp checkout, then `node lock-car.mjs --check`.";

class SetupError extends Error {}

function readBearer() {
  const file = process.env.TESLA_MCP_BEARER_FILE || join(homedir(), ".tesla-mcp-bearer");
  let token;
  try {
    if ((statSync(file).mode & 0o077) !== 0) {
      console.error(`warning: ${file} is readable by other users; run: chmod 600 ${file}`);
    }
    token = readFileSync(file, "utf8").trim();
  } catch {
    throw new SetupError(`cannot read the bearer token file ${file}`);
  }
  if (!token) throw new SetupError(`the bearer token file ${file} is empty`);
  return token;
}

let nextId = 1;

/** One MCP JSON-RPC request over Streamable HTTP (the server is stateless). */
async function rpc(url, token, method, params, timeoutMs) {
  const id = nextId++;
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new SetupError(`cannot reach ${url} (${error?.name ?? "error"})`);
  }
  if (response.status === 401) throw new SetupError("the server refused the bearer token (HTTP 401)");
  if (!response.ok) throw new SetupError(`the server answered HTTP ${response.status}`);
  const text = await response.text();
  // JSON, or server-sent events whose data lines carry the JSON-RPC reply.
  const bodies = text.trimStart().startsWith("{")
    ? [text]
    : text
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trim());
  for (const body of bodies) {
    let message;
    try {
      message = JSON.parse(body);
    } catch {
      continue;
    }
    if (message.id !== id) continue;
    if (message.error) throw new SetupError(`MCP error ${message.error.code}: ${message.error.message}`);
    return message.result;
  }
  throw new SetupError("the server sent no reply to the request");
}

async function callTool(url, token, name, args, timeoutMs) {
  const result = await rpc(url, token, "tools/call", { name, arguments: args }, timeoutMs);
  return { isError: result?.isError === true, data: result?.structuredContent ?? {} };
}

function fail(message, what = "LOCK") {
  console.error(`${what} FAILED: ${message}`);
  process.exitCode = 1;
}

async function main() {
  const mode = process.argv[2] ?? "";
  if (!["", "--dry-run", "--check"].includes(mode)) {
    throw new SetupError(`unknown option ${mode}; use --dry-run or --check`);
  }
  const url = process.env.TESLA_MCP_URL;
  if (!url) throw new SetupError("TESLA_MCP_URL is not set");
  const token = readBearer();
  const vehicle = process.env.TESLA_VEHICLE_ID ? { vehicle_id: process.env.TESLA_VEHICLE_ID } : {};

  await rpc(
    url,
    token,
    "initialize",
    { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "lock-car", version: "1" } },
    READ_TIMEOUT_MS,
  );

  if (mode === "--check") {
    const listed = await callTool(url, token, "tesla_vehicles_list", {}, READ_TIMEOUT_MS);
    if (listed.isError) {
      fail(`${listed.data.summary ?? "listing the cars failed"} [${listed.data.error ?? "error"}]`, "CHECK");
      if (listed.data.error === "reauth_required") console.error(REAUTH_FIX);
      return;
    }
    console.log(`ok: ${listed.data.summary}`);
    return;
  }

  const dryRun = mode === "--dry-run";
  const lock = await callTool(
    url,
    token,
    "tesla_lock",
    { ...vehicle, confirm: true, ...(dryRun ? { dryRun: true } : {}) },
    LOCK_TIMEOUT_MS,
  );
  if (lock.isError) {
    const reason = lock.data.reason ? `, reason ${lock.data.reason}` : "";
    fail(`${lock.data.summary ?? "tesla_lock failed"} [${lock.data.error ?? "error"}${reason}]`);
    if (lock.data.error === "reauth_required") console.error(REAUTH_FIX);
    return;
  }
  console.log(`tesla_lock: ${lock.data.summary}`);
  if (dryRun) return;

  const status = await callTool(url, token, "tesla_vehicle_status", vehicle, READ_TIMEOUT_MS);
  if (status.isError) {
    fail(`could not confirm: ${status.data.summary ?? "tesla_vehicle_status failed"} [${status.data.error}]`);
    return;
  }
  const locked = status.data.status?.locked;
  if (locked === true) {
    console.log(`confirmed: ${status.data.summary}`);
    return;
  }
  fail(
    locked === false
      ? `the car reports UNLOCKED after the lock: ${status.data.summary}`
      : `could not confirm the lock state (car is ${status.data.state ?? "unknown"}): ${status.data.summary}`,
  );
}

main().catch((error) => {
  if (error instanceof SetupError) {
    console.error(`LOCK NOT ATTEMPTED OR NOT CONFIRMED: ${error.message}`);
    process.exitCode = 2;
    return;
  }
  console.error(`LOCK FAILED: unexpected ${error?.name ?? "error"}`);
  process.exitCode = 1;
});
