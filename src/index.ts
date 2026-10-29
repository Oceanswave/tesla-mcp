import { OWNER_ID } from "./auth";
import type { Env } from "./env";
import { handleRequest } from "./routes";

// The Worker entry module exports only handlers and Durable Object classes;
// workerd refuses to start with any other named export.
export { OwnerState } from "./owner/state";
export { TeslaVcpSession } from "./tesla/vcp/session";

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  },
  async scheduled(_controller, env, ctx) {
    // Deprecated with the built-in nightly lock: the cron's only job is to keep
    // its alarm armed (idempotent). Removed together with the alarm.
    const owner = env.OWNER.get(env.OWNER.idFromName(OWNER_ID));
    ctx.waitUntil(owner.ensureAlarm());
  },
} satisfies ExportedHandler<Env>;
