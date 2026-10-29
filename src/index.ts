import type { Env } from "./env";
import { handleRequest } from "./routes";

// The Worker entry module exports only handlers and Durable Object classes;
// workerd refuses to start with any other named export.
export { OwnerState } from "./owner/state";
export { TeslaVcpSession } from "./tesla/vcp/session";

export default {
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
