// /admin/clients: pre-registered (static) OAuth clients, one per agent,
// managed with the static MCP_BEARER_TOKEN. A client secret is returned once,
// at creation, and stored only as a hash. Deleting a client revokes its
// grants and tokens.

import type { ClientInfo, OAuthAuthorizationServer } from "@cloudflare/workers-oauth-provider";
import { staticBearerMatches } from "../auth";
import { readBoundedBody } from "../body";
import type { Env } from "../env";
import { allowedRedirectUris, CLAUDE_REDIRECT_URIS } from "./redirects";

export const ADMIN_CLIENTS_PATH = "/admin/clients";
const MAX_ADMIN_BODY_BYTES = 8192;
const CLIENT_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
/** Listing stops after this many pages of 1000. */
const MAX_LIST_PAGES = 10;

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(value, { status, headers });
}

function error(status: number, code: string, description: string, headers: HeadersInit = {}): Response {
  return json({ error: code, error_description: description }, status, headers);
}

/** What a listing may show: never the secret or its hash. */
function publicClient(client: ClientInfo) {
  return {
    client_id: client.clientId,
    client_name: client.clientName ?? null,
    redirect_uris: client.redirectUris,
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    registered_at: client.registrationDate ? new Date(client.registrationDate * 1000).toISOString() : null,
  };
}

async function createClient(request: Request, env: Env, server: OAuthAuthorizationServer<Env>): Promise<Response> {
  const body = await readBoundedBody(request, MAX_ADMIN_BODY_BYTES);
  let input: unknown;
  try {
    input = body ? JSON.parse(new TextDecoder().decode(body)) : null;
  } catch {
    input = null;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return error(400, "invalid_request", 'Send a JSON object: {"name": "...", "redirect_uris": [...]}.');
  }
  const { name, redirect_uris: requested } = input as Record<string, unknown>;
  if (typeof name !== "string" || !/^[^\x00-\x1f\x7f]{1,100}$/.test(name.trim())) {
    return error(400, "invalid_request", "name must be 1 to 100 printable characters.");
  }
  const redirectUris = requested === undefined ? [...CLAUDE_REDIRECT_URIS] : allowedRedirectUris(requested, env);
  if (!redirectUris) {
    return error(
      400,
      "invalid_redirect_uri",
      "redirect_uris must list 1 to 10 allowed URIs: Claude's connector callback, http://localhost or http://127.0.0.1, or one in OAUTH_EXTRA_REDIRECT_URIS.",
    );
  }
  // No explicit auth method: the secret works with client_secret_basic and
  // client_secret_post alike.
  const created = await server.getOAuthApi(env).createClient({ clientName: name.trim(), redirectUris });
  return json(
    {
      ...publicClient(created),
      client_secret: created.clientSecret,
      token_endpoint_auth_methods: ["client_secret_basic", "client_secret_post"],
      note: "Store client_secret now. It is not shown again.",
    },
    201,
  );
}

async function listClients(env: Env, server: OAuthAuthorizationServer<Env>): Promise<Response> {
  const oauth = server.getOAuthApi(env);
  const clients: ReturnType<typeof publicClient>[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_LIST_PAGES; page++) {
    const listed = await oauth.listClients({ limit: 1000, ...(cursor ? { cursor } : {}) });
    clients.push(...listed.items.map(publicClient));
    cursor = listed.cursor;
    if (!cursor) break;
  }
  clients.sort((left, right) => (left.registered_at ?? "").localeCompare(right.registered_at ?? ""));
  return json({ clients });
}

async function deleteClient(clientId: string, env: Env, server: OAuthAuthorizationServer<Env>): Promise<Response> {
  const oauth = server.getOAuthApi(env);
  if (!CLIENT_ID_PATTERN.test(clientId) || !(await oauth.lookupClient(clientId))) {
    return error(404, "not_found", "No such client.");
  }
  await oauth.deleteClient(clientId);
  return json({ revoked: clientId });
}

export function isAdminClientsPath(pathname: string): boolean {
  return pathname === ADMIN_CLIENTS_PATH || pathname.startsWith(`${ADMIN_CLIENTS_PATH}/`);
}

export async function handleAdminClients(
  request: Request,
  env: Env,
  server: OAuthAuthorizationServer<Env>,
): Promise<Response> {
  const match = /^Bearer ([\x21-\x7e]{1,4096})$/.exec(request.headers.get("Authorization") ?? "");
  if (!(await staticBearerMatches(match?.[1] ?? null, env))) {
    return error(401, "invalid_token", "The admin API needs the server's MCP_BEARER_TOKEN.", {
      "WWW-Authenticate": 'Bearer realm="tesla-mcp-admin"',
    });
  }
  const { pathname } = new URL(request.url);
  if (pathname === ADMIN_CLIENTS_PATH) {
    if (request.method === "GET") return listClients(env, server);
    if (request.method === "POST") return createClient(request, env, server);
    return error(405, "method_not_allowed", "Use GET or POST.", { Allow: "GET, POST" });
  }
  if (request.method === "DELETE") return deleteClient(pathname.slice(ADMIN_CLIENTS_PATH.length + 1), env, server);
  return error(405, "method_not_allowed", "Use DELETE.", { Allow: "DELETE" });
}
