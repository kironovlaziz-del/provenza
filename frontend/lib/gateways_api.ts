// Gateways besides the LLM one (lib/gateway_api.ts): MCP servers, A2A peers
// and the egress proxy. Backend: app/api/mcp.py, a2a_gateway.py, egress_proxy.py.
import { api } from "./api";
import { passkeyAssertion, type Challenge } from "./signing";

// ---------------------------------------------------------------- MCP

export const MCP_PROTOCOLS = ["auto", "2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"] as const;
export type McpProtocol = (typeof MCP_PROTOCOLS)[number];

export interface McpServer {
  id: number;
  slug: string;
  name: string;
  url: string;
  protocol: McpProtocol;
  detected_version: string | null;
  auth_header: string;
  has_secret: boolean;
  credential_source: "none" | "sealed" | "local";
  enabled: boolean;
  timeout_seconds: number;
  server_info: Record<string, unknown> | null;
  last_synced_at: string | null;
  last_error: string | null;
  created_at: string;
}

export interface McpServerInput {
  slug?: string;
  name?: string;
  url?: string;
  protocol?: McpProtocol;
  auth_header?: string;
  clear_secret?: boolean;
  timeout_seconds?: number;
  enabled?: boolean;
}

export interface McpTool {
  id: number;
  name: string;
  exposed_name: string;
  title: string | null;
  description: string | null;
  digest: string;
  registry_entry_id: number | null;
  status: string;
  pinned_digest: string | null;
  served: boolean;
  removed_at: string | null;
}

export interface McpSyncReport {
  added: string[];
  changed: string[];
  unchanged: string[];
  removed: string[];
  skipped: { name: string; reason: string }[];
}

export const listMcpServers = async () => (await api.get<McpServer[]>("/mcp-servers")).data;
export const createMcpServer = async (input: McpServerInput) => (await api.post<McpServer>("/mcp-servers", input)).data;
export const updateMcpServer = async (id: number, input: McpServerInput) =>
  (await api.patch<McpServer>(`/mcp-servers/${id}`, input)).data;
export const deleteMcpServer = async (id: number) => {
  await api.delete(`/mcp-servers/${id}`);
};
export const syncMcpServer = async (id: number) => (await api.post<McpSyncReport>(`/mcp-servers/${id}/sync`)).data;
export const listMcpTools = async (id: number) => (await api.get<McpTool[]>(`/mcp-servers/${id}/tools`)).data;
export const approveMcpTool = async (serverId: number, toolId: number) =>
  (await api.post(`/mcp-servers/${serverId}/tools/${toolId}/approve`)).data;
export const blockMcpTool = async (serverId: number, toolId: number) =>
  (await api.post(`/mcp-servers/${serverId}/tools/${toolId}/block`)).data;

// ---------------------------------------------------------------- A2A

export interface A2aPeer {
  id: number;
  slug: string;
  tool_name: string;
  name: string;
  card_url: string;
  auth_header: string;
  has_secret: boolean;
  credential_source: "none" | "sealed" | "local";
  enabled: boolean;
  timeout_seconds: number;
  card: Record<string, unknown> | null;
  card_digest: string | null;
  endpoint_url: string | null;
  protocol_version: string | null;
  status: string;
  pinned_digest: string | null;
  served: boolean;
  last_synced_at: string | null;
  last_error: string | null;
  created_at: string;
}

export interface A2aPeerInput {
  slug?: string;
  name?: string;
  card_url?: string;
  auth_header?: string;
  clear_secret?: boolean;
  timeout_seconds?: number;
  enabled?: boolean;
}

export const listA2aPeers = async () => (await api.get<A2aPeer[]>("/a2a-peers")).data;
export const createA2aPeer = async (input: A2aPeerInput) => (await api.post<A2aPeer>("/a2a-peers", input)).data;
export const updateA2aPeer = async (id: number, input: A2aPeerInput) =>
  (await api.patch<A2aPeer>(`/a2a-peers/${id}`, input)).data;
export const deleteA2aPeer = async (id: number) => {
  await api.delete(`/a2a-peers/${id}`);
};
export const syncA2aPeer = async (id: number) =>
  (await api.post<{ version: string; endpoint: string; card_digest: string; changed: boolean; status: string; skills: number }>(
    `/a2a-peers/${id}/sync`)).data;
export const approveA2aPeer = async (id: number) => (await api.post(`/a2a-peers/${id}/approve`)).data;
export const blockA2aPeer = async (id: number) => (await api.post(`/a2a-peers/${id}/block`)).data;

// ---------------------------------------------------------------- egress proxy

export const EGRESS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;
/** sealed: in the browser to the proxies' keys (lib/sealing.ts); local: in their configuration */
export type CredentialSource = "sealed" | "local" | "none";

export interface EgressRoute {
  id: number;
  slug: string;
  tool_name: string;
  name: string;
  upstream_url: string;
  methods: string[];
  path_prefixes: string[];
  credential_source: CredentialSource;
  auth_header: string;
  has_secret: boolean;
  max_body_bytes: number;
  enabled: boolean;
  created_at: string;
}

export interface EgressRouteInput {
  slug?: string;
  name?: string;
  upstream_url?: string;
  methods?: string[];
  path_prefixes?: string[];
  credential_source?: CredentialSource;
  auth_header?: string;
  clear_secret?: boolean;
  max_body_bytes?: number;
  enabled?: boolean;
}

export interface EgressProxy {
  id: number;
  name: string;
  key_prefix: string;
  /** the proxy's own signing key (registered by the proxy), for checking its receipts offline */
  key_fingerprint?: string | null;
  /** its key credentials are sealed to (signed by the signing key) */
  encryption_key_fingerprint?: string | null;
  enabled: boolean;
  last_seen_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface EgressRedemption {
  id: number;
  proxy_id: number;
  route_id: number | null;
  agent_id: number;
  descriptor: Record<string, unknown>;
  reserved_at: string;
  completed_at: string | null;
  action_id: number | null;
}

export const listEgressRoutes = async () => (await api.get<EgressRoute[]>("/egress/routes")).data;
export const createEgressRoute = async (input: EgressRouteInput) => (await api.post<EgressRoute>("/egress/routes", input)).data;
export const updateEgressRoute = async (id: number, input: EgressRouteInput) =>
  (await api.patch<EgressRoute>(`/egress/routes/${id}`, input)).data;
export const deleteEgressRoute = async (id: number) => {
  await api.delete(`/egress/routes/${id}`);
};
export const listEgressProxies = async () => (await api.get<EgressProxy[]>("/egress/proxies")).data;
export const createEgressProxy = async (name: string) =>
  (await api.post<EgressProxy & { key: string }>("/egress/proxies", { name })).data;
export const revokeEgressProxy = async (id: number) => (await api.post<EgressProxy>(`/egress/proxies/${id}/revoke`)).data;
// ---------------------------------------------------------------- the proxy's local kill switch

/** One item the server states differently from the release the proxy held
 *  before the outage (docs/pvp/edge.md, section 7). */
export interface KillSwitchDifference {
  id: string;
  area: "manifest" | "bundle" | "credentials";
  section: string;
  key: string;
  label: string;
  before: string | null;
  now: string | null;
  /** the newest release the proxy verified states it so */
  signed: boolean;
}

export interface KillSwitch {
  engaged_at: string;
  reason: string | null;
  release_before: number;
  report_sha256: string;
  differences: KillSwitchDifference[];
  unsigned: string[];
  quorum: number;
  signers: { user_id: number; email: string }[];
  can_sign: boolean;
}

export const getKillSwitch = async (id: number) =>
  (await api.get<{ kill_switch: KillSwitch | null }>(`/egress/proxies/${id}/kill-switch`)).data.kill_switch;

/** This administrator's passkey over the report and the differences accepted. */
export async function signKillSwitchLift(id: number, accept: string[]): Promise<KillSwitch | null> {
  const { data: ch } = await api.post<Challenge>(`/egress/proxies/${id}/kill-switch/challenge`, { accept });
  const assertion = await passkeyAssertion(ch);
  const { data } = await api.post<{ kill_switch: KillSwitch | null }>(`/egress/proxies/${id}/kill-switch/sign`,
    { statement: ch.statement, assertion });
  return data.kill_switch;
}

export const listEgressRedemptions = async (open: boolean) =>
  (await api.get<EgressRedemption[]>("/egress/redemptions", { params: { open } })).data;

// ---------------------------------------------------------------- PVP evidence

export const getReceipt = async (actionId: number) =>
  (await api.get<Record<string, unknown>>(`/pvp/receipts/${actionId}`)).data;
export const getActionTrace = async (actionId: number) =>
  (await api.get<Record<string, unknown>>(`/pvp/receipts/${actionId}/trace`)).data;
export const getChainTrace = async (chainId: number) =>
  (await api.get<Record<string, unknown>>(`/pvp/chains/${chainId}/trace`)).data;

/** Save a JSON document as a file (receipts and TRACE exports are for auditors). */
export function downloadJson(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}


/** Absolute URL of a backend path - what agents are told to connect to. */
export function apiUrl(path: string): string {
  let base = String(api.defaults.baseURL ?? "/api/v1");
  while (base.endsWith("/")) base = base.slice(0, -1); // linear, no regex backtracking
  const origin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  return new URL(base + path, origin).toString();
}

// ---------------------------------------------------------------- HTTP tools

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface HttpTool {
  id: number;
  name: string;
  description: string | null;
  method: HttpMethod;
  url: string;
  input_schema: Record<string, unknown> | null;
  auth_header: string;
  has_secret: boolean;
  credential_source: "none" | "sealed" | "local";
  timeout_seconds: number;
  max_response_bytes: number;
  send_permit: boolean;
  enabled: boolean;
  digest: string;
  registry_entry_id: number | null;
  created_at: string;
  updated_at: string | null;
}

export interface HttpToolInput {
  name?: string;
  description?: string;
  method?: HttpMethod;
  url?: string;
  input_schema?: Record<string, unknown> | null;
  auth_header?: string;
  clear_secret?: boolean;
  timeout_seconds?: number;
  send_permit?: boolean;
  enabled?: boolean;
}

export const listHttpTools = async () => (await api.get<HttpTool[]>("/http-tools")).data;
export const createHttpTool = async (input: HttpToolInput) => (await api.post<HttpTool>("/http-tools", input)).data;
export const updateHttpTool = async (id: number, input: HttpToolInput) =>
  (await api.patch<HttpTool>(`/http-tools/${id}`, input)).data;
