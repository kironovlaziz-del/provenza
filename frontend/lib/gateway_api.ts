// LLM gateway admin API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export interface GatewaySettings {
  enabled: boolean;
  rpm_per_agent: number;
  max_tokens_cap: number;
  blocked_terms: string[];
  scan_output: boolean;
  source?: "default" | "org";
}

export interface GatewayProvider {
  id: number;
  name: string;
  type: string;
  status: string;
  default_model: string | null;
  has_key: boolean;
}

export interface GatewayRouteT {
  id: number;
  model: string;
  provider_id: number;
  provider: string | null;
  upstream_model: string | null;
  enabled: boolean;
  created_at: string;
}

export interface GatewayCallT {
  id: number;
  created_at: string;
  agent_id: number | null;
  agent_name: string | null;
  model: string | null;
  provider: string | null;
  status: "completed" | "filtered" | "blocked" | "failed" | "rate_limited" | "denied";
  reason: string | null;
  flags: string[];
  latency_ms: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  ai_request_id: number | null;
}

export interface GatewayOverview {
  settings: GatewaySettings;
  counts_24h: Record<string, number>;
  tokens_24h: { prompt: number; completion: number };
  providers: GatewayProvider[];
  routes: GatewayRouteT[];
  calls: GatewayCallT[];
}

export async function getGatewayOverview() {
  const { data } = await api.get<GatewayOverview>("/gateway/");
  return data;
}

export async function saveGatewaySettings(s: GatewaySettings) {
  const { data } = await api.put("/gateway/settings", {
    enabled: s.enabled,
    rpm_per_agent: s.rpm_per_agent,
    max_tokens_cap: s.max_tokens_cap,
    blocked_terms: s.blocked_terms,
    scan_output: s.scan_output,
  });
  return data;
}

export async function addRoute(model: string, provider_id: number, upstream_model: string | null) {
  const { data } = await api.post("/gateway/routes", { model, provider_id, upstream_model: upstream_model || null });
  return data;
}

export async function disableRoute(id: number) {
  const { data } = await api.post(`/gateway/routes/${id}/disable`);
  return data;
}

export function gatewayError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
