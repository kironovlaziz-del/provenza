// ASI08 circuit breaker API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export interface BreakerConfig {
  enabled: boolean;
  window_seconds: number;
  max_attempts: number;
  max_denials: number;
  max_incidents: number;
}

export type BreakerField = "window_seconds" | "max_attempts" | "max_denials" | "max_incidents";

export interface BreakerSettings {
  defaults: BreakerConfig;
  bounds: Record<BreakerField, [number, number]>;
  org: BreakerConfig & { source: "default" | "org" };
  overrides: (BreakerConfig & { agent_id: number; agent_name: string })[];
}

export interface BreakerDetails {
  exceeded: ("attempts" | "denials" | "incidents")[];
  counts: { attempts: number; denials: number; incidents: number };
  thresholds: { attempts: number; denials: number; incidents: number };
  window_seconds: number;
  settings_source: "default" | "org" | "agent";
  tripped_at: string;
}

export interface BreakerChain {
  id: number;
  root_agent_id: number;
  root_agent_name: string | null;
  root_task: string | null;
  status: string;
  breaker_tripped_at: string | null;
  breaker_reset_at: string | null;
  breaker_details: BreakerDetails | null;
}

export async function getBreakerSettings() {
  const { data } = await api.get<BreakerSettings>("/agent-breaker/settings");
  return data;
}

export async function updateOrgBreaker(cfg: BreakerConfig, confirmDisable = false) {
  const { data } = await api.put("/agent-breaker/settings", { ...cfg, confirm_disable: confirmDisable });
  return data;
}

export async function setAgentBreaker(agentId: number, cfg: BreakerConfig) {
  const { data } = await api.put(`/agent-breaker/settings/agents/${agentId}`, cfg);
  return data;
}

export async function deleteAgentBreaker(agentId: number) {
  const { data } = await api.delete(`/agent-breaker/settings/agents/${agentId}`);
  return data;
}

export async function listBreakerChains() {
  const { data } = await api.get<BreakerChain[]>("/agent-breaker/chains");
  return data;
}

export async function resumeChain(chainId: number) {
  const { data } = await api.post(`/agent-breaker/chains/${chainId}/resume`);
  return data;
}

export async function terminateChain(chainId: number) {
  const { data } = await api.post(`/agent-breaker/chains/${chainId}/terminate`);
  return data;
}

export function breakerError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
