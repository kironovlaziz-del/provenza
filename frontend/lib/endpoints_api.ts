// Discovery: devices that report telemetry and AI agents found on them.
import { api, type Page } from "./api";

export type FoundStatus = "new" | "registered" | "ignored";
export type AgentCategory = "coding_agent" | "agent_framework" | "agent_platform" | "custom_agent" | "unknown";

export interface DeviceT {
  id: number;
  host_id: string;
  source: { id: number; name: string; source_type: string };
  last_user: string | null;
  os: string | null;
  agent_version: string | null;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  agents_found: number;
  agents_new: number;
}

export interface FoundAgentT {
  id: number;
  product: string;
  name: string;
  vendor: string;
  category: AgentCategory;
  device_id: number;
  device_host: string;
  device_user: string | null;
  risk_score: number | null;
  evidence: {
    process_name?: string | null;
    matched_by?: string | null; // executable | package | module | path | behavior
    // matched_by "behavior" (an agent no catalog knows):
    confidence?: "high" | "medium" | null;
    api_hosts?: string[];
    env_keys?: string[]; // variable names only
    sdks?: string[];
  } | null;
  status: FoundStatus;
  registered_agent: { id: number; name: string } | null;
  decided_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
}

export interface DeviceDetailT extends DeviceT {
  agents: FoundAgentT[];
}

export interface FoundSummaryT {
  new: number;
  registered: number;
  ignored: number;
  devices: number;
}

export async function listDevices(q = "", skip = 0, limit = 200) {
  const { data } = await api.get<Page<DeviceT>>("/devices/", { params: { q: q || undefined, skip, limit } });
  return data;
}

export async function getDevice(id: number) {
  const { data } = await api.get<DeviceDetailT>(`/devices/${id}`);
  return data;
}

export async function listFoundAgents(status: FoundStatus | "" = "", skip = 0, limit = 200) {
  const { data } = await api.get<Page<FoundAgentT>>("/agents-found/", {
    params: { status: status || undefined, skip, limit },
  });
  return data;
}

export async function getFoundSummary() {
  const { data } = await api.get<FoundSummaryT>("/agents-found/summary");
  return data;
}

export async function ignoreFoundAgent(id: number) {
  const { data } = await api.post(`/agents-found/${id}/ignore`);
  return data;
}

export async function restoreFoundAgent(id: number) {
  const { data } = await api.post(`/agents-found/${id}/restore`);
  return data;
}

export async function linkFoundAgent(id: number, agentId: number) {
  const { data } = await api.post(`/agents-found/${id}/link`, { agent_id: agentId });
  return data;
}

/** Relative time like "5 min ago", for "last seen" columns. */
export function ago(iso: string, lang: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  if (s < 60) return rtf.format(-Math.round(s), "second");
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}
