// ASI07 agent-to-agent messages API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type A2AMode = "off" | "monitor" | "enforce";
export type MsgStatus = "accepted" | "quarantined" | "rejected";

export interface A2ASettings {
  mode: A2AMode;
  allow_same_chain: boolean;
  max_age_seconds: number;
  message_ttl_seconds: number;
  source?: "default" | "org";
}

export interface A2AMessageT {
  id: number;
  created_at: string;
  from_agent_id: number | null;
  from_agent: string | null;
  to_agent_id: number | null;
  to_agent: string | null;
  chain_id: number | null;
  message_type: string | null;
  status: MsgStatus;
  signature_valid: boolean;
  reasons: string[];
  findings: { check: string; label: string; snippet: string }[];
  consumed_at: string | null;
  receive_attempts: number;
}

export interface A2AChannelT {
  id: number;
  from_agent_id: number;
  from_agent: string | null;
  to_agent_id: number;
  to_agent: string | null;
  bidirectional: boolean;
  enabled: boolean;
  created_at: string;
}

export interface A2AOverview {
  settings: A2ASettings;
  counts_24h: Record<string, number>;
  agents: { id: number; name: string }[];
  messages: A2AMessageT[];
  channels: A2AChannelT[];
}

export async function getA2AOverview(status?: MsgStatus | "") {
  const { data } = await api.get<A2AOverview>("/a2a/", { params: status ? { status } : {} });
  return data;
}

export async function saveA2ASettings(s: A2ASettings) {
  const { data } = await api.put("/a2a/settings", {
    mode: s.mode,
    allow_same_chain: s.allow_same_chain,
    max_age_seconds: s.max_age_seconds,
    message_ttl_seconds: s.message_ttl_seconds,
  });
  return data;
}

export async function addChannel(from_agent_id: number, to_agent_id: number, bidirectional: boolean) {
  const { data } = await api.post("/a2a/channels", { from_agent_id, to_agent_id, bidirectional });
  return data;
}

export async function disableChannel(id: number) {
  const { data } = await api.post(`/a2a/channels/${id}/disable`);
  return data;
}

export async function releaseMessage(id: number) {
  const { data } = await api.post(`/a2a/messages/${id}/release`);
  return data;
}

export function a2aError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
