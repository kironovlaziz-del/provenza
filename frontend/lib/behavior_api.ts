// ASI10 behaviour monitor API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type BehaviorMode = "off" | "monitor" | "enforce";

export interface BehaviorSettings {
  mode: BehaviorMode;
  threshold: number;
  min_samples: number;
  baseline_days: number;
  source?: "default" | "org";
}

export interface BehaviorAgentRow {
  agent_id: number;
  name: string;
  status: string;
  baseline: {
    mature: boolean;
    samples: number;
    span_days: number;
    p95_per_5min: number;
    denial_rate: number;
    top_tools: string[];
    computed_at: string | null;
  } | null;
}

export interface BehaviorAnomaly {
  id: number;
  agent_id: number;
  agent_name: string;
  detected_at: string;
  tool_name: string | null;
  score: number;
  signals: Record<string, Record<string, unknown>>;
  outcome: "flagged" | "quarantined";
}

export interface BehaviorOverview {
  settings: BehaviorSettings;
  agents: BehaviorAgentRow[];
  anomalies: BehaviorAnomaly[];
  bounds: Record<"threshold" | "min_samples" | "baseline_days", [number, number]>;
  weights: Record<string, number>;
}

export async function getBehaviorOverview() {
  const { data } = await api.get<BehaviorOverview>("/agent-behavior/");
  return data;
}

export async function saveBehaviorSettings(s: BehaviorSettings) {
  const { data } = await api.put("/agent-behavior/settings", {
    mode: s.mode,
    threshold: s.threshold,
    min_samples: s.min_samples,
    baseline_days: s.baseline_days,
  });
  return data;
}

export async function releaseAgent(agentId: number) {
  const { data } = await api.post(`/agent-behavior/agents/${agentId}/release`);
  return data;
}

export async function refreshBaseline(agentId: number) {
  const { data } = await api.post(`/agent-behavior/agents/${agentId}/baseline`);
  return data;
}

export function behaviorError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
