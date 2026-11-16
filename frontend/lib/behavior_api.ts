// ASI10 behaviour monitor and automatic containment API. Reuses the shared axios instance from api.ts.
import { api } from "./api";
import { apiErrorText } from "./errors";
import { signWithSessionKey } from "./signing";

export type BehaviorMode = "off" | "monitor" | "enforce";

export interface BehaviorSettings {
  mode: BehaviorMode;
  threshold: number;
  min_samples: number;
  baseline_days: number;
  // automatic containment (backend/app/services/containment.py)
  containment_enabled: boolean;
  containment_max_boundary: number;
  containment_window_seconds: number;
  tripwire_tools: string[];
  source?: "default" | "org";
}

export interface QuarantineWhy {
  incident_id: number;
  at: string | null;
  reason: "boundary_refusals" | "tripwire" | "behavior";
  tool: string | null;
  count: number | null;
  refusals: { check_id: number; tool: string | null; reason: string | null; at: string | null }[];
  score: number | null;
  signals: string[];
}

export interface BehaviorAgentRow {
  agent_id: number;
  name: string;
  status: string;
  quarantine: QuarantineWhy | null;
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
  bounds: Record<"threshold" | "min_samples" | "baseline_days" | "containment_max_boundary" |
    "containment_window_seconds", [number, number]>;
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
    containment_enabled: s.containment_enabled,
    containment_max_boundary: s.containment_max_boundary,
    containment_window_seconds: s.containment_window_seconds,
    tripwire_tools: s.tripwire_tools,
  });
  return data;
}

// The release is signed with the person's session key, like a task or an approval.
export async function releaseAgent(agentId: number) {
  const base = `/agent-behavior/agents/${agentId}/release`;
  const { data } = await api.post<{ statement: Record<string, unknown> }>(`${base}/statement`);
  let signature: string;
  try {
    signature = await signWithSessionKey(String(data.statement.session_id), data.statement);
  } catch {
    throw { response: { data: { detail: "session.no_key" } } };
  }
  const res = await api.post(base, { statement: data.statement, signature });
  return res.data;
}

export async function refreshBaseline(agentId: number) {
  const { data } = await api.post(`/agent-behavior/agents/${agentId}/baseline`);
  return data;
}

export function behaviorError(err: unknown, fallback: string): string {
  return apiErrorText(err, fallback);
}
