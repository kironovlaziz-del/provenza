// Kill switch (backend services/kill_switch.py, /api/v1/kill-switch).
import { api } from "./api";

export type KillScope = "agent" | "team" | "all_agents" | "org_traffic";
export const KILL_SCOPES: KillScope[] = ["agent", "team", "all_agents", "org_traffic"];
export const ORG_WIDE: KillScope[] = ["all_agents", "org_traffic"];

export interface StoppedAgent {
  id: number;
  name: string | null;
  status?: string;
  event_id?: number;
  why?: string;
}

export interface KillEventT {
  id: number;
  scope: KillScope;
  agent_id: number | null;
  team_id: number | null;
  target_name: string | null;
  reason: string;
  active: boolean;
  agents: StoppedAgent[];
  chains: number[];
  team_ids: number[];
  created_at: string;
  created_by: number | null;
  created_by_email: string | null;
  lifted_at: string | null;
  lifted_by: number | null;
  lifted_by_email: string | null;
  lift_reason: string | null;
  lift_result: {
    restored: StoppedAgent[];
    kept: StoppedAgent[];
    skipped: StoppedAgent[];
    chains_not_resumed: number;
  } | null;
}

export interface KillOverviewT {
  traffic_stopped: boolean;
  all_agents_stopped: boolean;
  active: KillEventT[];
  agents: Record<string, number>;
}

export async function killOverview() {
  const { data } = await api.get<KillOverviewT>("/kill-switch");
  return data;
}

export async function killEvents(limit = 100) {
  const { data } = await api.get<KillEventT[]>("/kill-switch/events", { params: { limit } });
  return data;
}

export async function stopScope(input: {
  scope: KillScope;
  target_id?: number | null;
  reason: string;
  confirm?: string;
  terminate_chains?: boolean;
}) {
  const { data } = await api.post<KillEventT>("/kill-switch/events", input);
  return data;
}

export async function liftStop(id: number, reason?: string) {
  const { data } = await api.post<KillEventT>(`/kill-switch/events/${id}/lift`, { reason: reason || null });
  return data;
}
