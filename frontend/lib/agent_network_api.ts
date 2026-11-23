// An agent's own network, seen by the egress sensor (backend:
// app/api/agent_network.py; docs/egress-lockdown.md, "The agent's network").
import { api } from "./api";

export interface AgentNetworkWorkloadT {
  id: number;
  name: string;
  mode: "observe" | "alert" | "enforce";
  dns: "off" | "listed" | "any";
  enabled: boolean;
  isolated: boolean;
  egress_allow: { dest?: string; ports?: number[]; protocols?: string[] }[];
}

/** a host whose sensor runs the agent now */
export interface AgentNetworkRunningT {
  sensor_id: number;
  sensor: string;
  hostname: string | null;
  cgroups: number;
  processes: number;
  last_seen_at: string | null;
}

/** where the agent went: a name the sensor learned from its DNS, or an address */
export interface AgentDestinationT {
  dest: string;
  port: number | null;
  protocol: string | null;
  count: number;
  last_at: string;
  address: string | null;
  named: boolean;
  blocked: boolean;
}

export interface AgentNetworkT {
  agent_id: number;
  workload: AgentNetworkWorkloadT | null;
  running: AgentNetworkRunningT[];
  destinations: AgentDestinationT[];
}

export const getAgentNetwork = async (agentId: number) =>
  (await api.get<AgentNetworkT>(`/agents/${agentId}/network`)).data;

/** observe the network of an agent made before it was done by default */
export const observeAgentNetwork = async (agentId: number) =>
  (await api.post<AgentNetworkT>(`/agents/${agentId}/network`)).data;

/** allow these destinations and refuse the rest (the workload goes to enforce) */
export const enforceAgentNetwork = async (
  agentId: number, destinations: { dest: string; port: number | null; protocol: string | null }[],
) => (await api.post<AgentNetworkT>(`/agents/${agentId}/network/enforce`, { destinations })).data;
