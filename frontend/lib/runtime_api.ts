// Runtime: governed workloads and their egress violations
// (backend api/runtime.py, /api/v1/runtime).
import { api } from "./api";

export type RuntimeMode = "observe" | "alert" | "enforce";
export const RUNTIME_MODES: RuntimeMode[] = ["observe", "alert", "enforce"];
export type ViolationAction = "observed" | "alerted" | "blocked";
export const VIOLATION_ACTIONS: ViolationAction[] = ["observed", "alerted", "blocked"];

export interface AllowT {
  cidr: string;
  ports: number[]; // [] = any port
}

export interface WorkloadT {
  id: number;
  name: string;
  agent_id: number | null;
  cgroup_patterns: string[];
  egress_allow: AllowT[];
  allow_dns: boolean;
  mode: RuntimeMode;
  enabled: boolean;
  created_at: string;
}

export interface WorkloadInput {
  name: string;
  agent_id: number | null;
  cgroup_patterns: string[];
  egress_allow: AllowT[];
  allow_dns: boolean;
  mode: RuntimeMode;
  enabled: boolean;
}

export interface ViolationT {
  id: number;
  workload_id: number | null;
  agent_id: number | null;
  host: string;
  action: ViolationAction;
  protocol: string;
  dst_ip: string;
  dst_port: number;
  comm: string | null;
  cgroup: string | null;
  count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export async function listWorkloads() {
  const { data } = await api.get<WorkloadT[]>("/runtime/workloads");
  return data;
}

export async function createWorkload(input: WorkloadInput) {
  const { data } = await api.post<WorkloadT>("/runtime/workloads", input);
  return data;
}

export async function updateWorkload(id: number, input: Partial<WorkloadInput> & { unlink_agent?: boolean }) {
  const { data } = await api.patch<WorkloadT>(`/runtime/workloads/${id}`, input);
  return data;
}

export async function deleteWorkload(id: number) {
  await api.delete(`/runtime/workloads/${id}`);
}

export async function listViolations(filter: { workload_id?: number; action?: ViolationAction } = {}) {
  const { data } = await api.get<ViolationT[]>("/runtime/violations", { params: filter });
  return data;
}
