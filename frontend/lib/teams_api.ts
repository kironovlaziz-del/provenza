// Teams and role templates (backend services/teams.py, /api/v1/teams).
import { api } from "./api";

export interface TeamT {
  id: number;
  name: string;
  description: string | null;
  parent_id: number | null;
  agents: number;
  roles: number;
}

export interface RoleT {
  id: number;
  team_id: number | null; // null = org-wide
  name: string;
  description: string | null;
  capabilities: string[];
  allowed_tools: string[];
  allowed_models: string[];
  max_delegation_depth: number;
  require_hybrid: boolean;
  require_attestation: boolean;
  attestation_policy_id: number | null;
  agents: number;
  /** only in an update's response */
  agents_updated?: number;
}

export type RoleInput = Omit<RoleT, "id" | "agents" | "agents_updated" | "description"> & { description?: string | null };

export async function listTeams() {
  return (await api.get<TeamT[]>("/teams/")).data;
}

export async function createTeam(input: { name: string; description?: string; parent_id?: number | null }) {
  return (await api.post<TeamT>("/teams/", input)).data;
}

export async function updateTeam(id: number, input: { name?: string; description?: string; parent_id?: number | null }) {
  return (await api.patch<TeamT>(`/teams/${id}`, input)).data;
}

export async function deleteTeam(id: number) {
  return (await api.delete(`/teams/${id}`)).data;
}

/** All roles, or (with teamId) the roles an agent of that team can have: its team's and org-wide ones. */
export async function listRoles(teamId?: number | null) {
  return (await api.get<RoleT[]>("/teams/roles", { params: teamId ? { team_id: teamId } : {} })).data;
}

export async function createRole(input: RoleInput) {
  return (await api.post<RoleT>("/teams/roles", input)).data;
}

export async function updateRole(id: number, input: Partial<RoleInput>) {
  return (await api.patch<RoleT>(`/teams/roles/${id}`, input)).data;
}

export async function deleteRole(id: number) {
  return (await api.delete(`/teams/roles/${id}`)).data;
}

export async function assignAgent(agentId: number, teamId: number | null, roleId: number | null) {
  return (await api.put(`/agents/${agentId}/assignment`, { team_id: teamId, role_id: roleId })).data;
}

/** "a, b\nc" -> ["a", "b", "c"] */
export function splitList(text: string): string[] {
  return Array.from(new Set(text.split(/[,\n]/).map((x) => x.trim()).filter(Boolean)));
}

/** Team names with their parents: "Engineering / ML". */
export function teamPath(teams: TeamT[], id: number | null | undefined): string {
  const byId = new Map(teams.map((t) => [t.id, t]));
  const parts: string[] = [];
  const seen = new Set<number>();
  let cur = id != null ? byId.get(id) : undefined;
  while (cur && !seen.has(cur.id)) {
    seen.add(cur.id);
    parts.unshift(cur.name);
    cur = cur.parent_id != null ? byId.get(cur.parent_id) : undefined;
  }
  return parts.join(" / ");
}
