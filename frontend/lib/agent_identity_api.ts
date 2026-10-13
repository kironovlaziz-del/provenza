// Agent identity API (X-Agent-Key lifecycle). Reuses the shared axios instance from api.ts.
import { api } from "./api";
import { apiErrorText } from "./errors";

export interface IdentitySettings {
  require_agent_key: boolean;
  rotation_grace_minutes: number;
  /** Every agent must sign with Ed25519 + ML-DSA-65 (post-quantum hybrid). */
  require_pq_signatures: boolean;
  /** Direct registration and admin key replacement without proof of possession. Off by default. */
  allow_direct_registration?: boolean;
  /** Act only from a host whose latest egress check found it confined to the egress proxy. */
  require_confined_egress?: boolean;
  egress_check_max_age_hours?: number;
  source?: "default" | "org";
}

export interface AgentKeyRow {
  agent_id: number;
  name: string;
  status: string;
  owner: string | null;
  owner_active: boolean;
  has_public_key: boolean;
  key_last_used_at: string | null;
  key_rotated_at: string | null;
  key_revoked_at: string | null;
  previous_key_valid_until: string | null;
}

export interface IdentityOverview {
  settings: IdentitySettings;
  agents: AgentKeyRow[];
}

export async function getIdentityOverview() {
  const { data } = await api.get<IdentityOverview>("/agent-identity/");
  return data;
}

export async function saveIdentitySettings(s: IdentitySettings) {
  const { data } = await api.put("/agent-identity/settings", {
    require_agent_key: s.require_agent_key,
    rotation_grace_minutes: s.rotation_grace_minutes,
    require_pq_signatures: s.require_pq_signatures,
    allow_direct_registration: s.allow_direct_registration,
    require_confined_egress: s.require_confined_egress,
    egress_check_max_age_hours: s.egress_check_max_age_hours,
  });
  return data;
}

export async function rotateKey(agentId: number) {
  const { data } = await api.post<{ agent_id: number; api_key: string; previous_key_valid_until: string | null }>(
    `/agent-identity/agents/${agentId}/rotate`,
  );
  return data;
}

export async function revokeKey(agentId: number) {
  const { data } = await api.post(`/agent-identity/agents/${agentId}/revoke`);
  return data;
}

export function identityError(err: unknown, fallback: string): string {
  return apiErrorText(err, fallback);
}

export interface EgressCheckT {
  check_id: number;
  agent_id: number;
  verdict: "pending" | "confined" | "open";
  targets: string[];
  reported_at: string | null;
  beacon_hit_at: string | null;
  results: { target: string; reachable: boolean }[] | null;
}

/** Each agent's latest egress check (app/services/egress_check.py). */
export async function listEgressChecks() {
  const { data } = await api.get<{ checks: EgressCheckT[] }>("/agent-identity/egress");
  return data.checks;
}

export type LockdownKind = "kubernetes" | "docker" | "nftables";
export interface LockdownT {
  kind: LockdownKind;
  files: { name: string; content: string }[];
  agent_env: Record<string, string>;
  notes: string[];
  verify: string;
}

export async function renderLockdown(params: Record<string, unknown>) {
  const { data } = await api.post<LockdownT>("/egress-lockdown/render", params);
  return data;
}
