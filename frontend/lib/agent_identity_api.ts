// Agent identity API (X-Agent-Key lifecycle). Reuses the shared axios instance from api.ts.
import { api } from "./api";

export interface IdentitySettings {
  require_agent_key: boolean;
  rotation_grace_minutes: number;
  /** Every agent must sign with Ed25519 + ML-DSA-65 (post-quantum hybrid). */
  require_pq_signatures: boolean;
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
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
