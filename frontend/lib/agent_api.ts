// Agent-to-Agent Governance API calls. Reuses the shared axios instance
// and Page<T>/unwrap conventions from api.ts.
import { api, Page } from "./api";
import type {
  Agent,
  AgentCreated,
  DelegationChainT,
  DelegationChainDetail,
  AgentActionT,
  AgentPolicyT,
  AgentIncidentT,
  EscalationSummaryRow,
  KeyRevocationT,
  SigningKeyT,
} from "./agent_types";

function items<T>(p: Page<T>): T[] {
  return p.items;
}

// ---- Agents ----
export async function listAgents(limit?: number) {
  const { data } = await api.get<Page<Agent>>("/agents/", limit ? { params: { limit } } : undefined);
  return items(data);
}

export async function getAgent(id: number) {
  const { data } = await api.get<Agent>(`/agents/${id}`);
  return data;
}

export async function registerAgent(payload: {
  name: string;
  description?: string;
  agent_type?: string;
  owner_team?: string;
  capabilities?: string[];
  allowed_tools?: string[];
  allowed_models?: string[];
  max_delegation_depth?: number;
  /** The agent's own Ed25519 public key; omit to have the server generate a pair. */
  public_key?: string;
  /** With public_key: the agent's own ML-DSA-65 public key (hybrid scheme). */
  pq_public_key?: string;
  /** Server-generated keys only: "hybrid" also generates an ML-DSA-65 pair. */
  key_scheme?: "ed25519" | "hybrid";
}) {
  const { data } = await api.post<AgentCreated>("/agents/register", payload);
  return data;
}

export async function updateAgent(
  id: number,
  payload: Partial<{
    name: string;
    description: string;
    owner_team: string;
    capabilities: string[];
    allowed_tools: string[];
    allowed_models: string[];
    max_delegation_depth: number;
    status: string;
  }>
) {
  const { data } = await api.put<Agent>(`/agents/${id}`, payload);
  return data;
}

export async function killAgent(id: number, reason: string, cascade = true) {
  const { data } = await api.post<{ agents_stopped: number[]; chains_terminated: number }>(
    `/agents/${id}/kill`,
    { reason, cascade }
  );
  return data;
}

// ---- Delegation chains ----
export async function listChains() {
  const { data } = await api.get<Page<DelegationChainT>>("/agents/delegation-chains/");
  return items(data);
}

export async function getChain(id: number) {
  const { data } = await api.get<DelegationChainDetail>(`/agents/delegation-chains/${id}`);
  return data;
}

// ---- Actions ----
export async function listAgentActions(params?: { chain_id?: number; agent_id?: number; result?: string }) {
  const { data } = await api.get<Page<AgentActionT>>("/agents/actions/", { params });
  return items(data);
}

export async function approveAgentAction(actionId: number) {
  const { data } = await api.post<AgentActionT>(`/agents/actions/${actionId}/approve`);
  return data;
}

export async function denyAgentAction(actionId: number, reason?: string) {
  const { data } = await api.post<AgentActionT>(`/agents/actions/${actionId}/deny`, { reason });
  return data;
}

// ---- Policies ----
export async function listAgentPolicies() {
  const { data } = await api.get<Page<AgentPolicyT>>("/agents/policies/");
  return items(data);
}

export async function createAgentPolicy(payload: {
  name: string;
  agent_id?: number | null;
  rules: Record<string, unknown>;
  priority?: number;
  enabled?: boolean;
}) {
  const { data } = await api.post<AgentPolicyT>("/agents/policies/", payload);
  return data;
}

// ---- Incidents ----
export async function listAgentIncidents(params?: {
  incident_type?: string;
  unresolved_only?: boolean;
  skip?: number;
  limit?: number;
}) {
  const { data } = await api.get<Page<AgentIncidentT>>("/agents/incidents/", { params });
  return data;
}

export async function getEscalationSummary() {
  const { data } = await api.get<{ agents: EscalationSummaryRow[] }>(
    "/agents/incidents/escalation-summary",
  );
  return data;
}

// ---- Governance graph ----
import type { GovernanceGraphT } from "./agent_types";

export async function getGovernanceGraph() {
  const { data } = await api.get<GovernanceGraphT>("/agents/graph");
  return data;
}

// Signature evidence for a signed record (backend api/agents.py::_evidence).
// Verified in the browser by lib/ed25519_verify.ts, offline by tools/provenza_sign.py.
export interface HopVerification {
  format: string;
  record: "delegation_hop" | "agent_action";
  record_id: number;
  hop_id: number | null;
  agent_id: number;
  agent_name: string;
  has_signature: boolean;
  algorithm: "ed25519" | "ed25519+ml-dsa-65" | null;
  signed_payload: Record<string, unknown> | null;
  signed_message: string | null;
  signature: string | null;
  public_key: string | null;
  /** Hybrid signers only: ML-DSA-65 signature and public key over the same bytes. */
  pq_signature: string | null;
  pq_public_key: string | null;
  key_fingerprint: string | null;
  key_origin: "agent" | "server" | null;
  server_verified: boolean;
  /** when the server received the record - what revocation is judged against */
  signed_at?: string | null;
  /** the signing key's entry in the revocation list, if any */
  revocation?: KeyRevocationT | null;
  /** verified AND received before the key stopped being trusted */
  trusted?: boolean;
}

export async function getHopVerification(hopId: number) {
  const { data } = await api.get<HopVerification>(`/agents/delegation-hops/${hopId}/verification`);
  return data;
}

export async function setSigningKey(agentId: number, publicKey: string, pqPublicKey?: string) {
  const { data } = await api.post<Agent>(`/agents/${agentId}/signing-key`, {
    public_key: publicKey,
    pq_public_key: pqPublicKey || null,
  });
  return data;
}

export async function listKeyRevocations(agentId?: number) {
  const { data } = await api.get<KeyRevocationT[]>("/agents/key-revocations", {
    params: agentId != null ? { agent_id: agentId } : undefined,
  });
  return data;
}

export async function revokeSigningKey(agentId: number, keyId: number, reason: string, compromisedSince?: string) {
  const { data } = await api.post<KeyRevocationT>(`/agents/${agentId}/signing-keys/${keyId}/revoke`, {
    reason,
    compromised_since: compromisedSince || null,
  });
  return data;
}

export async function listSigningKeys(agentId: number) {
  const { data } = await api.get<SigningKeyT[]>(`/agents/${agentId}/signing-keys`);
  return data;
}
