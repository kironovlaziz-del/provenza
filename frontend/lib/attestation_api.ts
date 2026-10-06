// Workload attestation (backend services/attestation.py, /api/v1/attestation).
import { api } from "./api";

export interface AttestationPolicyT {
  id: number;
  name: string;
  description: string | null;
  kind: "k8s_sa";
  issuer: string;
  audience: string;
  jwks_keys: (string | null)[];
  jwks_url: string | null;
  namespaces: string[];
  service_accounts: string[];
  require_pod_bound: boolean;
  validity_minutes: number;
  roles: number;
  updated_at: string | null;
}

export interface PolicyInput {
  name?: string;
  description?: string | null;
  issuer?: string;
  audience?: string;
  jwks?: unknown | null;
  jwks_url?: string | null;
  namespaces?: string[];
  service_accounts?: string[];
  require_pod_bound?: boolean;
  validity_minutes?: number;
}

export interface WorkloadIdentity {
  iss?: string;
  sub?: string;
  namespace?: string;
  service_account?: string;
  pod?: string | null;
  pod_uid?: string | null;
  node?: string | null;
  exp?: number;
  /** only on a refused workload: "namespace/serviceaccount" */
  workload?: string;
}

export interface AttestationT {
  id: number;
  agent_id: number;
  agent_name?: string;
  policy_id: number | null;
  policy: string | null;
  kind: string;
  ok: boolean;
  reason: string | null;
  detail: string | null;
  identity: WorkloadIdentity | null;
  created_at: string;
  valid_until: string | null;
}

export interface AgentAttestationStatus {
  required: boolean;
  policy: AttestationPolicyT | null;
  refusal: string | null;
  current: AttestationT | null;
  last: AttestationT | null;
}

export interface AttestationHint {
  required: boolean;
  policy: string | null;
  kind: string | null;
  audience: string | null;
  validity_minutes: number | null;
}

export async function listPolicies() {
  return (await api.get<AttestationPolicyT[]>("/attestation/policies")).data;
}

export async function createPolicy(input: PolicyInput) {
  return (await api.post<AttestationPolicyT>("/attestation/policies", input)).data;
}

export async function updatePolicy(id: number, input: PolicyInput) {
  return (await api.patch<AttestationPolicyT>(`/attestation/policies/${id}`, input)).data;
}

export async function deletePolicy(id: number) {
  return (await api.delete(`/attestation/policies/${id}`)).data;
}

export async function testPolicy(id: number, token: string) {
  return (await api.post<{ ok: boolean; identity?: WorkloadIdentity; reason?: string; detail?: string; issuer_in_token?: string | null }>(
    `/attestation/policies/${id}/test`, { token })).data;
}

export async function listAttestations(agentId?: number, limit = 50) {
  return (await api.get<AttestationT[]>("/attestation/records", { params: { agent_id: agentId, limit } })).data;
}

export async function agentAttestation(agentId: number) {
  return (await api.get<AgentAttestationStatus>(`/attestation/agents/${agentId}`)).data;
}

/** The pod spec fragment that gives the agent its token. */
export function podSpecSnippet(audience: string, minutes = 60): string {
  return [
    "spec:",
    "  serviceAccountName: <your-agent-sa>",
    "  containers:",
    "  - name: agent",
    "    volumeMounts:",
    "    - name: provenza-token",
    "      mountPath: /var/run/secrets/provenza",
    "      readOnly: true",
    "  volumes:",
    "  - name: provenza-token",
    "    projected:",
    "      sources:",
    "      - serviceAccountToken:",
    `          audience: ${audience}`,
    `          expirationSeconds: ${Math.max(600, minutes * 60)}`,
    "          path: token",
  ].join("\n");
}

/** An attestation lasts until the policy's validity or the token's own expiry,
 *  whichever comes first; the kubelet renews a token when 80% of its life has
 *  passed, so with 1-hour tokens a current one always has 12+ minutes left. */
export function attestCommand(validityMinutes: number): string {
  const every = Math.max(1, Math.min(10, Math.floor(validityMinutes / 3)));
  return `python tools/provenza_sign.py attest --keys provenza-agent.json --every ${every}`;
}
