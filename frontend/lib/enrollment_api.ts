// Agent enrollment: one-time tokens an admin issues; the agent proves it holds
// its key (tools/provenza_sign.py enroll). See backend services/enrollment.py.
import { api } from "./api";

export interface EnrollmentT {
  id: number;
  purpose: "new" | "rekey";
  token_prefix: string;
  state: "open" | "used" | "revoked" | "expired";
  created_by: number;
  created_at: string | null;
  expires_at: string;
  used_at: string | null;
  agent_id: number | null;
  name: string | null;
  owner_team: string | null;
  team_id: number | null;
  role_id: number | null;
  agent_type: string | null;
  capabilities: string[];
  allowed_tools: string[];
  allowed_models: string[];
  max_delegation_depth: number;
  require_hybrid: boolean;
  discovered_agent_id: number | null;
  /** only in the response that issued it */
  token?: string;
  /** only in the response that issued it: the agent will have to attest */
  attestation?: import("./attestation_api").AttestationHint | null;
}

export interface EnrollmentInput {
  purpose?: "new" | "rekey";
  agent_id?: number;
  name?: string;
  description?: string;
  agent_type?: string;
  owner_team?: string;
  team_id?: number;
  /** rights come from this role template; the rights fields are ignored */
  role_id?: number;
  capabilities?: string[];
  allowed_tools?: string[];
  allowed_models?: string[];
  max_delegation_depth?: number;
  require_hybrid?: boolean;
  ttl_hours?: number;
  discovered_agent_id?: number;
}

export async function issueEnrollment(input: EnrollmentInput) {
  return (await api.post<EnrollmentT>("/agent-enrollment/tokens", input)).data;
}

export async function listEnrollments() {
  return (await api.get<EnrollmentT[]>("/agent-enrollment/tokens")).data;
}

export async function revokeEnrollment(id: number) {
  return (await api.post<EnrollmentT>(`/agent-enrollment/tokens/${id}/revoke`)).data;
}

/** The command the agent's operator runs where the agent lives. */
export function enrollCommand(token: string, hybrid: boolean, rekey = false): string {
  // the tool appends /api/v1 itself: the server is the API URL without it
  const api = process.env.NEXT_PUBLIC_API_URL || "";
  const origin = typeof window !== "undefined" ? window.location.origin : "https://provenza.example.com";
  const base = api.startsWith("http") ? api : origin + api;
  const server = base.replace(/\/api\/v1\/?$/, "").replace(/\/$/, "") || origin;
  return `python tools/provenza_sign.py enroll --server ${server} --token ${token}${hybrid ? " --hybrid" : ""}` +
    (rekey ? " --keys-in provenza-agent.json --out provenza-agent.json" : "");
}
