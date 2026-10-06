// Agent-to-Agent Governance types (mirror backend app/schemas/agent.py)

export interface Agent {
  id: number;
  org_id: number;
  name: string;
  description?: string | null;
  agent_type?: string | null;
  version?: string | null;
  owner_user_id?: number | null;
  owner_team?: string | null;
  team_id?: number | null;
  role_id?: number | null;
  capabilities?: string[] | null;
  allowed_tools?: string[] | null;
  allowed_models?: string[] | null;
  max_delegation_depth: number;
  status: string; // active, suspended, retired
  public_key?: string | null;
  pq_public_key?: string | null;
  key_origin?: "agent" | "server" | null;
  key_fingerprint?: string | null;
  signature_scheme?: "ed25519" | "ed25519+ml-dsa-65" | null;
  created_at: string;
  updated_at?: string | null;
}

export interface AgentCreated extends Agent {
  api_key: string;              // shown once
  private_key?: string | null;  // shown once, only when the server generated the keypair
  pq_private_key?: string | null;  // ML-DSA-65 seed, shown once, server-generated hybrid only
}

export interface SigningKeyT {
  id: number;
  public_key: string;
  pq_public_key?: string | null;
  scheme?: "ed25519" | "ed25519+ml-dsa-65";
  fingerprint: string;
  origin: "agent" | "server";
  created_by?: number | null;
  created_at: string;
  retired_at?: string | null;
}

/** An entry of the organization's signing-key revocation list. */
export interface KeyRevocationT {
  id: number;
  agent_id: number;
  signing_key_id: number | null;
  fingerprint: string;
  revoked_at: string;
  /** signatures received from this moment on are not trusted */
  untrusted_from: string;
  reason: string;
  revoked_by: number | null;
}

export interface DelegationHopT {
  id: number;
  from_agent_id: number;
  to_agent_id: number;
  depth: number;
  delegated_capabilities?: string[] | null;
  /** Tools handed over on this hop; null on hops recorded before tools were delegated. */
  delegated_tools?: string[] | null;
  task_description?: string | null;
  expires_at?: string | null;
  verified: boolean;
  created_at: string;
}

export interface DelegationChainT {
  breaker_tripped_at?: string | null;
  breaker_reset_at?: string | null;
  breaker_details?: Record<string, unknown> | null;
  tainted_at?: string | null;
  taint_details?: Record<string, unknown> | null;
  id: number;
  org_id: number;
  root_agent_id: number;
  root_task?: string | null;
  status: string; // active, completed, violated, terminated
  total_hops: number;
  max_depth_reached: number;
  started_at: string;
  completed_at?: string | null;
}

export interface DelegationChainDetail extends DelegationChainT {
  hops: DelegationHopT[];
}

export interface AgentActionT {
  id: number;
  org_id: number;
  chain_id?: number | null;
  agent_id: number;
  action_type?: string | null;
  tool_name?: string | null;
  policy_check_result?: string | null; // allowed, denied, pending_approval
  reason?: string | null;
  duration_ms?: number | null;
  created_at: string;
}

export interface AgentPolicyT {
  id: number;
  org_id: number;
  agent_id?: number | null;
  name: string;
  rules?: Record<string, unknown> | null;
  priority: number;
  enabled: boolean;
  created_at: string;
}

export interface AgentIncidentT {
  id: number;
  org_id: number;
  chain_id?: number | null;
  agent_id?: number | null;
  incident_type?: string | null;
  severity?: string | null;
  details?: Record<string, unknown> | null;
  resolved: boolean;
  created_at: string;
}

export interface EscalationSummaryRow {
  agent_id: number;
  attempts: number;
  last_attempt: string | null;
}

// ---- Governance graph (live map) ----
export interface GraphNodeT {
  id: number;
  name: string;
  agent_type?: string | null;
  status: string;
  has_violation: boolean;
  action_count: number;
}

export interface GraphEdgeT {
  id: number;
  chain_id: number;
  from_agent_id: number;
  to_agent_id: number;
  delegated_capabilities: string[];
  verified: boolean;
  chain_status: string;
  is_violation: boolean;
  is_tripped?: boolean;
}

export interface GovernanceGraphT {
  nodes: GraphNodeT[];
  edges: GraphEdgeT[];
  generated_at: string;
}
