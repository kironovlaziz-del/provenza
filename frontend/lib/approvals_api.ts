// ASI09 review-bound approvals. Reuses the shared axios instance from api.ts.
// A decision is signed with this session's key (docs/pvp/edge.md, section 3):
// the server builds the statement, this browser signs it, the server checks it.
import { api } from "./api";
import { apiErrorText } from "./errors";
import { signWithSessionKey } from "./signing";

export interface PendingApproval {
  id: number;
  agent_id: number;
  agent_name: string;
  chain_id: number | null;
  tool_name: string | null;
  reason: string | null;
  created_at: string;
  expires_at: string;
}

export interface ReviewPacket {
  action: {
    id: number;
    agent_id: number;
    chain_id: number | null;
    action_type: string | null;
    tool_name: string | null;
    input: Record<string, unknown>;
    status: string;
    reason: string | null;
    created_at: string;
  };
  verified: {
    input_sha256: string;
    signature: { present: boolean; valid: boolean; covers_these_arguments: boolean };
    check_id: number | null;
    policy: { id: number | null; name: string | null };
    agent: { id: number; name: string; status: string; owner_user_id: number | null; owner_team: string | null; allowed_tools: string[] };
    chain: {
      id: number;
      status: string;
      root_agent_id: number;
      depth: number;
      delegated_by_agent_id: number | null;
      delegated_capabilities: string[] | null;
    } | null;
    inventory: { system_id: number | null; risk_tier: string | null; risk_confirmed: boolean };
    recent_7d: { actions: number; denied: number; denial_rate: number | null };
  };
  unverified_statements: { source: string; text: string }[];
  decision: {
    decision: string;
    decided_by: number | null;
    decided_at: string;
    reason: string | null;
    self_approved: boolean;
    signed: boolean;
  } | null;
  reviewer: {
    can_decide: boolean;
    blocked_reason: string | null;
    self_approval: boolean;
    requires_typed_confirmation: boolean;
    confirmation_text: string;
    flags: string[];
    expires_at: string;
    /** this session's key is certified by the passkey: it can sign an approval */
    session_certified: boolean;
  };
}

export async function listPendingApprovals() {
  const { data } = await api.get<PendingApproval[]>("/agents/approvals/pending");
  return data;
}

export async function getReviewPacket(actionId: number) {
  const { data } = await api.get<ReviewPacket>(`/agents/actions/${actionId}/review`);
  return data;
}

type Decision = "approved" | "denied";

/** The server's statement for this decision, signed with this session's key. */
async function signedDecision(actionId: number, decision: Decision) {
  const { data } = await api.post<{ statement: Record<string, unknown> }>(`/agents/actions/${actionId}/statement`, {
    decision,
  });
  try {
    const signature = await signWithSessionKey(String(data.statement.session_id), data.statement);
    return { statement: data.statement, signature };
  } catch {
    // the key is not in this browser (cleared storage, another browser)
    throw { response: { data: { detail: "session.no_key" } } };
  }
}

export async function approveReviewed(actionId: number, inputSha256: string, confirmation?: string) {
  const signed = await signedDecision(actionId, "approved");
  const { data } = await api.post(`/agents/actions/${actionId}/approve`, {
    input_sha256: inputSha256,
    confirmation: confirmation || null,
    ...signed,
  });
  return data;
}

/** A denial is signed when this session can sign; refusing never waits for it. */
export async function denyReviewed(actionId: number, reason: string | undefined, canSign: boolean) {
  let signed = {};
  if (canSign) {
    try {
      signed = await signedDecision(actionId, "denied");
    } catch {
      signed = {};
    }
  }
  const { data } = await api.post(`/agents/actions/${actionId}/deny`, { reason: reason || null, ...signed });
  return data;
}

export function approvalError(err: unknown, fallback: string): string {
  return apiErrorText(err, fallback);
}
