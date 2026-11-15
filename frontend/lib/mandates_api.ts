// A task a person gives an agent, signed (docs/proof-of-authority.md): the
// server builds the statement, this browser signs it with the session key
// the person's passkey certified, the server checks it.
import { api } from "./api";
import { signWithSessionKey } from "./signing";

export interface MandateT {
  id: number;
  agent_id: number;
  user_id: number;
  task: string;
  /** null: all of the agent's tools */
  tools: string[] | null;
  status: "active" | "ended" | "expired";
  expires_at: string;
  created_at: string;
  ended_at: string | null;
  ended_by: number | null;
  statement_sha256: string;
}

export async function listMandates(agentId: number) {
  const { data } = await api.get<{ current: MandateT | null; history: MandateT[] }>(`/agents/${agentId}/mandates`);
  return data;
}

export async function giveMandate(agentId: number, task: string, tools: string[] | null, validHours: number) {
  const body = { task, tools, valid_hours: validHours };
  const { data } = await api.post<{ statement: Record<string, unknown> }>(`/agents/${agentId}/mandates/statement`, body);
  let signature: string;
  try {
    signature = await signWithSessionKey(String(data.statement.session_id), data.statement);
  } catch {
    // the key is not in this browser (cleared storage, another browser)
    throw { response: { data: { detail: "session.no_key" } } };
  }
  const res = await api.post<MandateT>(`/agents/${agentId}/mandates`, { ...body, statement: data.statement, signature });
  return res.data;
}

/** Ending is signed like giving: when the task stopped is the person's word. */
export async function endMandate(agentId: number, mandateId: number) {
  const base = `/agents/${agentId}/mandates/${mandateId}/end`;
  const { data } = await api.post<{ statement: Record<string, unknown> }>(`${base}/statement`);
  let signature: string;
  try {
    signature = await signWithSessionKey(String(data.statement.session_id), data.statement);
  } catch {
    throw { response: { data: { detail: "session.no_key" } } };
  }
  const res = await api.post<MandateT>(base, { statement: data.statement, signature });
  return res.data;
}
