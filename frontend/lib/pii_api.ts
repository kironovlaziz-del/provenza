// PII rules of the prompt firewall (backend services/pii_rules.py, /api/v1/pii).
import { api } from "./api";

export type PiiAction = "mask" | "block";

export interface BuiltinTypeT {
  type: string;
  source: "regex" | "names";
  example: string;
  enabled: boolean;
  action: PiiAction;
}

export interface PiiRuleT {
  id: number;
  name: string;
  label: string;
  description: string | null;
  pattern: string;
  ignore_case: boolean;
  action: PiiAction;
  enabled: boolean;
  revision: number;
  timeouts: number;
  last_timeout_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PiiOverviewT {
  builtin: BuiltinTypeT[];
  revision: number;
  rules: PiiRuleT[];
  names: { ner_enabled: boolean; ner_languages: string[]; gazetteer_languages: string[] };
  limits: { max_rules: number; max_pattern_length: number; rule_timeout_ms: number };
}

export interface RuleInput {
  name: string;
  label: string;
  description?: string | null;
  pattern: string;
  ignore_case: boolean;
  action: PiiAction;
  enabled: boolean;
}

export interface PiiTestT {
  rule: {
    ok: boolean;
    error: string | null;
    detail: string | null;
    elapsed_ms?: number;
    count?: number;
    matches: { start: number; end: number; text: string }[];
  } | null;
  firewall: { blocked: boolean; reason: string | null; flags: string[]; masked_text: string; timed_out: number[] };
}

export async function piiOverview() {
  const { data } = await api.get<PiiOverviewT>("/pii");
  return data;
}

export async function saveBuiltin(types: Record<string, { enabled?: boolean; action?: PiiAction }>, revision: number) {
  const { data } = await api.put<PiiOverviewT>("/pii/builtin", { types, revision });
  return data;
}

export async function createRule(input: RuleInput) {
  const { data } = await api.post<PiiRuleT>("/pii/rules", input);
  return data;
}

export async function updateRule(id: number, input: Partial<RuleInput> & { revision?: number }) {
  const { data } = await api.patch<PiiRuleT>(`/pii/rules/${id}`, input);
  return data;
}

export async function deleteRule(id: number) {
  await api.delete(`/pii/rules/${id}`);
}

export async function testPii(
  sample: string,
  rule?: { label?: string; pattern: string; ignore_case: boolean; action: PiiAction } | null,
  ruleId?: number | null,
) {
  const { data } = await api.post<PiiTestT>("/pii/test", { sample, rule: rule ?? null, rule_id: ruleId ?? null });
  return data;
}
