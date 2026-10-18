// Assurance records of AI systems (backend app/api/assurance.py): tests a
// system went through - evaluations, bias tests, red teaming, robustness.

import { api } from "./api";

export const ASSURANCE_KINDS = ["evaluation", "bias", "red_team", "robustness"] as const;
export const ASSURANCE_RESULTS = ["passed", "passed_with_findings", "failed"] as const;
export type AssuranceKind = (typeof ASSURANCE_KINDS)[number];
export type AssuranceResult = (typeof ASSURANCE_RESULTS)[number];

export interface AssuranceRecordIn {
  kind: AssuranceKind;
  title: string;
  performed_on: string;
  performed_by?: string | null;
  result: AssuranceResult;
  summary?: string | null;
  findings?: string | null;
  evidence_url?: string | null;
  next_due?: string | null;
}

export interface AssuranceRecord extends AssuranceRecordIn {
  id: number;
  system_id: number;
  created_by: number | null;
}

export async function listForSystem(systemId: number): Promise<AssuranceRecord[]> {
  const { data } = await api.get<AssuranceRecord[]>(`/assurance/systems/${systemId}`);
  return data;
}

export async function addRecord(systemId: number, rec: AssuranceRecordIn): Promise<AssuranceRecord> {
  const { data } = await api.post<AssuranceRecord>(`/assurance/systems/${systemId}`, rec);
  return data;
}
