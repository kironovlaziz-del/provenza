// Compliance auto-mapping API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type CStatus = "pass" | "partial" | "fail" | "manual" | "na";
export type FrameworkId = "eu_ai_act" | "gdpr" | "iso42001" | "nist_ai_rmf" | "owasp_agentic";

export interface Evidence {
  label: string;
  value: string | number | null;
  link?: string;
}

export interface Attestation {
  id: number;
  status: "met" | "not_met" | "not_applicable";
  note: string | null;
  evidence_url: string | null;
  attested_by: number;
  attested_at: string;
  valid_until: string | null;
  expired?: boolean;
}

export interface SystemRow {
  system_id: number;
  system: string;
  status: CStatus;
  detail: string;
  evidence: Evidence[];
  attestation: Attestation | null;
}

export interface RequirementResult {
  id: string;
  framework: FrameworkId;
  ref: string;
  title: string;
  scope: "org" | "system";
  applies: string;
  attest: boolean;
  fix: string | null;
  status: CStatus;
  detail: string;
  evidence: Evidence[];
  attestation: Attestation | null;
  systems?: SystemRow[];
}

export interface FrameworkSummary {
  name: string;
  ref: string;
  counts: Record<CStatus, number>;
  applicable: number;
  score: number | null;
}

export interface ComplianceResult {
  catalog_version: string;
  generated_at: string;
  frameworks: FrameworkId[];
  summary: Record<string, FrameworkSummary>;
  requirements: RequirementResult[];
  generated_by?: number;
}

export interface ReportListItem {
  id: number;
  created_at: string;
  created_by: number | null;
  frameworks: FrameworkId[];
  summary: Record<string, FrameworkSummary>;
  sha256: string;
}

export async function getComplianceStatus() {
  const { data } = await api.get<ComplianceResult>("/compliance/status");
  return data;
}

export async function attest(payload: {
  requirement_id: string;
  system_id?: number | null;
  status: Attestation["status"];
  note?: string;
  evidence_url?: string;
  valid_days?: number;
}) {
  const body = Object.fromEntries(Object.entries(payload).filter(([, v]) => v !== undefined && v !== "" && v !== null));
  const { data } = await api.post("/compliance/attestations", body);
  return data;
}

export async function createReport(frameworks?: FrameworkId[]) {
  const { data } = await api.post<{ id: number; sha256: string }>("/compliance/reports", { frameworks: frameworks ?? null });
  return data;
}

export async function listReports() {
  const { data } = await api.get<ReportListItem[]>("/compliance/reports");
  return data;
}

export async function getReport(id: number) {
  const { data } = await api.get<{ id: number; created_at: string; sha256: string; integrity_ok: boolean; content: ComplianceResult }>(
    `/compliance/reports/${id}`,
  );
  return data;
}

export function complianceError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}

export const STATUS_PILL: Record<CStatus, string> = {
  pass: "pill-low",
  partial: "pill-medium",
  fail: "pill-critical",
  manual: "pill-high",
  na: "pill-neutral",
};
