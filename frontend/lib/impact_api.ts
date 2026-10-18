// Impact assessments of AI systems (backend app/api/impact_assessments.py):
// one questionnaire per system that serves as the ISO/IEC 42005 impact
// assessment, the GDPR DPIA and the EU AI Act FRIA.

import { api } from "./api";

export type QuestionType = "text" | "choice" | "multi" | "date";
export type Answers = Record<string, string | string[]>;

export interface Question {
  id: string;
  label: string;
  type: QuestionType;
  options: string[];
  required: boolean;
  required_if: Record<string, string> | null;
  help: string | null;
}

export interface Section {
  id: string;
  title: string;
  refs: string[];
  questions: Question[];
}

export interface Template {
  version: string;
  sections: Section[];
}

export interface AssessmentSummary {
  id: number;
  version: number;
  status: "draft" | "approved";
  template_version: string;
  residual: string | null;
  decision: string | null;
  personal_data: string | null;
  created_at: string;
  updated_at: string | null;
  approved_by: number | null;
  approved_at: string | null;
  review_due: string | null;
}

export interface Assessment extends AssessmentSummary {
  answers: Answers;
}

export interface SystemAssessments {
  system_id: number;
  draft: Assessment | null;
  missing: string[] | null;
  approved: Assessment | null;
  history: AssessmentSummary[];
}

export async function getTemplate(): Promise<Template> {
  const { data } = await api.get<Template>("/impact-assessments/template");
  return data;
}

export async function getForSystem(systemId: number): Promise<SystemAssessments> {
  const { data } = await api.get<SystemAssessments>(`/impact-assessments/systems/${systemId}`);
  return data;
}

export async function saveDraft(systemId: number, answers: Answers): Promise<Assessment & { missing: string[] }> {
  const { data } = await api.put<Assessment & { missing: string[] }>(
    `/impact-assessments/systems/${systemId}/draft`, { answers });
  return data;
}

export async function approveDraft(systemId: number): Promise<Assessment> {
  const { data } = await api.post<Assessment>(`/impact-assessments/systems/${systemId}/approve`);
  return data;
}

/** A question is required by itself or by another answer (required_if). */
export function isRequired(q: Question, answers: Answers): boolean {
  if (q.required) return true;
  if (!q.required_if) return false;
  return Object.entries(q.required_if).every(([k, v]) => answers[k] === v);
}

export function isFilled(v: string | string[] | undefined): boolean {
  if (v === undefined) return false;
  return Array.isArray(v) ? v.length > 0 : v.trim().length > 0;
}
