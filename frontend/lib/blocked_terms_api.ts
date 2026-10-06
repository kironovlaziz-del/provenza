// Blocked terms (backend services/blocked_terms.py, /api/v1/blocked-terms).
import { api } from "./api";

export type TermScope = "org" | "agents" | "team" | "agent" | "policy";
export type TermMatch = "word" | "substring";
export type TermAction = "block" | "monitor";
export const TERM_SCOPES: TermScope[] = ["org", "agents", "team", "agent", "policy"];

export interface BlockedTermT {
  id: number;
  term: string;
  match: TermMatch;
  action: TermAction;
  scope: TermScope;
  target_id: number | null;
  target_name: string | null;
  category_id: number | null;
  category: string | null;
  enabled: boolean;
  note: string | null;
  hits: number;
  last_hit_at: string | null;
  source: string | null;
  created_at: string;
  updated_at: string;
}

export interface TermCategoryT {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  terms: number;
}

export interface TermsOverviewT {
  terms: BlockedTermT[];
  categories: TermCategoryT[];
  targets: { teams: { id: number; name: string }[]; agents: { id: number; name: string }[]; policies: { id: number; name: string }[] };
  limits: { max_terms: number; max_term_length: number };
}

export interface TermInput {
  term: string;
  match: TermMatch;
  action: TermAction;
  scope: TermScope;
  target_id: number | null;
  category_id: number | null;
  enabled: boolean;
  note: string | null;
}

export interface TermTestT {
  hits: {
    id: number | null;
    term: string;
    match: TermMatch;
    action: TermAction;
    scope: TermScope | "draft";
    target_name: string | null;
    category: string | null;
    spans: { start: number; end: number; text: string }[];
  }[];
}

export interface ImportResultT {
  dry_run: boolean;
  added: number;
  skipped: { line: number; term: string; why: string }[];
  errors: { line: number; term: string; why: string }[];
  preview: { line: number; term: string; scope: string; action: string }[];
}

export async function termsOverview() {
  const { data } = await api.get<TermsOverviewT>("/blocked-terms");
  return data;
}

export async function createTerm(input: TermInput) {
  const { data } = await api.post("/blocked-terms", input);
  return data;
}

export async function updateTerm(id: number, input: Partial<TermInput>) {
  const { data } = await api.patch(`/blocked-terms/${id}`, input);
  return data;
}

export async function deleteTerm(id: number) {
  await api.delete(`/blocked-terms/${id}`);
}

export async function createCategory(name: string) {
  const { data } = await api.post("/blocked-terms/categories", { name });
  return data;
}

export async function updateCategory(id: number, input: { name?: string; enabled?: boolean }) {
  const { data } = await api.patch(`/blocked-terms/categories/${id}`, input);
  return data;
}

export async function deleteCategory(id: number) {
  await api.delete(`/blocked-terms/categories/${id}`);
}

export async function testTerms(sample: string, term?: { term: string; match: TermMatch; action: TermAction } | null) {
  const { data } = await api.post<TermTestT>("/blocked-terms/test", { sample, term: term ?? null });
  return data;
}

export async function exportTermsCsv() {
  const { data } = await api.get<Blob>("/blocked-terms/export.csv", { responseType: "blob" });
  return data;
}

export async function importTermsCsv(csv: string, dryRun: boolean) {
  const { data } = await api.post<ImportResultT>("/blocked-terms/import", { csv, dry_run: dryRun });
  return data;
}
