// Rule packs (backend services/rule_packs.py, api/policy_packs.py).
import { api } from "./api";
import type { PolicyDocument, Scope } from "./policy_layers_api";

export type PackKind = "profile" | "guard";
export type PackLevel = Scope | "any";

export interface PackT {
  ref: string;
  id?: number;
  builtin: boolean;
  name: string;
  description: string | null;
  kind: PackKind;
  level: PackLevel;
  yaml: string;
  document: PolicyDocument;
}

export interface PackChange {
  field: string;
  before: unknown;
  after: unknown;
  added?: string[];
  removed?: string[];
}

export interface ApplyPreviewT {
  pack: { ref: string; name: string; kind: PackKind; level: PackLevel };
  revision: number;
  changes: PackChange[];
  skipped: string[];
}

export interface ApplicationT {
  id: number;
  pack_ref: string;
  pack_name: string;
  kind: PackKind;
  scope: Scope;
  target_id: number | null;
  applied_at: string | null;
  undone_at: string | null;
}

export interface UndoPreviewT {
  application: ApplicationT;
  revision: number;
  changes: PackChange[];
  edited_since: boolean;
}

export interface PackIn {
  name: string;
  description?: string | null;
  kind: PackKind;
  level: PackLevel;
  yaml: string;
}

export async function listPacks() {
  return (await api.get<{ builtin: PackT[]; own: PackT[] }>("/policy-packs")).data;
}

export async function createPack(body: PackIn) {
  return (await api.post<PackT>("/policy-packs", body)).data;
}

export async function updatePack(id: number, body: PackIn) {
  return (await api.put<PackT>(`/policy-packs/${id}`, body)).data;
}

export async function deletePack(id: number) {
  await api.delete(`/policy-packs/${id}`);
}

export async function previewApply(pack: string, scope: Scope, targetId: number | null) {
  return (await api.post<ApplyPreviewT>("/policy-packs/preview", { pack, scope, target_id: targetId })).data;
}

export async function applyPack(pack: string, scope: Scope, targetId: number | null, revision: number) {
  return (await api.post<{ skipped: string[] }>("/policy-packs/apply",
    { pack, scope, target_id: targetId, revision })).data;
}

export async function listApplications() {
  return (await api.get<ApplicationT[]>("/policy-packs/applications")).data;
}

export async function previewUndo(id: number) {
  return (await api.post<UndoPreviewT>(`/policy-packs/applications/${id}/preview-undo`)).data;
}

export async function undoApplication(id: number, revision: number, confirmEdited: boolean) {
  await api.post(`/policy-packs/applications/${id}/undo`, { revision, confirm_edited: confirmEdited });
}

/** A file name for a pack's YAML: letters, digits and dashes. */
export function packFileName(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
  return `${slug || "rule-pack"}.yaml`;
}
