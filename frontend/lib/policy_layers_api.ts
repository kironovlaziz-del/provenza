// Hierarchical policies (backend services/hier_policy.py, core/policy_doc.py).
import { api } from "./api";

export type Scope = "org" | "team" | "agent";

export interface PolicyDocument {
  version?: 1;
  description?: string;
  limits?: { requests_per_minute?: number; max_tokens?: number; max_delegation_depth?: number };
  models?: { allow?: string[] };
  providers?: { allow?: string[] };
  tools?: { allow?: string[]; deny?: string[]; require_approval?: string[] };
  content?: { scan_output?: boolean };
  requests?: { require_approval?: boolean };
}

export interface LayerT {
  scope: Scope;
  team_id: number | null;
  agent_id: number | null;
  document: PolicyDocument;
  yaml: string;
  revision: number;
  updated_at: string | null;
  updated_by: number | null;
}

export interface LevelT {
  source: string;
  scope: "gateway" | Scope;
  id: number | null;
  document: PolicyDocument;
}

export type FieldValue =
  | { value: number | boolean; source: string }
  | { constraints: { source: string; patterns: string[] }[] }
  | { items: { value: string; source: string }[] };

export interface ResolvedT {
  fields: Record<string, FieldValue>;
  ignored: { field: string; source: string; value: unknown; because: string; kept: unknown }[];
}

export interface PreviewT {
  ok: boolean;
  error?: { code: string; path: string; detail: string };
  document?: PolicyDocument;
  yaml?: string;
  levels?: LevelT[];
  effective?: ResolvedT;
}

export interface OverviewT {
  org: { rules: number; revision: number };
  teams: { id: number; name: string; parent_id: number | null; rules: number }[];
  agents: { id: number; name: string | null; rules: number }[];
}

export async function overview() {
  return (await api.get<OverviewT>("/policy-layers/overview")).data;
}

export async function getLayer(scope: Scope, targetId?: number | null) {
  return (await api.get<LayerT>("/policy-layers", { params: { scope, target_id: targetId ?? undefined } })).data;
}

export async function saveLayer(scope: Scope, targetId: number | null, body: { yaml?: string; document?: PolicyDocument },
                                revision: number) {
  return (await api.put<LayerT>("/policy-layers", { scope, target_id: targetId, revision, ...body })).data;
}

export async function previewLayer(scope: Scope, targetId: number | null, body: { yaml?: string; document?: PolicyDocument }) {
  return (await api.post<PreviewT>("/policy-layers/preview", { scope, target_id: targetId, ...body })).data;
}

export async function effectiveFor(params: { agent_id?: number; team_id?: number }) {
  return (await api.get<{ levels: LevelT[]; effective: ResolvedT }>("/policy-layers/effective", { params })).data;
}

/** The fields in display order, with how levels combine. */
export const FIELD_ORDER: { field: string; kind: "min" | "allow" | "union" | "or" }[] = [
  { field: "limits.requests_per_minute", kind: "min" },
  { field: "limits.max_tokens", kind: "min" },
  { field: "limits.max_delegation_depth", kind: "min" },
  { field: "models.allow", kind: "allow" },
  { field: "providers.allow", kind: "allow" },
  { field: "tools.allow", kind: "allow" },
  { field: "tools.deny", kind: "union" },
  { field: "tools.require_approval", kind: "union" },
  { field: "content.scan_output", kind: "or" },
  { field: "requests.require_approval", kind: "or" },
];
