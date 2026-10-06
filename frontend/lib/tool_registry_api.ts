// ASI04 Tool Registry API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type SupplyChainMode = "off" | "monitor" | "enforce";
export type ToolStatus = "approved" | "pending" | "blocked" | "drifted";
export type ToolKind = "tool" | "mcp_server" | "sdk";

export interface ToolEntry {
  id: number;
  pattern: string;
  kind: ToolKind;
  display_name?: string | null;
  source?: string | null;
  publisher?: string | null;
  pinned_version?: string | null;
  pinned_digest?: string | null;
  status: ToolStatus;
  discovered: boolean;
  seen_count: number;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  approved_at?: string | null;
  drift_details?: {
    problems?: string[];
    reported_version?: string | null;
    detected_at?: string;
  } | null;
  notes?: string | null;
  /** Capabilities an agent must hold (in its chain) to call a matching tool. */
  required_capabilities?: string[] | null;
}

export interface ToolEntryInput {
  pattern: string;
  kind: ToolKind;
  display_name?: string;
  source?: string;
  publisher?: string;
  pinned_version?: string;
  pinned_digest?: string;
  status?: "approved" | "pending" | "blocked";
  notes?: string;
  required_capabilities?: string[];
}

/** "payments, email.send" -> ["email.send", "payments"] */
export function parseCapabilities(text: string): string[] {
  return Array.from(new Set(text.split(/[,\s]+/).map((c) => c.trim()).filter(Boolean))).sort();
}

export async function getSupplyChainMode() {
  const { data } = await api.get<{ mode: SupplyChainMode }>("/tool-registry/settings");
  return data.mode;
}

export async function setSupplyChainMode(mode: SupplyChainMode) {
  const { data } = await api.put("/tool-registry/settings", { mode });
  return data;
}

export async function listToolEntries() {
  const { data } = await api.get<ToolEntry[]>("/tool-registry/");
  return data;
}

export async function createToolEntry(payload: ToolEntryInput) {
  const { data } = await api.post<ToolEntry>("/tool-registry/", payload);
  return data;
}

export async function updateToolEntry(
  id: number,
  payload: { pinned_version?: string | null; pinned_digest?: string | null; publisher?: string | null; source?: string | null; notes?: string | null; required_capabilities?: string[] | null },
) {
  const { data } = await api.patch<ToolEntry>(`/tool-registry/${id}`, payload);
  return data;
}

export async function approveToolEntry(id: number) {
  const { data } = await api.post<ToolEntry>(`/tool-registry/${id}/approve`);
  return data;
}

export async function blockToolEntry(id: number) {
  const { data } = await api.post<ToolEntry>(`/tool-registry/${id}/block`);
  return data;
}

export async function deleteToolEntry(id: number) {
  const { data } = await api.delete(`/tool-registry/${id}`);
  return data;
}

export async function computeManifestDigest(manifest: unknown) {
  const { data } = await api.post<{ digest: string }>("/tool-registry/manifest-digest", { manifest });
  return data.digest;
}

export function registryError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
