// ASI06 memory-integrity API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type MemoryMode = "off" | "monitor" | "enforce";
export type EntryStatus = "trusted" | "quarantined" | "revoked" | "rejected";

export interface MemorySettings {
  mode: MemoryMode;
  shared_namespaces: string[];
  default_ttl_days: number;
  source?: "default" | "org";
}

export interface MemFinding {
  check: "ASI01" | "ASI05";
  label: string;
  severity?: string;
  snippet: string;
  chunk_index?: number;
  poisoned?: boolean;
}

export interface MemoryEntryT {
  id: number;
  agent_id: number;
  agent_name: string;
  chain_id: number | null;
  namespace: string;
  key: string | null;
  sha256: string;
  size_bytes: number;
  source: string;
  source_ref: string | null;
  status: EntryStatus;
  reasons: string[];
  findings: MemFinding[];
  expires_at: string | null;
  created_at: string;
  decided: boolean;
}

export interface MemoryOverview {
  settings: MemorySettings;
  entry_counts: Record<string, number>;
  entries: MemoryEntryT[];
}

export async function getMemoryOverview(status?: EntryStatus | "") {
  const { data } = await api.get<MemoryOverview>("/memory/", { params: status ? { entry_status: status } : {} });
  return data;
}

export async function saveMemorySettings(s: MemorySettings) {
  const { data } = await api.put("/memory/settings", {
    mode: s.mode,
    shared_namespaces: s.shared_namespaces,
    default_ttl_days: s.default_ttl_days,
  });
  return data;
}

export async function setEntryTrust(id: number, trusted: boolean) {
  const { data } = await api.post(`/memory/entries/${id}/${trusted ? "trust" : "revoke"}`);
  return data;
}

export function memoryError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
