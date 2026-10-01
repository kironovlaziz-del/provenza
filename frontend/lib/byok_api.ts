// BYOK (organization encryption keys) API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type KeyProvider = "local" | "vault_transit" | "aws_kms";

export interface OrgKeyT {
  id: number;
  version: number;
  provider: KeyProvider;
  config: Record<string, string>;
  has_secret: boolean;
  status: "active" | "retired" | "shredded";
  last_check_at: string | null;
  last_check_ok: boolean | null;
  last_error: string | null;
  created_at: string;
  retired_at: string | null;
  shredded_at: string | null;
}

export interface DataRow {
  table: string;
  column: string;
  total: number;
  server_key: number;
  active_key: number;
  older_keys: number;
}

export interface JobT {
  id: number;
  kind: "enable" | "rotate" | "disable";
  target_key_id: number | null;
  status: "queued" | "running" | "done" | "failed";
  total: number;
  done: number;
  failed: number;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface ByokOverview {
  enabled: boolean;
  aws_available: boolean;
  keys: OrgKeyT[];
  data: DataRow[];
  jobs: JobT[];
}

export interface KeyConfig {
  provider: KeyProvider;
  addr?: string;
  mount?: string;
  key_name?: string;
  token?: string;
  namespace?: string;
  region?: string;
  key_id?: string;
  access_key_id?: string;
  secret_access_key?: string;
}

export async function getByok() {
  const { data } = await api.get<ByokOverview>("/byok/");
  return data;
}

export async function newKey(cfg: KeyConfig) {
  const body = Object.fromEntries(Object.entries(cfg).filter(([, v]) => v !== undefined && v !== ""));
  const { data } = await api.post("/byok/keys", body);
  return data;
}

export async function disableByok() {
  const { data } = await api.post("/byok/disable");
  return data;
}

export async function checkKey() {
  const { data } = await api.post<{ ok: boolean; error: string | null }>("/byok/check");
  return data;
}

export async function retryJob(id: number) {
  const { data } = await api.post(`/byok/jobs/${id}/retry`);
  return data;
}

export async function shredKeys(confirm: string) {
  const { data } = await api.post("/byok/shred", { confirm });
  return data;
}

export function byokError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
