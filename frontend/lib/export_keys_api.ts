// Export keys: read-only credentials a SIEM uses for the egress event feed
// (X-Export-Key). Backend: app/api/export_keys.py.

import { api } from "./api";

export interface ExportKey {
  id: number;
  name: string;
  scope: string;
  /** the first characters of the key, to tell keys apart */
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ExportKeyCreated extends ExportKey {
  /** the key itself - returned only by the create call */
  api_key: string;
}

export async function listExportKeys(): Promise<ExportKey[]> {
  const { data } = await api.get<ExportKey[]>("/export-keys/");
  return data;
}

export async function createExportKey(name: string): Promise<ExportKeyCreated> {
  const { data } = await api.post<ExportKeyCreated>("/export-keys/", { name });
  return data;
}

export async function revokeExportKey(id: number): Promise<ExportKey> {
  const { data } = await api.post<ExportKey>(`/export-keys/${id}/revoke`);
  return data;
}
