// OpenTelemetry export of PVP decisions: OTLP/HTTP log records to the
// organization's collector. Backend: app/api/otel_export.py,
// app/services/otel_export.py.

import { api } from "./api";

export interface OtelExportT {
  enabled: boolean;
  endpoint: string | null;
  /** where the records are POSTed: the endpoint, ending in /v1/logs */
  logs_url: string | null;
  /** the host this export sends to - outbound traffic */
  outbound_host: string | null;
  header_name: string | null;
  /** a header value is stored (never shown) */
  header_set: boolean;
  last_success_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  exported_total: number;
  updated_at: string | null;
}

export interface OtelExportInput {
  enabled: boolean;
  endpoint: string | null;
  /** no name removes the header; a name without a value keeps the stored value */
  header_name: string | null;
  header_value: string | null;
}

export async function getOtelExport(): Promise<OtelExportT> {
  const { data } = await api.get<OtelExportT>("/otel-export/");
  return data;
}

export async function setOtelExport(input: OtelExportInput): Promise<OtelExportT> {
  const { data } = await api.put<OtelExportT>("/otel-export/", input);
  return data;
}

export async function testOtelExport(): Promise<{ ok: boolean; note: string | null }> {
  const { data } = await api.post<{ ok: boolean; note: string | null }>("/otel-export/test");
  return data;
}
