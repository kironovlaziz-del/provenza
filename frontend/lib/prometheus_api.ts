// Prometheus HTTP API client, used by the /observability page.
// Separate from observability_api.ts (agent-observability stream) --
// different data sources, different shapes.
//
// The backend proxies these through /api/v1/observability/query{,_range}.

import { api } from "./api";

export interface PromSample {
  metric: Record<string, string>;
  value: [number, string];
}

export interface PromSeries {
  metric: Record<string, string>;
  values: [number, string][];
}

export interface PromResponse<T> {
  status: "success" | "error";
  data?: { resultType: string; result: T[] };
  error?: string;
}

export async function queryInstant(query: string): Promise<PromSample[]> {
  const r = await api.get<PromResponse<PromSample>>(
    "/metrics/query",
    { params: { query } },
  );
  return r.data.data?.result ?? [];
}

export async function queryRange(
  query: string,
  start: number,
  end: number,
  step = "15s",
): Promise<PromSeries[]> {
  const r = await api.get<PromResponse<PromSeries>>(
    "/metrics/query_range",
    { params: { query, start, end, step } },
  );
  return r.data.data?.result ?? [];
}

export function firstValue(samples: PromSample[]): number | null {
  if (!samples.length) return null;
  const v = samples[0].value?.[1];
  const n = v ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

export function seriesToChartRows(series: PromSeries[]): Array<Record<string, number>> {
  const byTs = new Map<number, Record<string, number>>();
  for (const s of series) {
    const label = Object.entries(s.metric)
      .filter(([k]) => k !== "__name__" && k !== "job" && k !== "instance" && k !== "service")
      .map(([k, v]) => `${k}=${v}`)
      .join(",") || "value";
    for (const [ts, raw] of s.values) {
      const n = Number(raw);
      if (!Number.isFinite(n)) continue;
      const row = byTs.get(ts) ?? { ts };
      row[label] = n;
      byTs.set(ts, row);
    }
  }
  return Array.from(byTs.values()).sort((a, b) => (a.ts as number) - (b.ts as number));
}

export function seriesLabels(series: PromSeries[]): string[] {
  const labels = new Set<string>();
  for (const s of series) {
    const label = Object.entries(s.metric)
      .filter(([k]) => k !== "__name__" && k !== "job" && k !== "instance" && k !== "service")
      .map(([k, v]) => `${k}=${v}`)
      .join(",") || "value";
    labels.add(label);
  }
  return Array.from(labels);
}
