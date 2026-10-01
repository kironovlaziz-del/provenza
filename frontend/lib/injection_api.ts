// ASI01 prompt-injection guard API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type InjectionMode = "off" | "monitor" | "enforce";
export type Verdict = "clean" | "suspicious" | "injection";

export interface InjectionSettings {
  mode: InjectionMode;
  threshold: number;
  source?: "default" | "org";
}

export interface Finding {
  label: string;
  weight: number;
  snippet: string;
}

export interface ScanResult {
  verdict: Verdict;
  score: number;
  findings: Finding[];
  truncated: boolean;
}

export interface Detection {
  id: number;
  detected_at: string;
  agent_id: number | null;
  agent_name: string | null;
  chain_id: number | null;
  action_id: number | null;
  source: "argument" | "output";
  tool_name: string | null;
  path: string | null;
  verdict: Verdict;
  score: number;
  findings: Finding[];
  outcome: "flagged" | "blocked" | "tainted";
}

export interface TaintedChain {
  chain_id: number;
  root_agent: string | null;
  status: string;
  tainted_at: string;
  details: { tool_name?: string; path?: string; score?: number; action_id?: number; findings?: Finding[] };
}

export interface InjectionOverview {
  settings: InjectionSettings;
  bounds: { threshold: [number, number] };
  weights: Record<string, number>;
  counts_24h: Record<string, number>;
  tainted_chains: TaintedChain[];
  detections: Detection[];
}

export async function getInjectionOverview() {
  const { data } = await api.get<InjectionOverview>("/injection/");
  return data;
}

export async function saveInjectionSettings(s: InjectionSettings) {
  const { data } = await api.put("/injection/settings", { mode: s.mode, threshold: s.threshold });
  return data;
}

export async function scanText(text: string) {
  const { data } = await api.post<ScanResult>("/injection/scan", { text });
  return data;
}

export async function clearTaint(chainId: number) {
  const { data } = await api.post(`/injection/chains/${chainId}/clear`);
  return data;
}

export function injectionError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
