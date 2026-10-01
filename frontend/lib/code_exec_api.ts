// ASI05 code-execution guard API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export type CodeExecMode = "off" | "monitor" | "enforce";
export type Severity = "none" | "medium" | "high" | "critical";

export interface CodeExecSettings {
  mode: CodeExecMode;
  code_tools: string[];
  approve_code_tools: boolean;
  source?: "default" | "org";
}

export interface ExecFinding {
  label: string;
  severity: Exclude<Severity, "none">;
  path: string;
  snippet: string;
}

export interface ExecDetection {
  id: number;
  detected_at: string;
  agent_id: number | null;
  agent_name: string | null;
  chain_id: number | null;
  tool_name: string | null;
  code_tool: boolean;
  severity: Severity;
  findings: ExecFinding[];
  outcome: "flagged" | "held" | "blocked";
}

export interface CodeExecOverview {
  settings: CodeExecSettings;
  default_code_tools: string[];
  labels: Record<string, Exclude<Severity, "none">>;
  counts_24h: Record<string, number>;
  detections: ExecDetection[];
}

export interface ExecScanResult {
  severity: Severity;
  findings: ExecFinding[];
  code_tool: boolean;
  would: "allowed" | "flagged" | "pending_approval" | "denied";
  mode: CodeExecMode;
}

export async function getCodeExecOverview() {
  const { data } = await api.get<CodeExecOverview>("/code-exec/");
  return data;
}

export async function saveCodeExecSettings(s: CodeExecSettings) {
  const { data } = await api.put("/code-exec/settings", {
    mode: s.mode,
    code_tools: s.code_tools,
    approve_code_tools: s.approve_code_tools,
  });
  return data;
}

export async function scanCall(toolName: string, input: string) {
  let body: Record<string, unknown>;
  try {
    const parsed = JSON.parse(input);
    body = { tool_name: toolName || null, arguments: parsed };
  } catch {
    body = { tool_name: toolName || null, text: input };
  }
  const { data } = await api.post<ExecScanResult>("/code-exec/scan", body);
  return data;
}

export function codeExecError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
