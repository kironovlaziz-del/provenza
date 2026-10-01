// Real-time agent observability API: history, aggregates and the live SSE
// stream (fetch + ReadableStream, because EventSource cannot send the
// Authorization header).
import { api, getToken } from "./api";

export type ObsEventType =
  | "action.checked"
  | "action.recorded"
  | "llm.call"
  | "a2a.message"
  | "delegation.hop"
  | "incident.created";
export const OBS_EVENT_TYPES: ObsEventType[] = [
  "action.checked",
  "action.recorded",
  "llm.call",
  "a2a.message",
  "delegation.hop",
  "incident.created",
];
export type Decision = "allowed" | "denied" | "pending_approval";

export interface ObsEvent {
  v: number;
  type: ObsEventType;
  id: number;
  ts: string;
  agent_id?: number;
  chain_id?: number;
  action_type?: string;
  tool?: string;
  decision?: Decision;
  guards?: string[];
  incident_type?: string;
  severity?: string;
  duration_ms?: number;
  policy_id?: number;
  has_check?: boolean;
  resolved?: boolean;
  // llm.call
  model?: string;
  status?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  flags?: string[];
  // a2a.message / delegation.hop
  to_agent_id?: number;
  message_type?: string;
  depth?: number;
  capabilities?: string[];
  verified?: boolean;
  // detail=1: content with PII masked
  content?: { label: string; text: string }[];
  masked?: boolean;
  content_error?: boolean;
}

export interface AgentRow {
  id: number;
  name: string;
  status: string;
  agent_type: string | null;
  key_revoked?: boolean;
  events: number;
  llm_calls: number;
  llm_tokens: number;
  decisions: number;
  denied: number;
  pending: number;
  incidents: number;
  last_seen: string | null;
  p95_ms: number | null;
}

export interface ObsSummary {
  window_minutes: number;
  bucket_seconds: number;
  generated_at: string;
  totals: {
    events: number;
    llm_calls: number;
    llm_errors: number;
    llm_tokens: number;
    llm_p95_ms: number | null;
    a2a_messages: number;
    delegations: number;
    decisions: number;
    allowed: number;
    denied: number;
    pending: number;
    incidents: number;
    recorded: number;
    deny_rate: number | null;
    p50_ms: number | null;
    p95_ms: number | null;
    active_agents: number;
    open_incidents: number;
  };
  agents: AgentRow[];
}

export type ObsDim = "type" | "decision" | "agent" | "model" | "llm_status" | "tool" | "guard" | "incident" | "a2a_status";
export type ObsMetric = "count" | "tokens" | "p95_ms";

export interface Timeseries {
  dim: ObsDim;
  metric: ObsMetric;
  window_minutes: number;
  bucket_seconds: number;
  buckets: string[];
  series: { key: string; total: number; values: number[] }[];
}

export interface Breakdown {
  dim: ObsDim;
  by: ObsDim;
  rows: { key: string; total: number; parts: Record<string, number> }[];
}

export async function getTimeseries(dim: ObsDim, metric: ObsMetric, minutes: number, agentIds: number[]): Promise<Timeseries> {
  const params: Record<string, string | number> = { dim, metric, minutes };
  if (agentIds.length) params.agent_id = agentIds.join(",");
  const { data } = await api.get<Timeseries>("/observability/timeseries", { params });
  return data;
}

export async function getBreakdown(dim: ObsDim, by: ObsDim, minutes: number, agentIds: number[]): Promise<Breakdown> {
  const params: Record<string, string | number> = { dim, by, minutes };
  if (agentIds.length) params.agent_id = agentIds.join(",");
  const { data } = await api.get<Breakdown>("/observability/breakdown", { params });
  return data;
}

/** Admin only, audited on the server: the event's content without PII masking. */
export async function revealEvent(type: ObsEventType, id: number, reason: string): Promise<{ label: string; text: string }[]> {
  const { data } = await api.post<{ content: { label: string; text: string }[] }>("/observability/reveal", { type, id, reason });
  return data.content;
}

export interface ObsFilters {
  agentIds: number[];
  types: ObsEventType[];
}

function filterParams(f: ObsFilters): Record<string, string> {
  const p: Record<string, string> = {};
  if (f.agentIds.length) p.agent_id = f.agentIds.join(",");
  if (f.types.length && f.types.length < OBS_EVENT_TYPES.length) p.event_types = f.types.join(",");
  return p;
}

export async function getObsSummary(minutes: number, agentIds: number[]): Promise<ObsSummary> {
  const params: Record<string, string | number> = { minutes };
  if (agentIds.length) params.agent_id = agentIds.join(",");
  const { data } = await api.get<ObsSummary>("/observability/summary", { params });
  return data;
}

export async function getObsEvents(f: ObsFilters, minutes = 15, limit = 300, detail = false): Promise<ObsEvent[]> {
  const params: Record<string, string | number> = { ...filterParams(f), minutes, limit };
  if (detail) params.detail = "true";
  const { data } = await api.get<ObsEvent[]>("/observability/events", { params });
  return data;
}

/** A decision is one verdict per action: every check, plus records made without a check. */
export function isDecision(e: ObsEvent): boolean {
  return e.type === "action.checked" || (e.type === "action.recorded" && !e.has_check);
}

export type StreamState = "connecting" | "live" | "retrying" | "stopped";

/**
 * Opens the live stream and keeps it open: reconnects with backoff (1 s up to
 * 30 s) after network errors or server-side failures; stops on 401/403/422.
 * Returns a function that closes it.
 */
export function openObsStream(
  f: ObsFilters,
  onEvents: (events: ObsEvent[], dropped: number) => void,
  onState: (s: StreamState, detail?: string) => void,
  withContent = false,
): () => void {
  const controller = new AbortController();
  let stopped = false;
  let delay = 1000;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
  const qs = new URLSearchParams({ ...filterParams(f), ...(withContent ? { detail: "true" } : {}) }).toString();

  function retry(detail?: string) {
    if (stopped) return;
    onState("retrying", detail);
    timer = setTimeout(run, delay);
    delay = Math.min(delay * 2, 30000);
  }

  function handle(raw: string): boolean {
    let name = "message";
    const lines: string[] = [];
    for (const line of raw.split("\n")) {
      if (line.startsWith("event:")) name = line.slice(6).trim();
      else if (line.startsWith("data:")) lines.push(line.slice(5).trim());
    }
    if (!lines.length) return true;
    let data: any;
    try {
      data = JSON.parse(lines.join("\n"));
    } catch {
      return true;
    }
    if (name === "hello") {
      delay = 1000;
      onState("live");
    } else if (name === "batch") {
      onEvents(data.events ?? [], data.dropped ?? 0);
    } else if (name === "error") {
      return false;
    }
    return true;
  }

  async function run() {
    if (stopped) return;
    onState("connecting");
    const token = getToken();
    if (!token) {
      stopped = true;
      onState("stopped", "not signed in");
      return;
    }
    try {
      const res = await fetch(`${apiBase}/observability/stream${qs ? `?${qs}` : ""}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" },
        signal: controller.signal,
        cache: "no-store",
      });
      if (res.status === 401 || res.status === 403 || res.status === 422) {
        stopped = true;
        onState("stopped", `HTTP ${res.status}`);
        return;
      }
      if (!res.ok || !res.body) {
        retry(`HTTP ${res.status}`);
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!stopped) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx: number;
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          if (!handle(frame)) {
            if (!controller.signal.aborted) reader.cancel().catch(() => undefined);
            retry("live events unavailable");
            return;
          }
        }
      }
      retry();
    } catch (e) {
      if ((e as { name?: string }).name === "AbortError") return;
      retry("connection lost");
    }
  }

  run();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    controller.abort();
    onState("stopped");
  };
}

export function obsError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
