// Request pipeline time limits API. Reuses the shared axios instance from api.ts.
import { api } from "./api";

export interface QueueSettings {
  queue_ttl_seconds: number;
  approval_ttl_hours: number;
  raw_prompt_retention_days: number | null;
  agent_check_retention_days?: number | null;
  agent_content_retention_days?: number | null;
  source?: "default" | "org";
}

export interface LiveRow {
  count: number;
  oldest_age_seconds: number | null;
}

export interface SweepRow {
  id: number;
  ran_at: string;
  trigger: "beat" | "manual";
  expired_queued: number;
  expired_approvals: number;
  failed_stuck: number;
  purged_prompts: number;
  purged_checks?: number;
  scrubbed_content?: number;
}

export interface QueueOverview {
  settings: QueueSettings;
  live: Record<"pending" | "approved" | "processing" | "pending_approval", LiveRow>;
  expired_7d: number;
  raw_prompts_kept: number;
  sweeps: SweepRow[];
}

export async function getQueueOverview() {
  const { data } = await api.get<QueueOverview>("/queue/");
  return data;
}

export async function saveQueueSettings(s: QueueSettings) {
  const { data } = await api.put("/queue/settings", {
    queue_ttl_seconds: s.queue_ttl_seconds,
    approval_ttl_hours: s.approval_ttl_hours,
    raw_prompt_retention_days: s.raw_prompt_retention_days,
    agent_check_retention_days: s.agent_check_retention_days ?? null,
    agent_content_retention_days: s.agent_content_retention_days ?? null,
  });
  return data;
}

export async function sweepNow() {
  const { data } = await api.post<Omit<SweepRow, "id" | "ran_at" | "trigger">>("/queue/sweep");
  return data;
}

export function queueError(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
