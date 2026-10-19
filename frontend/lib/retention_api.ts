// Retention of agent telemetry. Reuses the shared axios instance from api.ts.
import { api } from "./api";
import { apiErrorText } from "./errors";

export type RetentionKey = "agent_check_retention_days" | "agent_content_retention_days";

export interface RetentionSettings {
  agent_check_retention_days: number | null;   // null: keep indefinitely
  agent_content_retention_days: number | null;
  source?: "default" | "org";
}

export interface RetentionRun {
  id: number;
  ran_at: string;
  trigger: "beat" | "manual";
  purged_checks: number;
  scrubbed_content: number;
}

export interface RetentionOverview {
  settings: RetentionSettings;
  runs: RetentionRun[];
}

export async function getRetention() {
  const { data } = await api.get<RetentionOverview>("/retention/");
  return data;
}

export async function saveRetention(s: RetentionSettings) {
  const { data } = await api.put<RetentionSettings>("/retention/settings", {
    agent_check_retention_days: s.agent_check_retention_days,
    agent_content_retention_days: s.agent_content_retention_days,
  });
  return data;
}

export async function runRetention() {
  const { data } = await api.post<Pick<RetentionRun, "purged_checks" | "scrubbed_content">>("/retention/run");
  return data;
}

export function retentionError(err: unknown, fallback: string): string {
  return apiErrorText(err, fallback);
}
