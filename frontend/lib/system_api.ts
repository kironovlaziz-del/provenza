// System health API (database, Redis, Celery workers and beat).
import { api } from "./api";

export type HealthStatus = "ok" | "degraded" | "down";

export interface HealthProblem {
  code: "db_down" | "redis_down" | "no_workers" | "beat_stale" | "queue_backlog" | string;
  severity: "critical" | "warning";
  message: string;
}

export interface SystemHealth {
  status: HealthStatus;
  checked_at: string;
  problems: HealthProblem[];
  components: {
    database: { ok: boolean; latency_ms?: number; error?: string };
    redis: { ok: boolean; latency_ms?: number; queued_tasks?: number; error?: string; hint?: string };
    workers: { ok: boolean; names: string[]; count: number; error?: string };
    beat: { ok: boolean; last_heartbeat_age_seconds: number | null; expected_every_seconds: number };
  };
}

export async function getSystemHealth(): Promise<SystemHealth> {
  const { data } = await api.get<SystemHealth>("/system/health");
  return data;
}
