"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { getSystemHealth, type SystemHealth } from "@/lib/system_api";

const PILL = { ok: "pill-low", degraded: "pill-medium", down: "pill-critical" } as const;

function Row({ ok, title, detail, fix }: { ok: boolean; title: string; detail: React.ReactNode; fix?: string }) {
  const { t } = useTranslation();
  return (
    <div style={{ display: "flex", gap: 12, padding: "12px 0", borderBottom: "1px solid var(--border)", alignItems: "flex-start" }}>
      <span className={`pill ${ok ? "pill-low" : "pill-critical"}`} style={{ minWidth: 64, textAlign: "center" }}>
        {ok ? t("health.ok", "OK") : t("health.fail", "FAIL")}
      </span>
      <div style={{ flex: 1 }}>
        <strong>{title}</strong>
        <div className="hint-text" style={{ fontSize: 13 }}>{detail}</div>
        {!ok && fix && <pre className="mono" style={{ fontSize: 12, padding: 8, marginTop: 6, borderRadius: 4, whiteSpace: "pre-wrap" }}>{fix}</pre>}
      </div>
    </div>
  );
}

export default function SystemStatusPage() {
  const { t } = useTranslation();
  const [h, setH] = useState<SystemHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    setBusy(true);
    getSystemHealth()
      .then((d) => { setH(d); setError(null); })
      .catch(() => setError(t("health.load_failed", "Could not load the system status.")))
      .finally(() => setBusy(false));
  }, [t]);

  useEffect(() => {
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [load]);

  const c = h?.components;
  return (
    <>
      <PageHeader title={t("health.title", "System status")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t("health.hint", "The web app can look fine while background work has stopped. This page checks each part behind it: database, Redis, the Celery workers that process requests and sweeps, and Celery beat that schedules them.")}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "var(--risk-critical)" }}><div className="panel-body" style={{ color: "var(--risk-critical)" }}>{error}</div></div>}
        {h && c && (
          <div className="panel">
            <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
              <h2 style={{ display: "flex", gap: 10, alignItems: "center" }}>
                {t("health.overall", "Overall")}
                <span className={`pill ${PILL[h.status]}`}>{t(`health.status_${h.status}`, h.status)}</span>
              </h2>
              <span className="hint-text" style={{ fontSize: 12 }}>
                {t("health.checked", "checked")} {new Date(h.checked_at).toLocaleTimeString()}{" "}
                <button className="btn btn-sm" onClick={load} disabled={busy}>{t("health.recheck", "Check again")}</button>
              </span>
            </div>
            <div className="panel-body">
              <Row ok={c.database.ok} title={t("health.database", "Database (PostgreSQL)")}
                detail={c.database.ok ? `${c.database.latency_ms} ms` : c.database.error}
                fix="docker compose ps        # self-hosted: is postgres healthy?" />
              <Row ok={c.redis.ok} title={t("health.redis", "Redis (task queue and live events)")}
                detail={c.redis.ok ? `${c.redis.latency_ms} ms · ${t("health.queued", "queued tasks")}: ${c.redis.queued_tasks ?? 0}` : `${c.redis.hint} (${c.redis.error})`}
                fix={"Check that REDIS_PASSWORD in the backend environment matches the one Redis was started with,\nthen restart the API, worker and beat."} />
              <Row ok={c.workers.ok} title={t("health.workers", "Celery workers")}
                detail={c.workers.ok ? c.workers.names.join(", ") : t("health.no_workers", "No worker answers.") + (c.workers.error ? ` (${c.workers.error})` : "")}
                fix={"systemctl status ai-ct-celery          # systemd install\ndocker compose logs --tail 50 worker   # self-hosted"} />
              <Row ok={c.beat.ok} title={t("health.beat", "Celery beat (scheduled jobs)")}
                detail={c.beat.last_heartbeat_age_seconds == null
                  ? t("health.beat_never", "No heartbeat recorded yet.")
                  : `${t("health.beat_last", "last heartbeat")} ${Math.round(c.beat.last_heartbeat_age_seconds)} s ${t("health.ago", "ago")} (${t("health.expected", "expected every")} ${c.beat.expected_every_seconds} s)`}
                fix={"systemctl status ai-ct-celery-beat     # systemd install\ndocker compose logs --tail 50 beat     # self-hosted"} />
            </div>
          </div>
        )}
      </div>
    </>
  );
}
