"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { HealthPanel, type CheckState, type HealthCheck } from "@/components/observability/HealthPanel";
import { MON_RANGES, TrendChart, type MonRange } from "@/components/observability/TrendChart";
import { EndpointsTable } from "@/components/observability/EndpointsTable";
import { useVizColors } from "@/components/observability/useVizColors";
import { fmtAge, fmtLatency, fmtNumber, fmtPercent, fmtRate } from "@/components/observability/format";
import { firstValue, queryInstant } from "@/lib/prometheus_api";
import { getSystemHealth, type SystemHealth } from "@/lib/system_api";
import { useAuth } from "@/lib/auth";

// This page is admin-only. Admins see the whole installation: the
// platform aggregates metrics across every organization, because in a
// self-hosted install there is typically exactly one. Approvers and
// users do not reach here — the nav item is adminOnly, the page has a
// defensive role check, and /api/v1/metrics/query{,_range} enforces
// require_role(UserRole.admin) on the backend.
//
// Layout: first the verdict - is everything working, and if not, what and
// what to do - then the trends behind it, then the busiest endpoints.
//
// For deeper drill-downs the operator opens Grafana. It listens on the
// server's 127.0.0.1:3001 only, never on the public address, so the link
// points at the operator's own machine: it opens through an SSH tunnel
// (ssh -L 3001:127.0.0.1:3001 user@server), as the hint below says.
const GRAFANA_URL = "http://localhost:3001/d/ai-ct-backend";
const REFRESH_MS = 30_000;

interface Signals {
  reqRate: number | null;
  errorPct: number | null;
  p95: number | null;
  sensors: number | null;
  offline: number | null;
  heartbeatAge: number | null;
  auditRows: number | null;
  unsealed: number | null;
  checkpointAge: number | null;
  pruneFailed: number | null;
  prunedAgo: number | null;
  violationsPerMin: number | null;
}

const EMPTY: Signals = {
  reqRate: null, errorPct: null, p95: null, sensors: null, offline: null, heartbeatAge: null,
  auditRows: null, unsealed: null, checkpointAge: null, pruneFailed: null, prunedAgo: null,
  violationsPerMin: null,
};

export default function ObservabilityPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const colors = useVizColors();
  const [range, setRange] = useState<MonRange>(MON_RANGES[1]);
  const [signals, setSignals] = useState<Signals>(EMPTY);
  const [system, setSystem] = useState<SystemHealth | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const isAdmin = !!user && user.role === "admin";

  const loadSignals = useCallback(() => {
    if (!isAdmin) return;
    // Global queries — no org_id filter: the whole installation.
    const q = (expr: string) => queryInstant(expr).then(firstValue);
    Promise.all([
      q("sum(rate(http_requests_total[5m])) or vector(0)"),
      q('sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100'),
      q("histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))"),
      q("count(sensor_last_heartbeat_age_seconds) or vector(0)"),
      q("sum(sensors_offline) or vector(0)"),
      q("max(sensor_last_heartbeat_age_seconds)"),
      q("sum(audit_logs_rows) or vector(0)"),
      q("sum(audit_unsealed_records) or vector(0)"),
      q("max(audit_checkpoints_latest_age_seconds)"),
      q("max(retention_last_prune_failed) or vector(0)"),
      q("max(retention_last_pruned_at_seconds_ago)"),
      q("sum(rate(sensor_violations_inserted_total[15m])) * 60 or vector(0)"),
    ])
      .then(([reqRate, errorPct, p95, sensors, offline, heartbeatAge, auditRows, unsealed,
        checkpointAge, pruneFailed, prunedAgo, violationsPerMin]) => {
        setSignals({ reqRate, errorPct, p95, sensors, offline, heartbeatAge, auditRows, unsealed,
          checkpointAge, pruneFailed, prunedAgo, violationsPerMin });
        setError(null);
        setUpdatedAt(new Date());
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoaded(true));
    getSystemHealth().then(setSystem).catch(() => setSystem(null));
  }, [isAdmin]);

  useEffect(() => {
    loadSignals();
    const id = window.setInterval(() => {
      loadSignals();
      setRefreshKey((k) => k + 1);
    }, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [loadSignals]);

  const checks = useMemo<HealthCheck[]>(() => {
    const s = signals;
    const out: HealthCheck[] = [];

    // API: share of server errors over the last 5 minutes
    const err = s.errorPct ?? 0;
    const apiState: CheckState = s.reqRate === null ? "unknown" : err >= 5 ? "critical" : err >= 1 ? "warn" : "ok";
    out.push({
      key: "api",
      title: t("mon.api", "API"),
      state: apiState,
      value: `${fmtPercent(s.reqRate ? err : 0)} ${t("mon.api_errors", "errors")} · ${fmtRate(s.reqRate)} ${t("mon.per_sec", "req/s")} · p95 ${fmtLatency(s.p95)}`,
      detail: t("mon.api_detail", "Server errors (5xx) among all requests in the last 5 minutes. Over 1 % needs a look, over 5 % is an outage."),
      action: <>{t("mon.api_action", "See which endpoint fails in the table below, then the API log:")} <code>provenza logs backend</code></>,
    });

    // Database and Redis, from the backend's own health check
    if (system) {
      const db = system.components.database;
      const redis = system.components.redis;
      out.push({
        key: "data",
        title: t("mon.data", "Database and queue"),
        state: db.ok && redis.ok ? "ok" : "critical",
        value: `PostgreSQL ${db.ok ? `${fmtNumber(db.latency_ms)} ms` : t("mon.down", "down")} · Redis ${redis.ok ? `${fmtNumber(redis.latency_ms)} ms` : t("mon.down", "down")}`,
        detail: t("mon.data_detail", "The API's round trip to PostgreSQL and Redis, measured now."),
        action: <><code>provenza status</code> · <code>provenza logs postgres</code> · <code>provenza logs redis</code></>,
      });
      const w = system.components.workers;
      const b = system.components.beat;
      const jobsState: CheckState = !w.ok ? "critical" : !b.ok ? "warn" : "ok";
      out.push({
        key: "jobs",
        title: t("mon.jobs", "Background jobs"),
        state: jobsState,
        value: `${w.count} ${t("mon.workers", "worker(s)")} · ${t("mon.beat", "scheduler")} ${b.last_heartbeat_age_seconds === null ? "—" : `${fmtAge(b.last_heartbeat_age_seconds)} ${t("mon.ago", "ago")}`}`,
        detail: t("mon.jobs_detail", "The worker sends notifications, seals the audit log and prunes old data; the scheduler starts those jobs on time."),
        action: <><code>provenza logs worker</code> · <code>provenza logs beat</code> · <code>provenza restart worker</code></>,
      });
    } else {
      out.push({
        key: "data", title: t("mon.data", "Database and queue"), state: "unknown", value: "—",
        detail: t("mon.data_unknown", "The backend's health check did not answer."),
      });
    }

    // Egress sensors
    const total = s.sensors ?? 0;
    const off = s.offline ?? 0;
    const sensorState: CheckState = s.sensors === null ? "unknown" : total === 0 ? "unknown"
      : off === 0 ? "ok" : off >= total ? "critical" : "warn";
    out.push({
      key: "sensors",
      title: t("mon.sensors", "Egress sensors"),
      state: sensorState,
      value: total === 0
        ? t("mon.sensors_none", "none registered")
        : `${total - off}/${total} ${t("mon.online", "online")} · ${t("mon.last_heartbeat", "oldest heartbeat")} ${fmtAge(s.heartbeatAge)} · ${fmtNumber(s.violationsPerMin, 1)} ${t("mon.violations_min", "violations/min")}`,
      detail: total === 0
        ? t("mon.sensors_none_detail", "No sensor reports to this installation yet. Register one on the Runtime page.")
        : t("mon.sensors_detail", "A sensor that sends no heartbeat for 5 minutes counts as offline; its host is no longer governed."),
      action: <>{t("mon.sensors_action", "On the sensor's host:")} <code>systemctl status provenzasensor</code></>,
    });

    // Audit evidence: every record under a signed checkpoint
    const unsealed = s.unsealed ?? 0;
    const auditState: CheckState = s.unsealed === null ? "unknown"
      : unsealed === 0 ? "ok" : unsealed > 1000 ? "critical" : "warn";
    out.push({
      key: "audit",
      title: t("mon.audit", "Audit evidence"),
      state: auditState,
      value: unsealed === 0
        ? `${fmtNumber(s.auditRows)} ${t("mon.audit_sealed", "records, all sealed")}`
        : `${fmtNumber(unsealed)} ${t("mon.audit_waiting", "records waiting for a checkpoint")}`,
      detail: `${t("mon.audit_detail", "Records are sealed under a signed checkpoint every 5 minutes; only sealed records can be proven.")} ${s.checkpointAge !== null ? `${t("mon.last_checkpoint", "Last checkpoint")}: ${fmtAge(s.checkpointAge)} ${t("mon.ago", "ago")}.` : ""}`,
      action: <>{t("mon.audit_action", "The worker or the scheduler is not sealing:")} <code>provenza logs worker</code></>,
    });

    // Data retention
    const retentionState: CheckState = s.pruneFailed === null && s.prunedAgo === null ? "unknown"
      : (s.pruneFailed ?? 0) >= 1 ? "critical" : (s.prunedAgo ?? 0) > 3 * 3600 ? "warn" : "ok";
    out.push({
      key: "retention",
      title: t("mon.retention", "Data retention"),
      state: retentionState,
      value: s.prunedAgo === null ? t("mon.retention_never", "not run yet") : `${t("mon.last_run", "last run")} ${fmtAge(s.prunedAgo)} ${t("mon.ago", "ago")}`,
      detail: t("mon.retention_detail", "Sensor activity and violations older than each organization's retention are deleted every hour. The audit log is never deleted."),
      action: <code>provenza logs worker</code>,
    });
    return out;
  }, [signals, system, t]);

  // Defence in depth: the nav item is adminOnly, the backend enforces
  // require_role(admin). This branch catches a direct URL visit by a
  // signed-in non-admin so the page renders a clear message rather than
  // a stream of 403s from the proxy.
  if (user && user.role !== "admin") {
    return (
      <>
        <PageHeader title={t("observability.title", "Observability")} />
        <div className="content">
          <div className="panel">
            <div className="panel-body">
              {t("observability.admin_only", "This page is available to administrators only.")}
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={t("observability.title", "Observability")}
        actions={
          <a href={GRAFANA_URL} target="_blank" rel="noopener noreferrer" className="btn btn-sm"
            title={t("observability.grafana_hint", "")}>
            {t("observability.open_grafana", "Open in Grafana")}
          </a>
        }
      />
      <div className="content">
        <div className="mon-toolbar">
          <div className="mon-range" role="group" aria-label={t("mon.range", "Time range")}>
            {MON_RANGES.map((r) => (
              <button key={r.key} type="button" aria-pressed={r.key === range.key} onClick={() => setRange(r)}>
                {t(`mon.range_${r.key}`, r.key)}
              </button>
            ))}
          </div>
          <span className="mon-updated">
            {updatedAt
              ? `${t("mon.updated", "Updated")} ${updatedAt.toLocaleTimeString()} · ${t("mon.every_30s", "refreshes every 30 s")}`
              : ""}
          </span>
        </div>

        {error && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "var(--risk-critical)" }}>
            <div className="panel-body" style={{ color: "var(--risk-critical)" }}>
              {t("mon.prometheus_error", "Prometheus did not answer, so the figures below may be missing:")} {error}
            </div>
          </div>
        )}

        <HealthPanel checks={checks} loading={!loaded} />

        <div className="mon-charts">
          <TrendChart
            title={t("mon.traffic", "API traffic")}
            subtitle={t("mon.traffic_sub", "Requests per second by outcome")}
            kind="stacked"
            range={range}
            refreshKey={refreshKey}
            format={fmtRate}
            headline="sum"
            headlineLabel={t("mon.per_sec", "req/s")}
            emptyText={t("mon.no_traffic", "No API requests in this range.")}
            onError={setError}
            series={[
              { key: "ok", label: t("mon.out_ok", "Success (2xx-3xx)"), color: colors.blue,
                query: 'sum(rate(http_requests_total{status=~"[23].."}[$w])) or vector(0)' },
              { key: "client", label: t("mon.out_client", "Client errors (4xx)"), color: colors.aqua,
                query: 'sum(rate(http_requests_total{status=~"4.."}[$w])) or vector(0)' },
              { key: "server", label: t("mon.out_server", "Server errors (5xx)"), color: colors.orange,
                query: 'sum(rate(http_requests_total{status=~"5.."}[$w])) or vector(0)' },
            ]}
          />
          <TrendChart
            title={t("mon.latency", "API response time")}
            subtitle={t("mon.latency_sub", "Half of the requests finish within p50, 95 % within p95, 99 % within p99")}
            kind="lines"
            range={range}
            refreshKey={refreshKey}
            format={fmtLatency}
            headline="p95"
            headlineLabel="p95"
            emptyText={t("mon.no_traffic", "No API requests in this range.")}
            onError={setError}
            series={[
              { key: "p50", label: "p50", color: colors.p50,
                query: "histogram_quantile(0.5, sum by (le) (rate(http_request_duration_seconds_bucket[$w])))" },
              { key: "p95", label: "p95", color: colors.p95,
                query: "histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[$w])))" },
              { key: "p99", label: "p99", color: colors.p99,
                query: "histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket[$w])))" },
            ]}
          />
          <TrendChart
            title={t("mon.sensor_events", "Egress sensor events")}
            subtitle={t("mon.sensor_events_sub", "Events per minute the sensors report: violations, and the sample of allowed connections")}
            kind="lines"
            range={range}
            refreshKey={refreshKey}
            format={(v) => fmtNumber(v, v < 10 ? 1 : 0)}
            headline="violations"
            headlineLabel={t("mon.violations_min", "violations/min")}
            emptyText={t("mon.no_sensor_events", "No sensor events in this range. With no violations this stays empty - that is good news.")}
            onError={setError}
            series={[
              { key: "violations", label: t("mon.ev_violations", "Violations"), color: colors.orange,
                query: "sum(rate(sensor_violations_inserted_total[$w])) * 60 or vector(0)" },
              { key: "activity", label: t("mon.ev_activity", "Allowed (sampled)"), color: colors.blue,
                query: "sum(rate(sensor_activity_inserted_total[$w])) * 60 or vector(0)" },
            ]}
          />
          <EndpointsTable range={range} refreshKey={refreshKey} onError={setError} />
        </div>

        <p className="hint-text" style={{ marginTop: 16 }}>
          {t(
            "observability.grafana_hint",
            "Grafana runs on the server only (127.0.0.1:3001). Open a tunnel from your computer first: ssh -L 3001:127.0.0.1:3001 user@your-server - then \"Open in Grafana\" works, with no login needed to view.",
          )}
        </p>
      </div>
    </>
  );
}
