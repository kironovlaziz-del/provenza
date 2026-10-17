"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { StatPanel } from "@/components/observability/StatPanel";
import { TimeSeriesPanel } from "@/components/observability/TimeSeriesPanel";
import { firstValue, queryInstant, type PromSample } from "@/lib/prometheus_api";
import { useAuth } from "@/lib/auth";

// This page is admin-only. Admins see the whole installation: the
// platform aggregates metrics across every organization, because in a
// self-hosted install there is typically exactly one. Approvers and
// users do not reach here — the nav item is adminOnly, the page has a
// defensive role check, and /api/v1/metrics/query{,_range} enforces
// require_role(UserRole.admin) on the backend.
//
// For deeper drill-downs and log correlation the operator opens Grafana.
const GRAFANA_URL =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname}:3001/d/ai-ct-backend/ai-control-tower-e28094-backend`
    : "http://localhost:3001";

interface KpiState {
  offline: number | null;
  heartbeatAge: number | null;
  errorRate: number | null;
  activityRows: number | null;
  violationRows: number | null;
  auditRows: number | null;
  checkpointAge: number | null;
  unsealedRecords: number | null;
}

export default function ObservabilityPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [kpi, setKpi] = useState<KpiState>({
    offline: null,
    heartbeatAge: null,
    errorRate: null,
    activityRows: null,
    violationRows: null,
    auditRows: null,
    checkpointAge: null,
    unsealedRecords: null,
  });
  const [error, setError] = useState<string | null>(null);

  const loadKpi = useCallback(() => {
    if (!user || user.role !== "admin") return;
    // Global queries — no org_id filter. The admin sees every sensor,
    // every audit row, every event across the installation.
    Promise.all([
      queryInstant("sensors_offline"),
      queryInstant("max(sensor_last_heartbeat_age_seconds)"),
      queryInstant('sum(rate(http_requests_total{status=~"5.."}[5m])) or vector(0)'),
      queryInstant("sum(sensor_activity_rows) or vector(0)"),
      queryInstant("sum(sensor_violations_rows) or vector(0)"),
      queryInstant("sum(audit_logs_rows) or vector(0)"),
      queryInstant("max(audit_checkpoints_latest_age_seconds)"),
      queryInstant("sum(audit_unsealed_records) or vector(0)"),
    ])
      .then(([off, hb, err, act, vio, aud, cpAge, unsealed]) => {
        const pick = (arr: PromSample[]) => firstValue(arr);
        setKpi({
          offline: pick(off),
          heartbeatAge: pick(hb),
          errorRate: pick(err),
          activityRows: pick(act),
          violationRows: pick(vio),
          auditRows: pick(aud),
          checkpointAge: pick(cpAge),
          unsealedRecords: pick(unsealed),
        });
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, [user]);

  useEffect(() => {
    loadKpi();
    const id = window.setInterval(loadKpi, 15000);
    return () => window.clearInterval(id);
  }, [loadKpi]);

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
              {t(
                "observability.admin_only",
                "This page is available to administrators only.",
              )}
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
          <a
            href={GRAFANA_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-sm"
          >
            {t("observability.open_grafana", "Open in Grafana")}
          </a>
        }
      />
      <div className="content">
        {error && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "var(--risk-critical)" }}>
            <div className="panel-body" style={{ color: "var(--risk-critical)" }}>{error}</div>
          </div>
        )}

        <div className="obs-grid">
          <StatPanel
            title={t("observability.kpi_offline", "Sensors offline")}
            value={kpi.offline}
            thresholds={[1, 2]}
            hint={t("observability.kpi_offline_hint", "No heartbeat for 5+ minutes")}
          />
          <StatPanel
            title={t("observability.kpi_heartbeat_age", "Heartbeat age")}
            value={kpi.heartbeatAge}
            unit="s"
            thresholds={[90, 300]}
            hint={t("observability.kpi_heartbeat_age_hint", "Oldest active sensor")}
          />
          <StatPanel
            title={t("observability.kpi_error_rate", "HTTP 5xx rate")}
            value={kpi.errorRate}
            unit="req/s"
            thresholds={[0.01, 1]}
            hint={t("observability.kpi_error_rate_hint", "5-minute window")}
          />
          <StatPanel
            title={t("observability.kpi_rows", "Activity / violations")}
            value={
              kpi.activityRows !== null && kpi.violationRows !== null
                ? kpi.activityRows + kpi.violationRows
                : null
            }
            hint={`${kpi.activityRows ?? "-"} / ${kpi.violationRows ?? "-"}`}
          />
          <StatPanel
            title={t("observability.kpi_audit", "Audit log")}
            value={kpi.auditRows}
            hint={t("observability.kpi_audit_hint", "Append-only, never deleted")}
          />
          <StatPanel
            title={t("observability.kpi_unsealed", "Unsealed audit records")}
            value={kpi.unsealedRecords}
            thresholds={[1, 100]}
            hint={t("observability.kpi_unsealed_hint", "Rows not yet in a signed checkpoint. 0 = everything provable.")}
          />
        </div>

        <div style={{ display: "grid", gap: 16, marginTop: 16 }}>
          <TimeSeriesPanel
            title={t("observability.chart_requests", "Requests rate by path")}
            query="sum by (path) (rate(http_requests_total[5m]))"
            unit="req/s"
            onError={setError}
          />
          <TimeSeriesPanel
            title={t("observability.chart_latency", "Latency p95 by path")}
            query="histogram_quantile(0.95, sum by (le, path) (rate(http_request_duration_seconds_bucket[5m])))"
            unit="seconds"
            onError={setError}
          />
          <TimeSeriesPanel
            title={t("observability.chart_ingestion", "Sensor event ingestion")}
            query="rate(sensor_activity_inserted_total[5m]) or rate(sensor_violations_inserted_total[5m])"
            unit="events/s"
            onError={setError}
          />
        </div>

        <p className="hint-text" style={{ marginTop: 16 }}>
          {t(
            "observability.grafana_hint",
            "For drill-downs, histogram breakouts and correlation with logs, open Grafana.",
          )}
        </p>
      </div>
    </>
  );
}
