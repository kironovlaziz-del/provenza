"use client";

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { queryInstant } from "@/lib/prometheus_api";
import { fmtLatency, fmtPercent, fmtRate } from "./format";
import type { MonRange } from "./TrendChart";

interface EndpointRow {
  path: string;
  rate: number;
  errorPct: number;
  p95: number | null;
}

const LIMIT = 8;

/** Routes that are slow by design, with why: shown under the path, so a high
 *  p95 there does not read as a problem. */
const SLOW_BY_DESIGN: Record<string, [string, string]> = {
  "/api/v1/system/health": ["mon.ep_health_note", "Waits 1.5 s for the workers to answer a ping - by design, not counted in the response time above"],
};

/** The busiest API endpoints in the selected range: traffic, server errors
 *  and p95 latency side by side - a table, because these are three measures
 *  of different scale for the same few routes. */
export function EndpointsTable({ range, refreshKey, onError }: {
  range: MonRange;
  refreshKey: number;
  onError?: (msg: string) => void;
}) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<EndpointRow[] | null>(null);
  // the whole selected range, not the short rate window: "busiest over 6 h"
  const w = `${Math.round(range.seconds / 60)}m`;

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      queryInstant(`sum by (path) (rate(http_requests_total[${w}]))`),
      queryInstant(`sum by (path) (rate(http_requests_total{status=~"5.."}[${w}]))`),
      queryInstant(`histogram_quantile(0.95, sum by (le, path) (rate(http_request_duration_seconds_bucket[${w}])))`),
    ])
      .then(([rates, errors, p95s]) => {
        if (cancelled) return;
        const num = (v: string | undefined) => {
          const n = Number(v);
          return Number.isFinite(n) ? n : null;
        };
        const err = new Map<string, number>(errors.map((s): [string, number] => [s.metric.path ?? "", num(s.value?.[1]) ?? 0]));
        const lat = new Map<string, number | null>(p95s.map((s): [string, number | null] => [s.metric.path ?? "", num(s.value?.[1])]));
        const out = rates
          .map((s) => {
            const path = s.metric.path ?? "";
            const rate = num(s.value?.[1]) ?? 0;
            const e = err.get(path) ?? 0;
            return { path, rate, errorPct: rate > 0 ? (e / rate) * 100 : 0, p95: lat.get(path) ?? null };
          })
          .filter((r) => r.rate > 0)
          .sort((a, b) => b.rate - a.rate)
          .slice(0, LIMIT);
        setRows(out);
      })
      .catch((e) => {
        if (!cancelled) onError?.(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [w, refreshKey, onError]);

  const max = rows && rows.length ? rows[0].rate : 0;
  const label = (p: string) => (p === "__unmatched__" ? t("mon.ep_unmatched", "(no matching route)") : p);

  return (
    <div className="panel">
      <div className="panel-body">
        <div className="mon-chart-head">
          <div>
            <h2 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>{t("mon.ep_title", "Busiest API endpoints")}</h2>
            <div className="mon-chart-sub">
              {t("mon.ep_sub", "Over the selected range: requests per second, share of server errors (5xx), and the time 95 % of requests finish within.")}
            </div>
          </div>
        </div>
        {rows === null ? (
          <div className="mon-empty" style={{ height: 120 }}>…</div>
        ) : rows.length === 0 ? (
          <div className="mon-empty" style={{ height: 120 }}>{t("mon.ep_empty", "No API traffic in this range.")}</div>
        ) : (
          <table className="mon-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>{t("mon.ep_path", "Endpoint")}</th>
                <th className="num">{t("mon.ep_rate", "Req/s")}</th>
                <th className="num">{t("mon.ep_errors", "5xx")}</th>
                <th className="num">{t("mon.ep_p95", "p95")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.path}>
                  <td>
                    <code>{label(r.path)}</code>
                    {SLOW_BY_DESIGN[r.path] && (
                      <div className="mon-chart-sub">{t(SLOW_BY_DESIGN[r.path][0], SLOW_BY_DESIGN[r.path][1])}</div>
                    )}
                    <div className="mon-bar" style={{ width: `${max > 0 ? Math.max(2, (r.rate / max) * 100) : 0}%` }} />
                  </td>
                  <td className="num">{fmtRate(r.rate)}</td>
                  <td className={`num${r.errorPct >= 5 ? " mon-critical" : r.errorPct >= 1 ? " mon-warn" : ""}`}>
                    {fmtPercent(r.errorPct)}
                  </td>
                  <td className="num">{fmtLatency(r.p95)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
