"use client";

import React, { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { queryRange } from "@/lib/prometheus_api";
import { fmtClock } from "./format";

/** A time range of the monitoring page: look-back, query step and the
 *  rate() window - wider ranges use coarser steps and smoother rates. */
export interface MonRange {
  key: string;
  seconds: number;
  step: string;
  rateWindow: string;
}

export const MON_RANGES: MonRange[] = [
  { key: "15m", seconds: 15 * 60, step: "15s", rateWindow: "2m" },
  { key: "1h", seconds: 3600, step: "30s", rateWindow: "5m" },
  { key: "6h", seconds: 6 * 3600, step: "3m", rateWindow: "10m" },
  { key: "24h", seconds: 24 * 3600, step: "10m", rateWindow: "30m" },
];

export interface TrendSeries {
  key: string;
  label: string;
  color: string;
  /** PromQL returning one series (sum or quantile); "$w" becomes the rate window. */
  query: string;
}

interface Props {
  title: string;
  subtitle: string;
  series: TrendSeries[];
  range: MonRange;
  /** Formats a value for the axis, the tooltip, the legend and the headline. */
  format: (v: number) => string;
  /** Stacked areas (parts of a whole) or lines (independent measures). */
  kind: "stacked" | "lines";
  /** The headline: the latest value of this series key, or the sum of all. */
  headline?: string | "sum";
  headlineLabel?: string;
  emptyText: string;
  refreshKey: number;
  onError?: (msg: string) => void;
}

type Row = { ts: number } & Record<string, number>;

interface TooltipEntry {
  dataKey?: unknown;
  value?: unknown;
}

function ChartTooltip(props: {
  active?: boolean;
  payload?: ReadonlyArray<TooltipEntry>;
  label?: unknown;
  series: TrendSeries[];
  format: (v: number) => string;
}) {
  const { active, payload, label, series, format } = props;
  if (!active || !payload || payload.length === 0) return null;
  const byKey = new Map<string, number>();
  for (const p of payload) {
    if (typeof p.dataKey === "string" && typeof p.value === "number") byKey.set(p.dataKey, p.value);
  }
  return (
    <div className="mon-tooltip">
      <div className="mon-tooltip-time">{typeof label === "number" ? fmtClock(label, true) : ""}</div>
      {/* listed in legend order, not stack order */}
      {series.map((s) => (
        <div className="mon-tooltip-row" key={s.key}>
          <i style={{ background: s.color }} />
          {s.label}
          <b>{byKey.has(s.key) ? format(byKey.get(s.key) as number) : "—"}</b>
        </div>
      ))}
    </div>
  );
}

export function TrendChart({
  title, subtitle, series, range, format, kind, headline, headlineLabel, emptyText, refreshKey, onError,
}: Props) {
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const queries = series.map((s) => s.query.split("$w").join(range.rateWindow)).join("\n");

  useEffect(() => {
    let cancelled = false;
    const end = Math.floor(Date.now() / 1000);
    const start = end - range.seconds;
    Promise.all(series.map((s) => queryRange(s.query.split("$w").join(range.rateWindow), start, end, range.step)))
      .then((results) => {
        if (cancelled) return;
        const byTs = new Map<number, Row>();
        results.forEach((res, i) => {
          const key = series[i].key;
          for (const r of res) {
            for (const [ts, raw] of r.values) {
              const n = Number(raw);
              if (!Number.isFinite(n)) continue;
              const row = byTs.get(ts) ?? ({ ts } as Row);
              row[key] = (row[key] ?? 0) + n;
              byTs.set(ts, row);
            }
          }
        });
        setRows(Array.from(byTs.values()).sort((a, b) => a.ts - b.ts));
        setLoading(false);
      })
      .catch((e) => {
        if (cancelled) return;
        setLoading(false);
        onError?.(String(e));
      });
    return () => {
      cancelled = true;
    };
    // queries captures the series and the window; refreshKey re-polls
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queries, range.seconds, range.step, refreshKey]);

  const last = rows.length ? rows[rows.length - 1] : null;
  const latest = (key: string) => (last && typeof last[key] === "number" ? (last[key] as number) : null);
  let headValue: number | null = null;
  if (headline === "sum") {
    headValue = last ? series.reduce((acc, s) => acc + (latest(s.key) ?? 0), 0) : null;
  } else if (headline) {
    headValue = latest(headline);
  }
  const hasData = rows.some((r) => series.some((s) => (r[s.key] ?? 0) > 0));
  const withDate = range.seconds > 6 * 3600;

  const axisProps = {
    stroke: "var(--text-muted)",
    fontSize: 11,
    tickLine: false,
    axisLine: false,
  } as const;

  const tooltip = (
    <Tooltip
      cursor={{ stroke: "var(--border-strong)", strokeWidth: 1 }}
      content={(p: { active?: boolean; payload?: ReadonlyArray<TooltipEntry>; label?: unknown }) => (
        <ChartTooltip {...p} series={series} format={format} />
      )}
    />
  );

  const xAxis = (
    <XAxis
      dataKey="ts"
      type="number"
      scale="time"
      domain={["dataMin", "dataMax"]}
      tickFormatter={(t: number) => fmtClock(t, withDate)}
      minTickGap={48}
      {...axisProps}
    />
  );
  const yAxis = <YAxis tickFormatter={(v: number) => format(v)} width={64} {...axisProps} />;

  return (
    <div className="panel">
      <div className="panel-body">
        <div className="mon-chart-head">
          <div>
            <h2 className="panel-title" style={{ fontSize: 14, fontWeight: 600 }}>{title}</h2>
            <div className="mon-chart-sub">{subtitle}</div>
          </div>
          {headline && (
            <div className="mon-chart-now" title={headlineLabel}>
              {headValue === null ? "—" : format(headValue)}
              {headlineLabel && <small>{headlineLabel}</small>}
            </div>
          )}
        </div>

        <div style={{ height: 220, marginTop: 12 }}>
          {loading ? (
            <div className="mon-empty">…</div>
          ) : !hasData ? (
            <div className="mon-empty">{emptyText}</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              {kind === "stacked" ? (
                <AreaChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--viz-grid)" />
                  {xAxis}
                  {yAxis}
                  {tooltip}
                  {series.map((s) => (
                    <Area
                      key={s.key}
                      dataKey={s.key}
                      name={s.label}
                      stackId="a"
                      type="linear"
                      stroke={s.color}
                      strokeWidth={1.5}
                      fill={s.color}
                      fillOpacity={0.35}
                      isAnimationActive={false}
                    />
                  ))}
                </AreaChart>
              ) : (
                <LineChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--viz-grid)" />
                  {xAxis}
                  {yAxis}
                  {tooltip}
                  {series.map((s) => (
                    <Line
                      key={s.key}
                      dataKey={s.key}
                      name={s.label}
                      type="linear"
                      stroke={s.color}
                      strokeWidth={2}
                      dot={false}
                      activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--bg-panel)" }}
                      isAnimationActive={false}
                    />
                  ))}
                </LineChart>
              )}
            </ResponsiveContainer>
          )}
        </div>

        {series.length > 1 && (
          <div className="mon-legend">
            {series.map((s) => (
              <span key={s.key}>
                <i style={{ background: s.color }} />
                {s.label}
                <b>{latest(s.key) === null ? "—" : format(latest(s.key) as number)}</b>
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
