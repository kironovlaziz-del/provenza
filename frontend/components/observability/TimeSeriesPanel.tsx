"use client";

import React, { useEffect, useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { queryRange, seriesToChartRows, seriesLabels } from "@/lib/prometheus_api";

// Palette matches the dashboard charts so a series keeps its colour across
// the app. Not a theme, just enough distinct hues for typical cardinality.
const PALETTE = [
  "#3987e5", "#d95926", "#199e70", "#c98500",
  "#d55181", "#9085e9", "#e66767", "#69707d",
];

interface TimeSeriesPanelProps {
  title: string;
  query: string;
  /** Seconds of look-back; default 5 minutes. */
  windowSeconds?: number;
  /** Prometheus step; default 15s. */
  step?: string;
  unit?: string;
  /** Called when Prometheus is unavailable or the query errors. */
  onError?: (msg: string) => void;
}

export function TimeSeriesPanel({
  title,
  query,
  windowSeconds = 300,
  step = "15s",
  unit,
  onError,
}: TimeSeriesPanelProps) {
  const [rows, setRows] = useState<Array<Record<string, number>>>([]);
  const [labels, setLabels] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      const end = Math.floor(Date.now() / 1000);
      const start = end - windowSeconds;
      queryRange(query, start, end, step)
        .then((series) => {
          if (cancelled) return;
          setRows(seriesToChartRows(series));
          setLabels(seriesLabels(series));
          setLoading(false);
        })
        .catch((err) => {
          if (cancelled) return;
          setLoading(false);
          onError?.(String(err));
        });
    };
    load();
    const id = window.setInterval(load, 15_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [query, windowSeconds, step, onError]);

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
        {unit && <span className="hint-text">{unit}</span>}
      </div>
      <div className="panel-body" style={{ height: 240 }}>
        {loading ? (
          <div className="hint-text" style={{ padding: 40, textAlign: "center" }}>Loading…</div>
        ) : rows.length === 0 ? (
          <div className="hint-text" style={{ padding: 40, textAlign: "center" }}>No data in window</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={rows}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                dataKey="ts"
                tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString()}
                stroke="var(--text-muted)"
                fontSize={11}
              />
              <YAxis stroke="var(--text-muted)" fontSize={11} />
              <Tooltip
                contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)" }}
                labelFormatter={(t) => new Date((t as number) * 1000).toLocaleString()}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {labels.map((label, i) => (
                <Line
                  key={label}
                  type="monotone"
                  dataKey={label}
                  stroke={PALETTE[i % PALETTE.length]}
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
