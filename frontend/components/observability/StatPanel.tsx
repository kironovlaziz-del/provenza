"use client";

import React from "react";

interface StatPanelProps {
  title: string;
  value: number | null;
  unit?: string;
  /** Thresholds in ascending order: [yellow, red]. */
  thresholds?: [number, number];
  hint?: string;
}

/** A single KPI card. Colour follows value vs. thresholds; a null value
 *  (Prometheus down, no data) renders a dash instead of 0 — 0 and "unknown"
 *  look the same on a green background and that is a lie. */
export function StatPanel({ title, value, unit, thresholds, hint }: StatPanelProps) {
  let cls = "";
  if (value !== null && thresholds) {
    if (value >= thresholds[1]) cls = "critical";
    else if (value >= thresholds[0]) cls = "warn";
  }
  const display = value === null ? "—" : value.toLocaleString(undefined, { maximumFractionDigits: 2 });
  return (
    <div className={`panel obs-stat ${cls}`}>
      <div className="panel-body">
        <div className="obs-stat-title">{title}</div>
        <div className="obs-stat-value">
          {display}
          {unit && value !== null && <span className="obs-stat-unit"> {unit}</span>}
        </div>
        {hint && <div className="obs-stat-hint">{hint}</div>}
      </div>
    </div>
  );
}
