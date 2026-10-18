"use client";

import React from "react";
import { useTranslation } from "react-i18next";

export type CheckState = "ok" | "warn" | "critical" | "unknown";

export interface HealthCheck {
  key: string;
  title: string;
  state: CheckState;
  /** The current measurement, short: "0.2 % errors · 3 req/s". */
  value: string;
  /** What is measured and what the state means. */
  detail: string;
  /** What to do, shown only when the check is not ok. */
  action?: React.ReactNode;
}

const RANK: Record<CheckState, number> = { ok: 0, unknown: 1, warn: 2, critical: 3 };

/** The state icon: a shape per state, so it never rests on color alone. */
export function StateIcon({ state }: { state: CheckState }) {
  const common = { className: `mon-icon mon-${state}`, viewBox: "0 0 20 20", "aria-hidden": true } as const;
  if (state === "ok")
    return (
      <svg {...common}><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="2" />
        <path d="M6 10.5l2.6 2.6L14 7.6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
    );
  if (state === "warn")
    return (
      <svg {...common}><path d="M10 2.5l8 14H2z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M10 8v4M10 14.6v.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
    );
  if (state === "critical")
    return (
      <svg {...common}><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="2" />
        <path d="M7 7l6 6M13 7l-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
    );
  return (
    <svg {...common}><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="3 3" />
      <path d="M7 10h6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
  );
}

export function HealthPanel({ checks, loading }: { checks: HealthCheck[]; loading: boolean }) {
  const { t } = useTranslation();
  const worst = checks.reduce<CheckState>((w, c) => (RANK[c.state] > RANK[w] ? c.state : w), "ok");
  const bad = checks.filter((c) => c.state === "warn" || c.state === "critical");

  let verdict: string;
  let sub: string;
  if (loading) {
    verdict = t("mon.verdict_loading", "Checking the installation…");
    sub = "";
  } else if (worst === "critical") {
    verdict = t("mon.verdict_critical", "Something is broken");
    sub = bad.map((c) => c.title).join(" · ");
  } else if (worst === "warn") {
    verdict = t("mon.verdict_warn", "Needs attention");
    sub = bad.map((c) => c.title).join(" · ");
  } else if (worst === "unknown") {
    verdict = t("mon.verdict_unknown", "Running, with gaps in the data");
    sub = t("mon.verdict_unknown_sub", "Some checks have nothing to measure yet - see below.");
  } else {
    verdict = t("mon.verdict_ok", "All systems operational");
    sub = t("mon.verdict_ok_sub", "Every check below is within its limits.");
  }

  // the problems first, then the rest in their usual order
  const ordered = [...checks].sort((a, b) => RANK[b.state] - RANK[a.state]);

  return (
    <div className="panel" style={{ overflow: "hidden" }}>
      <div className="mon-health-head" role="status">
        <StateIcon state={loading ? "unknown" : worst} />
        <div>
          <div className="mon-verdict">{verdict}</div>
          {sub && <div className="mon-verdict-sub">{sub}</div>}
        </div>
      </div>
      <div className="mon-checks">
        {ordered.map((c) => (
          <div className="mon-check" key={c.key}>
            <StateIcon state={c.state} />
            <div className="mon-check-title">
              {c.title}
              <span className={`mon-state mon-${c.state}`}>{t(`mon.state_${c.state}`, c.state)}</span>
            </div>
            <div className="mon-check-value">{c.value}</div>
            <div className="mon-check-detail">{c.detail}</div>
            {c.action && c.state !== "ok" && <div className="mon-check-action">{c.action}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
