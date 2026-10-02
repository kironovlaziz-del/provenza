"use client";

// Shown at the top of every page for admins and approvers when background
// work is broken (no Celery worker, beat silent, Redis rejecting the password).
// Polls once a minute; hidden while everything is fine.

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { getSystemHealth, type SystemHealth } from "@/lib/system_api";

const POLL_MS = 60000;

export function SystemHealthBanner() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const role = user?.role as string | undefined;
  const allowed = role === "admin" || role === "approver";
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [dismissed, setDismissed] = useState<string | null>(null);

  useEffect(() => {
    if (!allowed) return;
    let alive = true;
    const load = () => getSystemHealth().then((h) => alive && setHealth(h)).catch(() => undefined);
    load();
    const id = setInterval(load, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [allowed]);

  if (!allowed || !health || health.status === "ok") return null;
  const key = health.problems.map((p) => p.code).sort().join(",");
  if (dismissed === key) return null;
  const critical = health.status === "down";

  return (
    <div role="alert" style={{
      display: "flex", gap: 12, alignItems: "flex-start", padding: "10px 16px",
      background: critical ? "var(--risk-critical-bg)" : "var(--risk-medium-bg)",
      borderBottom: `1px solid ${critical ? "var(--risk-critical)" : "var(--risk-medium)"}`,
      color: "var(--text-primary)", fontSize: 13,
    }}>
      <span style={{ fontWeight: 700, color: critical ? "var(--risk-critical)" : "var(--risk-medium)", whiteSpace: "nowrap" }}>
        {critical ? t("health.banner_down", "Background processing is down") : t("health.banner_degraded", "Background processing needs attention")}
      </span>
      <span style={{ flex: 1 }}>
        {health.problems.map((p) => t(`health.problem.${p.code}`, p.message)).join(" · ")}
      </span>
      <Link href="/system-status" style={{ whiteSpace: "nowrap" }}>{t("health.details", "Details")} →</Link>
      <button onClick={() => setDismissed(key)} aria-label={t("health.dismiss", "Dismiss")}
        style={{ background: "none", border: "none", color: "inherit", cursor: "pointer", fontSize: 16, lineHeight: 1 }}>×</button>
    </div>
  );
}
