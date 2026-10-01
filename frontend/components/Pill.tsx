"use client";

import React from "react";
import { useTranslation } from "react-i18next";

const RISK_CLASS: Record<string, string> = {
  low: "pill-low",
  medium: "pill-medium",
  high: "pill-high",
  critical: "pill-critical",
};

const STATUS_CLASS: Record<string, string> = {
  active: "pill-low",
  approved: "pill-low",
  completed: "pill-low",
  resolved: "pill-low",
  registered: "pill-low",
  allowed: "pill-low",
  open: "pill-medium",
  pending: "pill-neutral",
  pending_approval: "pill-medium",
  draft: "pill-neutral",
  investigating: "pill-medium",
  reviewing: "pill-medium",
  new: "pill-medium",
  rejected: "pill-critical",
  blocked: "pill-critical",
  stopped: "pill-critical",
  confirmed_shadow: "pill-critical",
  rolled_back: "pill-medium",
  inactive: "pill-neutral",
  dismissed: "pill-neutral",
  suspended: "pill-critical",
  quarantined: "pill-critical",
  queued: "pill-neutral",
  running: "pill-medium",
  failed: "pill-critical",
  expired: "pill-neutral",
  processing: "pill-medium",
  cancelled: "pill-neutral",
};

export function RiskPill({ level }: { level: string }) {
  const { t } = useTranslation();
  return (
    <span className={`pill ${RISK_CLASS[level] ?? "pill-neutral"}`}>
      {t(`risk.${level}`, level)}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <span className={`pill ${STATUS_CLASS[status] ?? "pill-neutral"}`}>
      {t(`status.${status}`, status)}
    </span>
  );
}
