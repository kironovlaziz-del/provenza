"use client";

import React from "react";
import { useTranslation } from "react-i18next";

const TIER_CLASS: Record<string, string> = {
  unacceptable: "pill-critical",
  high: "pill-high",
  limited: "pill-medium",
  minimal: "pill-low",
};

const STAGE_CLASS: Record<string, string> = {
  idea: "pill-neutral",
  development: "pill-neutral",
  validation: "pill-medium",
  production: "pill-low",
  retired: "pill-neutral",
};

/** Risk tier. A tier that no human has confirmed yet is drawn dashed with a "?". */
export function TierPill({ tier, confirmed }: { tier?: string | null; confirmed?: boolean }) {
  const { t } = useTranslation();
  if (!tier) return <span className="pill pill-neutral">—</span>;
  return (
    <span
      className={`pill ${TIER_CLASS[tier] ?? "pill-neutral"}`}
      style={confirmed ? undefined : { border: "1px dashed currentColor", opacity: 0.85 }}
      title={
        confirmed
          ? t("inventory.tier_confirmed", "Confirmed by a human")
          : t("inventory.tier_suggested", "Suggested by the classifier — not confirmed yet")
      }
    >
      {t(`inventory.tiers.${tier}`, tier)}
      {confirmed ? "" : " ?"}
    </span>
  );
}

export function StagePill({ stage }: { stage: string }) {
  const { t } = useTranslation();
  return <span className={`pill ${STAGE_CLASS[stage] ?? "pill-neutral"}`}>{t(`inventory.stages.${stage}`, stage)}</span>;
}

const SEVERE = new Set(["in_production_without_confirmed_risk", "unacceptable_in_production"]);

/** Governance gaps for a system. compact = icons with tooltips (for tables). */
export function AttentionList({ items, compact }: { items: string[]; compact?: boolean }) {
  const { t } = useTranslation();
  if (!items || items.length === 0) {
    return compact ? <span className="hint-text">—</span> : null;
  }
  if (compact) {
    return (
      <span style={{ display: "inline-flex", gap: 6 }}>
        {items.map((key) => (
          <span
            key={key}
            title={t(`inventory.attention.${key}`, key)}
            style={{ color: SEVERE.has(key) ? "#ef4444" : "#f59e0b", fontWeight: 700 }}
          >
            {SEVERE.has(key) ? "⚠" : "●"}
          </span>
        ))}
      </span>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {items.map((key) => (
        <div
          key={key}
          style={{
            padding: "8px 12px",
            borderRadius: 6,
            fontSize: 13,
            background: SEVERE.has(key) ? "rgba(239,68,68,0.12)" : "rgba(245,158,11,0.12)",
            color: SEVERE.has(key) ? "#ef4444" : "#d97706",
          }}
        >
          {SEVERE.has(key) ? "⚠ " : "● "}
          {t(`inventory.attention.${key}`, key)}
        </div>
      ))}
    </div>
  );
}
