"use client";

// What hides in a tool definition, shown before anyone approves it
// (lib/hidden_text.ts, docs/hidden-text.md): each finding with where it is
// and, for tag characters and variation selectors, the text they spell; and
// the whole definition with every invisible character made visible.

import React from "react";
import { useTranslation } from "react-i18next";
import { reveal, type HiddenFinding, type HiddenLevel } from "@/lib/hidden_text";

export function HiddenPill({ level }: { level: HiddenLevel }) {
  const { t } = useTranslation();
  if (level === "clean") return null;
  return (
    <span className={`pill ${level === "refuse" ? "pill-critical" : "pill-high"}`} title={t(`hidden.level_${level}_hint`)}>
      {t(`hidden.level_${level}`)}
    </span>
  );
}

export function HiddenFindings({ findings, level }: { findings: HiddenFinding[]; level: HiddenLevel }) {
  const { t } = useTranslation();
  if (level === "clean") return null;
  return (
    <div className="u-mt-8" style={{ borderLeft: `3px solid var(--risk-${level === "refuse" ? "critical" : "high"})`, paddingLeft: 10 }}>
      <p style={{ margin: "0 0 6px" }}><strong>{t(`hidden.level_${level}_hint`)}</strong></p>
      <ul className="hint-text" style={{ margin: 0, paddingLeft: 18 }}>
        {findings.map((f, i) => (
          <li key={i}>
            {t(`hidden.kind_${f.kind}`)} · <span className="u-mono">{f.path}</span> · {f.count}
            {f.codepoints.length > 0 && <span className="u-mono"> ({f.codepoints.join(" ")})</span>}
            {f.hidden && (
              <div className="u-mono" style={{ color: "var(--risk-critical)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                {t("hidden.spells")}: {f.hidden}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The definition as the agent's model reads it, invisible characters made visible. */
export function RevealedDefinition({ value }: { value: unknown }) {
  return (
    <pre className="u-mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: 12, maxHeight: 320,
                                      overflow: "auto", margin: "8px 0 0" }}>
      {reveal(JSON.stringify(value, null, 2))}
    </pre>
  );
}
