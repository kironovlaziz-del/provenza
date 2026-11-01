"use client";

import React from "react";
import { useTranslation } from "react-i18next";

/** A page's data did not load: say so, and offer to try again - instead of an
 * empty list that looks like "nothing here" or a "Loading…" that never ends. */
export function LoadError({ message, onRetry }: { message: string | null; onRetry?: () => void }) {
  const { t } = useTranslation();
  if (!message) return null;
  return (
    <div className="panel" role="alert" style={{ marginBottom: 16, borderColor: "var(--risk-critical,#c1352f)" }}>
      <div className="panel-body" style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <span style={{ color: "var(--risk-critical,#c1352f)", flex: 1 }}>{message}</span>
        {onRetry && (
          <button className="btn btn-sm" onClick={onRetry}>{t("common.retry_load")}</button>
        )}
      </div>
    </div>
  );
}
