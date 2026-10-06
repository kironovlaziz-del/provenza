"use client";

import Link from "next/link";
import React, { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";

// A regular policy version's rules_json understands:
//   effect: "require_approval" -> every request under this policy needs sign-off
// Blocked terms of a policy are kept on the Blocked terms page (scope "policy"),
// PII rules on the PII rules page.

export function PolicyRuleBuilder({
  value,
  onChange,
}: {
  value: Record<string, unknown>;
  onChange: (rules: Record<string, unknown>) => void;
}) {
  const { t } = useTranslation();

  const [requireApproval, setRequireApproval] = useState<boolean>(
    () => value?.effect === "require_approval"
  );

  useEffect(() => {
    const rules: Record<string, unknown> = {};
    if (requireApproval) rules.effect = "require_approval";
    onChange(rules);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requireApproval]);

  return (
    <div>
      <div style={{ border: "1px solid var(--border,#e5e7eb)", borderRadius: 8, padding: 12, marginBottom: 12 }}>
        <strong style={{ fontSize: 14 }}>🚫 {t("rulebuilder.pol_blocked_title")}</strong>
        <p className="hint-text" style={{ fontSize: 12, margin: "4px 0 0" }}>
          {t("rulebuilder.pol_blocked_moved")} <Link href="/blocked-terms">{t("sidebar.nav.blocked_terms")}</Link>
        </p>
      </div>

      <div style={{ border: "1px solid var(--border,#e5e7eb)", borderRadius: 8, padding: 12 }}>
        <label style={{ display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={requireApproval}
            onChange={(e) => setRequireApproval(e.target.checked)}
            style={{ marginTop: 3 }}
          />
          <span>
            <strong style={{ fontSize: 14 }}>⏸️ {t("rulebuilder.pol_approval_title")}</strong>
            <p className="hint-text" style={{ fontSize: 12, margin: "4px 0 0" }}>{t("rulebuilder.pol_approval_hint")}</p>
          </span>
        </label>
      </div>
    </div>
  );
}
