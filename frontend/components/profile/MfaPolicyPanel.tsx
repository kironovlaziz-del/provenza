"use client";

// Who in the organization must sign in with a second factor (admins only).

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { getMfaPolicy, MfaPolicy, setMfaPolicy } from "@/lib/api";
import { errorMessage } from "@/lib/errors";

export function MfaPolicyPanel() {
  const { t } = useTranslation();
  const [policy, setPolicy] = useState<MfaPolicy | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { getMfaPolicy().then((p) => setPolicy(p.mfa_required)).catch(() => setPolicy(null)); }, []);

  async function change(next: MfaPolicy) {
    if (next !== "none" && !(await confirmDialog(t("mfa.policy_confirm")))) return;
    setError(null);
    try {
      setPolicy((await setMfaPolicy(next)).mfa_required);
    } catch (e) {
      setError(errorMessage(e, t, t("mfa.failed")));
    }
  }

  if (!policy) return null;
  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("mfa.policy_title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("mfa.policy_hint")}</p>
        <div className="u-row-tight">
          {(["none", "reviewers", "all"] as MfaPolicy[]).map((p) => (
            <label key={p} className="u-flex u-items-center u-gap-6">
              <input type="radio" name="mfa-policy" style={{ width: "auto" }} checked={policy === p} onChange={() => change(p)} />
              {t(`mfa.policy_${p}`)}
            </label>
          ))}
        </div>
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
