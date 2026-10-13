"use client";

// Which AI providers the organization's prompts may reach: any, or only
// self-hosted ones on its own network (admins change it).

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { getProviderPolicy, setProviderPolicy, type ProviderPolicy, type ProviderPolicyView } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";

export function ProviderPolicyPanel({ refreshKey }: { refreshKey?: unknown }) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [view, setView] = useState<ProviderPolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { getProviderPolicy().then(setView).catch(() => setView(null)); }, [refreshKey]);

  async function change(next: ProviderPolicy) {
    if (next === "self_hosted" && !(await confirmDialog(t("provider_policy.confirm")))) return;
    setError(null);
    try {
      setView(await setProviderPolicy(next));
    } catch (e) {
      setError(errorMessage(e, t, t("provider_policy.failed")));
    }
  }

  if (!view) return null;
  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("provider_policy.title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("provider_policy.hint")}</p>
        <div className="u-row-tight">
          {(["any", "self_hosted"] as ProviderPolicy[]).map((p) => (
            <label key={p} className="u-flex u-items-center u-gap-6">
              <input type="radio" name="provider-policy" style={{ width: "auto" }} disabled={!isAdmin}
                checked={view.policy === p} onChange={() => change(p)} />
              {t(`provider_policy.${p}`)}
            </label>
          ))}
        </div>
        {view.policy === "self_hosted" && (
          <>
            <p className="hint-text">{t("provider_policy.self_hosted_note")}</p>
            {view.cloud_connections.length > 0 && (
              <p className="error-text">
                {t("provider_policy.cloud_refused")}: {view.cloud_connections.map((c) => c.name).join(", ")}
              </p>
            )}
          </>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
