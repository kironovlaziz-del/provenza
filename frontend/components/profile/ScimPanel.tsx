"use client";

// SCIM 2.0 provisioning (admins): the identity provider (Okta, Entra ID, ...)
// creates and switches off users. A user switched off there is offboarded
// here at once: sessions end, their agents' keys are revoked.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { api } from "@/lib/api";
import { errorMessage } from "@/lib/errors";

interface ScimSettings {
  enabled: boolean;
  has_token: boolean;
  token_prefix: string | null;
  default_role: "user" | "approver";
  base_url: string;
  last_used_at: string | null;
}

export function ScimPanel() {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<ScimSettings | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => { api.get<ScimSettings>("/scim/settings").then((r) => setSt(r.data)).catch(() => setSt(null)); }, []);

  async function run(fn: () => Promise<{ data: ScimSettings & { token?: string } }>) {
    setError(null);
    try {
      const { data } = await fn();
      setSt(data);
      if (data.token) setToken(data.token);
    } catch (e) {
      setError(errorMessage(e, t, t("scim.failed")));
    }
  }

  async function copy(what: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(what);
    } catch {
      /* visible anyway */
    }
  }

  if (!st) return null;
  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("scim.title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("scim.hint")}</p>
        <div className="field">
          <label>{t("scim.base_url")}</label>
          <div className="u-btn-row">
            <code className="mono" style={{ wordBreak: "break-all" }}>{st.base_url}</code>
            <button className="btn btn-sm" onClick={() => copy("url", st.base_url)}>{copied === "url" ? t("agents.copied") : t("agents.copy")}</button>
          </div>
        </div>
        {token && (
          <div className="field">
            <label>{t("scim.token")}</label>
            <div className="u-btn-row">
              <code className="mono" style={{ wordBreak: "break-all" }}>{token}</code>
              <button className="btn btn-sm" onClick={() => copy("token", token)}>{copied === "token" ? t("agents.copied") : t("agents.copy")}</button>
            </div>
            <p className="error-text">{t("scim.token_once")}</p>
          </div>
        )}
        <p className="ag-small">
          <span className={`pill ${st.enabled ? "pill-low" : "pill-neutral"}`}>{st.enabled ? t("scim.on") : t("scim.off")}</span>
          {st.token_prefix && <span className="hint-text"> · <code className="mono">{st.token_prefix}…</code></span>}
          {st.last_used_at && <span className="hint-text"> · {t("scim.last_used")} {new Date(st.last_used_at).toLocaleString(i18n.language)}</span>}
        </p>
        <div className="u-row-tight u-mb-12">
          <label htmlFor="scim-role">{t("scim.default_role")}</label>
          <select id="scim-role" style={{ width: "auto" }} value={st.default_role}
            onChange={(e) => run(() => api.put("/scim/settings", { default_role: e.target.value }))}>
            <option value="user">{t("users.roles.user")}</option>
            <option value="approver">{t("users.roles.approver")}</option>
          </select>
        </div>
        <div className="u-btn-row">
          <button className="btn btn-sm btn-primary" onClick={async () => {
            if (st.has_token && !await confirmDialog(t("scim.confirm_new"))) return;
            run(() => api.post("/scim/token"));
          }}>{st.has_token ? t("scim.new_token") : t("scim.enable")}</button>
          {st.has_token && (
            <button className="btn btn-sm btn-danger" onClick={async () => {
              if (!await confirmDialog(t("scim.confirm_revoke"))) return;
              setToken(null);
              run(() => api.delete("/scim/token"));
            }}>{t("scim.revoke")}</button>
          )}
        </div>
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
