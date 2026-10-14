"use client";

// Single sign-on with OpenID Connect (admins): the provider, the client
// registered there, and the rules - allowed domains, accounts created on first
// sign-in, SSO only (passwords left to admins), the provider's second factor.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { api } from "@/lib/api";
import { errorMessage } from "@/lib/errors";

interface SsoSettings {
  redirect_uri: string;
  enabled: boolean;
  issuer: string | null;
  client_id: string | null;
  has_secret: boolean;
  email_claim: string;
  allowed_domains: string[];
  jit: boolean;
  default_role: "user" | "approver";
  enforce: boolean;
  require_idp_mfa: boolean;
}

export function SsoPanel() {
  const { t } = useTranslation();
  const [st, setSt] = useState<SsoSettings | null>(null);
  const [form, setForm] = useState({ issuer: "", client_id: "", client_secret: "", domains: "", email_claim: "email",
                                     jit: false, default_role: "user", enforce: false, require_idp_mfa: false });
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = () => api.get<SsoSettings>("/sso/settings").then((r) => {
    setSt(r.data);
    setForm({ issuer: r.data.issuer ?? "", client_id: r.data.client_id ?? "", client_secret: "",
              domains: r.data.allowed_domains.join(", "), email_claim: r.data.email_claim, jit: r.data.jit,
              default_role: r.data.default_role, enforce: r.data.enforce, require_idp_mfa: r.data.require_idp_mfa });
  }).catch(() => setSt(null));
  useEffect(() => { load(); }, []);

  async function save(enabled: boolean) {
    if (enabled && form.enforce && !st?.enforce && !(await confirmDialog(t("sso.confirm_enforce")))) return;
    setBusy(true);
    setError(null);
    try {
      await api.put("/sso/settings", {
        enabled, issuer: form.issuer.trim(), client_id: form.client_id.trim(),
        client_secret: form.client_secret || undefined, email_claim: form.email_claim.trim() || "email",
        allowed_domains: form.domains.split(/[,\s]+/).filter(Boolean), jit: form.jit, default_role: form.default_role,
        enforce: form.enforce, require_idp_mfa: form.require_idp_mfa,
      });
      setEditing(false);
      await load();
    } catch (e) {
      setError(errorMessage(e, t, t("sso.failed")));
    } finally {
      setBusy(false);
    }
  }

  if (!st) return null;
  const check = (key: "jit" | "enforce" | "require_idp_mfa", label: string, hint: string) => (
    <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
      <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={form[key]}
        onChange={(e) => setForm({ ...form, [key]: e.target.checked })} />
      <span>{label}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{hint}</span></span>
    </label>
  );

  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("sso.title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">{t("sso.hint")}</p>
        <div className="field">
          <label>{t("sso.redirect_uri")}</label>
          <div className="u-btn-row">
            <code className="mono" style={{ wordBreak: "break-all" }}>{st.redirect_uri}</code>
            <button className="btn btn-sm" onClick={async () => {
              try { await navigator.clipboard.writeText(st.redirect_uri); setCopied(true); } catch { /* visible anyway */ }
            }}>{copied ? t("agents.copied") : t("agents.copy")}</button>
          </div>
        </div>
        <p className="ag-small">
          <span className={`pill ${st.enabled ? "pill-low" : "pill-neutral"}`}>{st.enabled ? t("sso.on") : t("sso.off")}</span>
          {st.enabled && <span className="hint-text"> · {st.issuer}{st.enforce ? ` · ${t("sso.enforced")}` : ""}</span>}
        </p>
        {!editing ? (
          <div className="u-btn-row">
            <button className="btn btn-sm btn-primary" onClick={() => setEditing(true)}>{st.enabled ? t("sso.change") : t("sso.setup")}</button>
            {st.enabled && <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => save(false)}>{t("sso.disable")}</button>}
          </div>
        ) : (
          <div className="ag-stack">
            <div className="form-row">
              <div className="field">
                <label htmlFor="sso-iss">{t("sso.issuer")}</label>
                <input id="sso-iss" className="mono" value={form.issuer} placeholder="https://acme.okta.com"
                  onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="sso-client">{t("sso.client_id")}</label>
                <input id="sso-client" className="mono" value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
              </div>
            </div>
            <div className="form-row">
              <div className="field">
                <label htmlFor="sso-secret">{t("sso.client_secret")}</label>
                <input id="sso-secret" type="password" autoComplete="new-password" value={form.client_secret}
                  placeholder={st.has_secret ? t("sso.secret_keep") : ""} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="sso-domains">{t("sso.domains")}</label>
                <input id="sso-domains" className="mono" value={form.domains} placeholder="acme.com"
                  onChange={(e) => setForm({ ...form, domains: e.target.value })} />
              </div>
              <div className="field" style={{ maxWidth: 160 }}>
                <label htmlFor="sso-claim">{t("sso.email_claim")}</label>
                <input id="sso-claim" className="mono" value={form.email_claim} onChange={(e) => setForm({ ...form, email_claim: e.target.value })} />
              </div>
            </div>
            {check("jit", t("sso.jit"), t("sso.jit_hint"))}
            {form.jit && (
              <div className="u-row-tight">
                <label htmlFor="sso-role">{t("scim.default_role")}</label>
                <select id="sso-role" style={{ width: "auto" }} value={form.default_role} onChange={(e) => setForm({ ...form, default_role: e.target.value })}>
                  <option value="user">{t("users.roles.user")}</option>
                  <option value="approver">{t("users.roles.approver")}</option>
                </select>
              </div>
            )}
            {check("enforce", t("sso.enforce"), t("sso.enforce_hint"))}
            {check("require_idp_mfa", t("sso.require_idp_mfa"), t("sso.require_idp_mfa_hint"))}
            <div className="u-btn-row">
              <button className="btn btn-sm btn-primary" disabled={busy || !form.issuer.trim() || !form.client_id.trim()} onClick={() => save(true)}>
                {busy ? t("common.loading") : t("sso.save")}
              </button>
              <button className="btn btn-sm" onClick={() => setEditing(false)}>{t("common.cancel")}</button>
            </div>
          </div>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
