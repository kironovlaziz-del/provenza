"use client";

import { ExtensionBanner } from "@/components/ExtensionBanner";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { translateApiError } from "@/lib/errors";
import { getAuthConfig, ssoInfo, ssoStartUrl } from "@/lib/api";
import { Logo } from "@/components/Logo";

const LAST_ORG_KEY = "ai_ct_last_org";

export default function LoginPage() {
  const { login, completeMfa } = useAuth();
  const { t } = useTranslation();
  const [orgSlug, setOrgSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [signupEnabled, setSignupEnabled] = useState(false);
  // second step of a two-factor sign-in
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");
  // single sign-on: offered for the organization typed; "password" false = admins only
  const [sso, setSso] = useState<{ sso: boolean; password: boolean } | null>(null);

  useEffect(() => {
    const ssoError = new URLSearchParams(window.location.search).get("sso_error");
    if (ssoError) setError(translateApiError(ssoError, t, t("auth.sso_failed")));
  }, [t]);

  useEffect(() => {
    if (!/^[a-z0-9-]{2,}$/.test(orgSlug)) { setSso(null); return; }
    const timer = window.setTimeout(() => { ssoInfo(orgSlug).then(setSso).catch(() => setSso(null)); }, 300);
    return () => window.clearTimeout(timer);
  }, [orgSlug]);

  useEffect(() => {
    getAuthConfig()
      .then((c) => setSignupEnabled(c.signup_enabled))
      .catch(() => setSignupEnabled(false));
  }, []);

  // Pre-fill the last used slug for convenience.
  useEffect(() => {
    const saved = window.localStorage.getItem(LAST_ORG_KEY);
    if (saved) setOrgSlug(saved);
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (mfaToken) {
        await completeMfa(mfaToken, code);
      } else {
        const { mfaToken: next } = await login(orgSlug, email, password);
        window.localStorage.setItem(LAST_ORG_KEY, orgSlug);
        if (next) {
          setMfaToken(next);
          setPassword("");
          return;
        }
      }
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })
        ?.response?.data?.detail;
      setError(translateApiError(detail, t, t("auth.login_failed")));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand" style={{ display: "flex", justifyContent: "center", marginBottom: 8 }}><Logo size="lg" center /></div>
        <LanguageSwitcher variant="light" />
        <h1 className="auth-title">{t("auth.login_title")}</h1>
        {mfaToken ? (
          <form onSubmit={handleSubmit}>
            <p className="hint-text">{t("auth.mfa_prompt")}</p>
            <div className="field">
              <label htmlFor="mfa_code">{t("auth.mfa_code")}</label>
              <input
                id="mfa_code"
                required
                autoFocus
                autoComplete="one-time-code"
                inputMode="text"
                maxLength={32}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
              />
              <span className="hint-text">{t("auth.mfa_recovery_hint")}</span>
            </div>
            {error && <p className="error-text">{error}</p>}
            <button type="submit" className="btn btn-primary" style={{ width: "100%", justifyContent: "center", marginTop: 4 }}
              disabled={submitting}>
              {submitting ? t("auth.login_button_loading") : t("auth.mfa_verify")}
            </button>
            <button type="button" className="btn" style={{ width: "100%", justifyContent: "center", marginTop: 8 }}
              onClick={() => { setMfaToken(null); setCode(""); setError(null); }}>
              {t("auth.mfa_back")}
            </button>
          </form>
        ) : (
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="org_slug">{t("auth.org_slug")}</label>
            <input
              id="org_slug"
              required
              autoFocus
              value={orgSlug}
              onChange={(e) => setOrgSlug(e.target.value.toLowerCase())}
              placeholder="acme"
              pattern="[a-z0-9-]+"
            />
            <span className="hint-text">{t("auth.org_slug_hint")}</span>
          </div>
          {sso?.sso && (
            <div className="u-mb-12">
              <button type="button" className="btn btn-primary" style={{ width: "100%", justifyContent: "center" }}
                onClick={() => { window.localStorage.setItem(LAST_ORG_KEY, orgSlug); window.location.href = ssoStartUrl(orgSlug); }}>
                {t("auth.sso_button")}
              </button>
              <p className="hint-text" style={{ textAlign: "center", marginTop: 6 }}>
                {sso.password ? t("auth.sso_or_password") : t("auth.sso_only")}
              </p>
            </div>
          )}
          <div className="field">
            <label htmlFor="email">{t("auth.email")}</label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
            />
          </div>
          <div className="field">
            <label htmlFor="password">{t("auth.password")}</label>
            <input
              id="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>
          {error && <p className="error-text">{error}</p>}
          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", justifyContent: "center", marginTop: 4 }}
            disabled={submitting}
          >
            {submitting ? t("auth.login_button_loading") : t("auth.login_button")}
          </button>
        </form>
        )}
        <ExtensionBanner />
        {signupEnabled && (
          <p className="auth-switch">
            {t("auth.no_account")} <Link href="/register">{t("auth.register_link")}</Link>
          </p>
        )}
      </div>
    </div>
  );
}
