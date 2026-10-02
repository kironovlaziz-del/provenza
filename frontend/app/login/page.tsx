"use client";

import { ExtensionBanner } from "@/components/ExtensionBanner";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { translateApiError } from "@/lib/errors";
import { getAuthConfig } from "@/lib/api";
import { Logo } from "@/components/Logo";

const LAST_ORG_KEY = "ai_ct_last_org";

export default function LoginPage() {
  const { login } = useAuth();
  const { t } = useTranslation();
  const [orgSlug, setOrgSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [signupEnabled, setSignupEnabled] = useState(false);

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
      await login(orgSlug, email, password);
      window.localStorage.setItem(LAST_ORG_KEY, orgSlug);
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
