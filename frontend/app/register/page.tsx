"use client";

import { ExtensionBanner } from "@/components/ExtensionBanner";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { getAuthConfig, register } from "@/lib/api";
import { translateApiError } from "@/lib/errors";
import { useAuth } from "@/lib/auth";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { Logo } from "@/components/Logo";

function slugify(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 63);
}

export default function RegisterPage() {
  const { login } = useAuth();
  const { t } = useTranslation();
  const [form, setForm] = useState({
    org_name: "",
    org_slug: "",
    name: "",
    email: "",
    password: "",
  });
  const [slugTouched, setSlugTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // null while loading; any failure to read the config counts as "closed".
  const [signupEnabled, setSignupEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    getAuthConfig()
      .then((c) => setSignupEnabled(c.signup_enabled))
      .catch(() => setSignupEnabled(false));
  }, []);

  function update(field: keyof typeof form, value: string) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  function handleOrgNameChange(value: string) {
    setForm((f) => ({
      ...f,
      org_name: value,
      // Auto-suggest a slug while the user has not edited it themselves.
      org_slug: slugTouched ? f.org_slug : slugify(value),
    }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await register({ ...form, role: "admin" } as never);
      await login(form.org_slug, form.email, form.password);
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(translateApiError(detail, t, t("register.failed")));
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand" style={{ display: "flex", justifyContent: "center", marginBottom: 8 }}><Logo size="lg" center /></div>
        <LanguageSwitcher variant="light" />
        {signupEnabled === false ? (
          <>
            <h1 className="auth-title">{t("register.disabled_title")}</h1>
            <p className="hint-text" style={{ textAlign: "center", marginBottom: 16 }}>
              {t("register.disabled_text")}
            </p>
          </>
        ) : signupEnabled === null ? null : (
        <>
        <h1 className="auth-title">{t("register.title")}</h1>
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="org_name">{t("register.org_name")}</label>
            <input
              id="org_name"
              required
              value={form.org_name}
              onChange={(e) => handleOrgNameChange(e.target.value)}
              placeholder={t("register.org_name_placeholder")}
            />
          </div>
          <div className="field">
            <label htmlFor="org_slug">{t("register.org_slug")}</label>
            <input
              id="org_slug"
              required
              value={form.org_slug}
              onChange={(e) => {
                setSlugTouched(true);
                update("org_slug", e.target.value.toLowerCase());
              }}
              placeholder="acme"
              pattern="[a-z0-9-]+"
            />
            <span className="hint-text">{t("register.org_slug_hint")}</span>
          </div>
          <div className="field">
            <label htmlFor="name">{t("register.your_name")}</label>
            <input
              id="name"
              required
              value={form.name}
              onChange={(e) => update("name", e.target.value)}
              placeholder={t("register.your_name_placeholder")}
            />
          </div>
          <div className="field">
            <label htmlFor="email">{t("register.email")}</label>
            <input
              id="email"
              type="email"
              required
              value={form.email}
              onChange={(e) => update("email", e.target.value)}
              placeholder="you@company.com"
            />
          </div>
          <div className="field">
            <label htmlFor="password">{t("register.password")}</label>
            <input
              id="password"
              type="password"
              required
              minLength={8}
              value={form.password}
              onChange={(e) => update("password", e.target.value)}
              placeholder={t("register.password_hint")}
            />
          </div>
          {error && <p className="error-text">{error}</p>}
          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%", justifyContent: "center", marginTop: 4 }}
            disabled={submitting}
          >
            {submitting ? t("register.submitting") : t("register.submit")}
          </button>
        </form>
        </>
        )}
        <ExtensionBanner />
        <p className="auth-switch">
          {t("register.already_have")}{" "}
          <Link href="/login">{t("register.login_link")}</Link>
        </p>
      </div>
    </div>
  );
}
