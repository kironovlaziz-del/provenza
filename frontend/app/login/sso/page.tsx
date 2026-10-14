"use client";

// Where single sign-on lands: the one-time code is in the URL fragment (it
// never reaches a server log); it is exchanged for a session at once.

import React, { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";

export default function SsoLandingPage() {
  const { completeSso } = useAuth();
  const { t } = useTranslation();
  const [error, setError] = useState<string | null>(null);
  const done = useRef(false);

  useEffect(() => {
    if (done.current) return;
    done.current = true;
    const code = new URLSearchParams(window.location.hash.slice(1)).get("code");
    window.history.replaceState(null, "", window.location.pathname);   // the code leaves the address bar
    if (!code) {
      setError(t("auth.sso_failed"));
      return;
    }
    completeSso(code).catch((err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(translateApiError(detail, t, t("auth.sso_failed")));
    });
  }, [completeSso, t]);

  return (
    <div className="auth-shell">
      <div className="auth-card">
        {error ? (
          <>
            <p className="error-text">{error}</p>
            <Link href="/login" className="btn">{t("auth.mfa_back")}</Link>
          </>
        ) : (
          <p className="hint-text">{t("auth.sso_signing_in")}</p>
        )}
      </div>
    </div>
  );
}
