"use client";

import React, { useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { loginUrl, useAuth } from "@/lib/auth";
import { canOpen, homeFor } from "@/lib/navigation";
import { DialogHost } from "@/components/Dialog";
import { ReleaseBanner } from "@/components/ReleaseBanner";
import { SessionBanner } from "@/components/SessionBanner";
import { TopBar } from "@/components/TopBar";
import { SystemHealthBanner } from "@/components/SystemHealthBanner";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const { t } = useTranslation();

  useEffect(() => {
    if (!loading && !user) {
      router.replace(loginUrl());
    }
  }, [loading, user, router]);

  if (loading) {
    return (
      // the server renders in English, the browser in the reader's language
      <div className="loading-line" style={{ padding: 40 }} suppressHydrationWarning>
        {t("common.loading")}
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="shell">
      <TopBar />
      <div className="main">
        {user.role === "auditor" && (
          // one line, every page: why the buttons answer "read-only"
          <div role="note" style={{ padding: "6px 16px", fontSize: 12, color: "var(--text-muted)",
            borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
            {t("roles.auditor_banner", "Auditor: read-only access. You see everything administrators see and change nothing.")}
          </div>
        )}
        <SessionBanner />
        <ReleaseBanner />
        <SystemHealthBanner />
        {canOpen(pathname, user.role, !!user.is_operator) ? children : (
          // a page this role does not see (an old link, a typed address): say so
          // instead of rendering it and letting every request be refused
          <div className="content">
            <div className="panel" role="alert" style={{ maxWidth: 560 }}>
              <div className="panel-body">
                <h2 style={{ marginTop: 0, fontSize: 16 }}>{t("nav.no_access_title")}</h2>
                <p className="hint-text">{t("nav.no_access")}</p>
                <Link href={homeFor(user.role)} className="btn btn-primary">{t("nav.no_access_home")}</Link>
              </div>
            </div>
          </div>
        )}
      </div>
      <DialogHost />
    </div>
  );
}