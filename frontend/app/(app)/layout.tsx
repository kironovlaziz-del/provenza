"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { DialogHost } from "@/components/Dialog";
import { ReleaseBanner } from "@/components/ReleaseBanner";
import { SessionBanner } from "@/components/SessionBanner";
import { Sidebar } from "@/components/Sidebar";
import { SystemHealthBanner } from "@/components/SystemHealthBanner";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const { t } = useTranslation();

  useEffect(() => {
    if (!loading && !user) {
      router.replace("/login");
    }
  }, [loading, user, router]);

  if (loading) {
    return (
      <div className="loading-line" style={{ padding: 40 }}>
        {t("common.loading")}
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="shell">
      <Sidebar />
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
        {children}
      </div>
      <DialogHost />
    </div>
  );
}