"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
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
      <div className="main"><SystemHealthBanner />{children}</div>
    </div>
  );
}