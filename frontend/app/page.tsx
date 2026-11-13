"use client";

import "./welcome.css";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { Welcome } from "@/components/Welcome";

/** /: the welcome page for visitors; a signed-in user goes on to the dashboard. */
export default function RootPage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const { t } = useTranslation();

  useEffect(() => {
    if (!loading && user) router.replace("/dashboard");
  }, [loading, user, router]);

  if (loading || user) {
    return (
      <div className="loading-line" style={{ padding: 40 }}>
        {t("common.loading")}
      </div>
    );
  }
  return <Welcome />;
}
