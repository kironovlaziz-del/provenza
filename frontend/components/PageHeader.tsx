"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { pageMatches, sectionOf } from "@/lib/navigation";
import { useFeatures } from "@/lib/features";

/** The page title, its actions, and - when the page's section has several
 *  pages the user may open - those pages as tabs (lib/navigation.ts). */
export function PageHeader({
  title,
  actions,
}: {
  title: string;
  actions?: React.ReactNode;
}) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const { user } = useAuth();
  const { features } = useFeatures();
  const section = sectionOf(pathname, user?.role, features, !!user?.is_operator);
  return (
    <>
      <div className="topbar">
        <h1>{title}</h1>
        {actions && <div style={{ display: "flex", gap: 8 }}>{actions}</div>}
      </div>
      {section && section.pages.length > 1 && (
        <nav className="section-tabs" aria-label={t(section.labelKey)}>
          {section.pages.map((p) => (
            <Link key={p.href} href={p.href} className={`section-tab${pageMatches(p.href, pathname) ? " active" : ""}`}>
              {t(p.labelKey)}
            </Link>
          ))}
        </nav>
      )}
    </>
  );
}
