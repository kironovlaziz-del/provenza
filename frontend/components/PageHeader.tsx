"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { pageMatches, sectionOf } from "@/lib/navigation";
import { useFeatures } from "@/lib/features";

/** The page title, its actions, and - when the page's section has several
 *  pages the user may open - those pages as tabs (lib/navigation.ts). Pages
 *  for occasional use sit behind "More"; the one open now shows as a tab. */
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
  const [showMore, setShowMore] = useState(false);
  const pages = section?.pages ?? [];
  const main = pages.filter((p) => !p.more || pageMatches(p.href, pathname));
  const more = pages.filter((p) => p.more && !pageMatches(p.href, pathname));
  return (
    <>
      <div className="topbar">
        <h1>{title}</h1>
        {actions && <div style={{ display: "flex", gap: 8 }}>{actions}</div>}
      </div>
      {section && (main.length > 1 || more.length > 0) && (
        <nav className="section-tabs" aria-label={t(section.labelKey)}>
          {main.map((p) => (
            <Link key={p.href} href={p.href} className={`section-tab${pageMatches(p.href, pathname) ? " active" : ""}`}>
              {t(p.labelKey)}
            </Link>
          ))}
          {more.length > 0 && (
            <button type="button" className="section-tab section-more" aria-expanded={showMore}
              onClick={() => setShowMore((v) => !v)}>
              {t("sidebar.more", "More")} {showMore ? "▴" : "▾"}
            </button>
          )}
        </nav>
      )}
      {section && showMore && more.length > 0 && (
        <nav className="section-tabs section-tabs-more" aria-label={t("sidebar.more", "More")}>
          {more.map((p) => (
            <Link key={p.href} href={p.href} className="section-tab">{t(p.labelKey)}</Link>
          ))}
        </nav>
      )}
    </>
  );
}
