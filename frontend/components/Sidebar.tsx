"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { useFeatures } from "@/lib/features";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { Logo } from "@/components/Logo";
import { pageMatches, sectionOf } from "@/lib/navigation";
import { useVisibleNav } from "@/lib/useNav";

// Stroke icons (24x24, feather-style paths), one per section.
const ICONS: Record<string, string> = {
  overview: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z",
  discovery: "M12 12h.01M16.24 7.76a6 6 0 1 1-8.49 0M19.07 4.93a10 10 0 1 1-14.14 0",
  registry: "M9 3h6v4H9zM15 5h4v16H5V5h4M9 12h6M9 16h4",
  policies: "M12 3v18M7 21h10M5 7h14M5 7l-3 7a3 3 0 0 0 6 0zM19 7l-3 7a3 3 0 0 0 6 0z",
  security: "M12 2l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V6z",
  audit: "M14 2H6v20h12V6zM14 2v4h4M9 15l2 2 4-4",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
  chevron: "M9 6l6 6-6 6",
  collapse: "M15 6l-6 6 6 6",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  alert: "M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  check: "M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11",
  stop: "M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9zM9 9h6v6H9z",
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  agent: "M12 2a4 4 0 1 1 0 8 4 4 0 0 1 0-8zM4 22v-2a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v2",
  gateway: "M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18z",
};

function Icon({ name, size = 16 }: { name: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ flexShrink: 0 }}>
      <path d={ICONS[name]} />
    </svg>
  );
}

const NARROW_KEY = "pvz.sidebar.narrow";
const THEME_KEY = "pvz.theme";

function load<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw == null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

function save(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* private mode: preference simply not kept */
  }
}

export function applyTheme(theme: "dark" | "light") {
  document.documentElement.setAttribute("data-theme", theme);
}

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { t } = useTranslation();
  const [narrow, setNarrow] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [query, setQuery] = useState("");

  const { features } = useFeatures();
  const groups = useVisibleNav(user?.role, !!user?.is_operator);
  const active = sectionOf(pathname, user?.role, features, !!user?.is_operator)?.key;

  useEffect(() => {
    setNarrow(load<boolean>(NARROW_KEY, false));
    const th = load<"dark" | "light">(THEME_KEY, "dark");
    setTheme(th);
    applyTheme(th);
  }, []);

  function toggleNarrow() {
    setNarrow(!narrow);
    save(NARROW_KEY, !narrow);
  }

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
    save(THEME_KEY, next);
  }

  // search finds pages, not only sections: "PII" lands on PII rules directly
  const q = query.trim().toLowerCase();
  const hits = q
    ? groups.flatMap((g) => g.sections.flatMap((s) => s.pages.map((p) => ({ page: p, section: s }))))
        .filter(({ page, section }) =>
          t(page.labelKey).toLowerCase().includes(q) || t(section.labelKey).toLowerCase().includes(q) || page.href.includes(q))
    : [];

  return (
    <aside className={`sidebar${narrow ? " narrow" : ""}`}>
      <div className="sidebar-brand">
        {narrow ? <div className="sidebar-brand-mini" title="Provenza">P</div> : <Logo />}
        {!narrow && <div className="sidebar-brand-sub" style={{ marginTop: 6 }}>org-{user?.org_id ?? "—"}</div>}
      </div>

      {!narrow && (
        <div className="sidebar-search">
          <Icon name="search" size={14} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("sidebar.search")}
            aria-label={t("sidebar.search")} />
          {query && <button onClick={() => setQuery("")} aria-label={t("common.clear")}>×</button>}
        </div>
      )}

      <nav className="sidebar-nav">
        {q ? (
          <div className="sidebar-items">
            {hits.map(({ page, section }) => (
              <Link key={page.href} href={page.href} onClick={() => setQuery("")}
                className={`sidebar-link${pageMatches(page.href, pathname) ? " active" : ""}`}>
                {t(page.labelKey)}
                {section.pages.length > 1 && <span className="sidebar-hit-section"> · {t(section.labelKey)}</span>}
              </Link>
            ))}
            {hits.length === 0 && <div className="sidebar-empty">{t("sidebar.no_match")}</div>}
          </div>
        ) : (
          groups.map((group) => (
            <div key={group.key} className="sidebar-group">
              {!narrow && <div className="sidebar-group-label">{t(group.labelKey)}</div>}
              {group.sections.map((section) =>
                narrow ? (
                  <Link key={section.key} href={section.pages[0].href} title={t(section.labelKey)}
                    className={`sidebar-icon-link${active === section.key ? " active" : ""}`}>
                    <Icon name={section.icon} size={18} />
                  </Link>
                ) : (
                  <Link key={section.key} href={section.pages[0].href}
                    className={`sidebar-link sidebar-section-link${active === section.key ? " active" : ""}`}>
                    <Icon name={section.icon} size={15} />
                    <span>{t(section.labelKey)}</span>
                  </Link>
                ),
              )}
            </div>
          ))
        )}
      </nav>

      <div className="sidebar-footer">
        {!narrow && (
          <>
            <div className="sidebar-user">{user?.name ?? "—"}</div>
            <div className="sidebar-org">{t(`sidebar.role_${user?.role ?? "user"}`)}</div>
            <div style={{ marginTop: 8 }}>
              <LanguageSwitcher />
            </div>
          </>
        )}
        <div className={`sidebar-tools${narrow ? " col" : ""}`}>
          <button onClick={toggleTheme} title={theme === "dark" ? t("sidebar.theme_light", "Light theme") : t("sidebar.theme_dark", "Dark theme")}>
            <Icon name={theme === "dark" ? "sun" : "moon"} size={15} />
          </button>
          <button onClick={toggleNarrow} title={narrow ? t("sidebar.expand", "Expand sidebar") : t("sidebar.collapse", "Collapse sidebar")}>
            <span style={{ display: "inline-flex", transform: narrow ? "rotate(180deg)" : undefined }}><Icon name="collapse" size={15} /></span>
          </button>
          <button onClick={logout} title={t("sidebar.logout")}>
            <Icon name="logout" size={15} />
            {!narrow && <span style={{ marginLeft: 6 }}>{t("sidebar.logout")}</span>}
          </button>
        </div>
      </div>
    </aside>
  );
}
