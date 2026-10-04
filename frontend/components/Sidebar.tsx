"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { Logo } from "@/components/Logo";

type Item = { href: string; labelKey: string; adminOnly?: boolean };
type Group = { sectionKey: string; icon: string; items: Item[] };

// Stroke icons (24x24, feather-style paths), one per section.
const ICONS: Record<string, string> = {
  overview: "M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z",
  connections: "M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0zM12 18v4",
  management: "M3 7h6l2 2h10v11H3z",
  operations: "M22 12h-4l-3 9L9 3l-3 9H2",
  monitoring: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  agents: "M7 7h10v10H7zM9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3",
  security: "M12 2l8 4v6c0 5-3.5 9-8 10-4.5-1-8-5-8-10V6z",
  data: "M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3",
  chevron: "M9 6l6 6-6 6",
  collapse: "M15 6l-6 6 6 6",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
};

function Icon({ name, size = 16 }: { name: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ flexShrink: 0 }}>
      <path d={ICONS[name]} />
    </svg>
  );
}

const NAV: Group[] = [
  { sectionKey: "sidebar.sections.overview", icon: "overview", items: [{ href: "/dashboard", labelKey: "sidebar.nav.dashboard" }] },
  { sectionKey: "sidebar.sections.connections", icon: "connections", items: [{ href: "/connections", labelKey: "sidebar.nav.connections" }] },
  {
    sectionKey: "sidebar.sections.management",
    icon: "management",
    items: [
      { href: "/inventory", labelKey: "sidebar.nav.inventory" },
      { href: "/policies", labelKey: "sidebar.nav.policies" },
      { href: "/use-cases", labelKey: "sidebar.nav.use_cases" },
      { href: "/providers", labelKey: "sidebar.nav.providers" },
      { href: "/users", labelKey: "sidebar.nav.users", adminOnly: true },
    ],
  },
  {
    sectionKey: "sidebar.sections.operations",
    icon: "operations",
    items: [
      { href: "/requests", labelKey: "sidebar.nav.requests" },
      { href: "/approvals", labelKey: "sidebar.nav.approvals" },
      { href: "/provider-chat", labelKey: "sidebar.nav.provider_chat" },
    ],
  },
  {
    sectionKey: "sidebar.sections.monitoring",
    icon: "monitoring",
    items: [
      { href: "/incidents", labelKey: "sidebar.nav.incidents" },
      { href: "/shadow-ai", labelKey: "sidebar.nav.shadow_ai" },
      { href: "/domain-catalog", labelKey: "sidebar.nav.domain_catalog", adminOnly: true },
      { href: "/ingestion-sources", labelKey: "sidebar.nav.ingestion_sources", adminOnly: true },
      { href: "/discovery", labelKey: "sidebar.nav.discovery", adminOnly: true },
      { href: "/audit", labelKey: "sidebar.nav.audit" },
    ],
  },
  {
    sectionKey: "sidebar.sections.agent_governance",
    icon: "agents",
    items: [
      { href: "/agent-observability", labelKey: "sidebar.nav.agent_observability" },
      { href: "/agent-map", labelKey: "sidebar.nav.agent_map" },
      { href: "/agents", labelKey: "sidebar.nav.agents" },
      { href: "/agent-chains", labelKey: "sidebar.nav.agent_chains" },
      { href: "/agent-identity", labelKey: "sidebar.nav.agent_identity", adminOnly: true },
      { href: "/gateway", labelKey: "sidebar.nav.gateway", adminOnly: true },
    ],
  },
  {
    sectionKey: "sidebar.sections.agent_security",
    icon: "security",
    items: [
      { href: "/agent-policies", labelKey: "sidebar.nav.agent_policies", adminOnly: true },
      { href: "/agent-approvals", labelKey: "sidebar.nav.agent_approvals", adminOnly: true },
      { href: "/agent-incidents", labelKey: "sidebar.nav.agent_incidents", adminOnly: true },
      { href: "/agent-breaker", labelKey: "sidebar.nav.agent_breaker", adminOnly: true },
      { href: "/tool-registry", labelKey: "sidebar.nav.tool_registry", adminOnly: true },
      { href: "/agent-behavior", labelKey: "sidebar.nav.agent_behavior", adminOnly: true },
      { href: "/agent-injection", labelKey: "sidebar.nav.agent_injection", adminOnly: true },
      { href: "/agent-code-exec", labelKey: "sidebar.nav.agent_code_exec", adminOnly: true },
      { href: "/agent-memory", labelKey: "sidebar.nav.agent_memory", adminOnly: true },
      { href: "/agent-messages", labelKey: "sidebar.nav.agent_messages", adminOnly: true },
    ],
  },
  {
    sectionKey: "sidebar.sections.data_compliance",
    icon: "data",
    items: [
      { href: "/compliance", labelKey: "sidebar.nav.compliance" },
      { href: "/encryption-keys", labelKey: "sidebar.nav.encryption_keys", adminOnly: true },
      { href: "/queue-ttl", labelKey: "sidebar.nav.queue_ttl", adminOnly: true },
    ],
  },
  { sectionKey: "sidebar.sections.settings", icon: "settings", items: [
      { href: "/notifications", labelKey: "sidebar.nav.notifications" },
      { href: "/system-status", labelKey: "sidebar.nav.system_status", adminOnly: true },
    ] },
];

const OPEN_KEY = "pvz.sidebar.open";
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
  const [open, setOpen] = useState<string[] | null>(null);
  const [narrow, setNarrow] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [query, setQuery] = useState("");

  const isActive = (href: string) => pathname === href || !!pathname?.startsWith(href + "/");
  const groups = useMemo(
    () =>
      NAV.map((g) => ({ ...g, items: g.items.filter((i) => !i.adminOnly || user?.role === "admin") })).filter((g) => g.items.length),
    [user?.role],
  );
  const activeGroup = groups.find((g) => g.items.some((i) => isActive(i.href)))?.sectionKey;

  useEffect(() => {
    setOpen(load<string[]>(OPEN_KEY, ["sidebar.sections.overview"]));
    setNarrow(load<boolean>(NARROW_KEY, false));
    const th = load<"dark" | "light">(THEME_KEY, "dark");
    setTheme(th);
    applyTheme(th);
  }, []);

  // open the group of the current page when the user navigates to it - once
  // per navigation, so the group can still be collapsed afterwards
  const openedFor = useRef<string | null>(null);
  useEffect(() => {
    if (!open || !activeGroup || openedFor.current === pathname) return;
    openedFor.current = pathname ?? null;
    if (!open.includes(activeGroup)) {
      const next = [...open, activeGroup];
      setOpen(next);
      save(OPEN_KEY, next);
    }
  }, [activeGroup, open, pathname]);

  function toggle(key: string) {
    const cur = open ?? [];
    const next = cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key];
    setOpen(next);
    save(OPEN_KEY, next);
  }

  function setAll(expand: boolean) {
    const next = expand ? groups.map((g) => g.sectionKey) : activeGroup ? [activeGroup] : [];
    setOpen(next);
    save(OPEN_KEY, next);
  }

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

  const q = query.trim().toLowerCase();
  const visible = q
    ? groups
        .map((g) => ({ ...g, items: g.items.filter((i) => t(i.labelKey).toLowerCase().includes(q) || i.href.includes(q)) }))
        .filter((g) => g.items.length)
    : groups;

  return (
    <aside className={`sidebar${narrow ? " narrow" : ""}`}>
      <div className="sidebar-brand">
        {narrow ? <div className="sidebar-brand-mini" title="Provenza">P</div> : <Logo />}
        {!narrow && <div className="sidebar-brand-sub" style={{ marginTop: 6 }}>org-{user?.org_id ?? "—"}</div>}
      </div>

      {!narrow && (
        <div className="sidebar-search">
          <Icon name="search" size={14} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("sidebar.search", "Search menu…")}
            aria-label={t("sidebar.search", "Search menu…")} />
          {query && <button onClick={() => setQuery("")} aria-label="clear">×</button>}
        </div>
      )}
      {!narrow && !q && (
        <div className="sidebar-expand">
          <button onClick={() => setAll(true)}>{t("sidebar.expand_all", "Expand all")}</button>
          <button onClick={() => setAll(false)}>{t("sidebar.collapse_all", "Collapse all")}</button>
        </div>
      )}

      <nav className="sidebar-nav">
        {visible.map((group) => {
          const expanded = !!q || (open ?? []).includes(group.sectionKey);
          const containsActive = group.sectionKey === activeGroup;
          if (narrow) {
            const first = group.items[0];
            return (
              <Link key={group.sectionKey} href={first.href} title={t(group.sectionKey)}
                className={`sidebar-icon-link${containsActive ? " active" : ""}`}
                onClick={(e) => {
                  // a group with several pages: open the wide sidebar on that group instead of jumping
                  if (group.items.length > 1) {
                    e.preventDefault();
                    setNarrow(false);
                    save(NARROW_KEY, false);
                    if (!(open ?? []).includes(group.sectionKey)) toggle(group.sectionKey);
                  }
                }}>
                <Icon name={group.icon} size={18} />
              </Link>
            );
          }
          return (
            <div key={group.sectionKey} className={`sidebar-group${containsActive ? " has-active" : ""}`}>
              <button className="sidebar-section" onClick={() => toggle(group.sectionKey)} aria-expanded={expanded}>
                <Icon name={group.icon} size={15} />
                <span className="sidebar-section-label">{t(group.sectionKey)}</span>
                <span className="sidebar-count">{group.items.length}</span>
                <span className={`sidebar-chevron${expanded ? " open" : ""}`}><Icon name="chevron" size={13} /></span>
              </button>
              {expanded && (
                <div className="sidebar-items">
                  {group.items.map((item) => (
                    <Link key={item.href} href={item.href} className={`sidebar-link${isActive(item.href) ? " active" : ""}`}>
                      {t(item.labelKey)}
                    </Link>
                  ))}
                </div>
              )}
            </div>
          );
        })}
        {q && visible.length === 0 && <div className="sidebar-empty">{t("sidebar.no_match", "Nothing found")}</div>}
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
