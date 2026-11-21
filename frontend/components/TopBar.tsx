"use client";

// The console's one bar: the mode's tabs - simple mode: AI agents, Rules,
// Audit log, Shadow AI; full console: Inbox, AI, Rules, Evidence - search
// (also Ctrl+K), Stop all for admins, Help, Settings and the user's menu.
// Simple mode adds what waits for a decision (approvals and open incidents,
// to the Inbox) and, for admins, whether the protection works (to Settings).
// Under the bar, while anything is stopped, a red line says so on every page.

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { homeFor, isReviewer, pageMatches, sectionOf, visibleSections, type NavSection } from "@/lib/navigation";
import { api, listIncidentsPage } from "@/lib/api";
import { listAgentIncidents } from "@/lib/agent_api";
import { listPendingApprovals } from "@/lib/approvals_api";
import { useConsoleMode } from "@/lib/console_mode";
import { protectionState, type CoverageSummary } from "@/lib/coverage";
import { killOverview, type KillOverviewT } from "@/lib/kill_switch_api";
import { Icon } from "./Icon";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { Logo } from "./Logo";

const THEME_KEY = "pvz.theme";

function loadTheme(): "dark" | "light" {
  try {
    const raw = window.localStorage.getItem(THEME_KEY);
    return raw ? (JSON.parse(raw) === "light" ? "light" : "dark") : "dark";
  } catch {
    return "dark";
  }
}

export function applyTheme(theme: "dark" | "light") {
  document.documentElement.setAttribute("data-theme", theme);
}

/** Every page this role may open, for search. */
function searchHits(sections: NavSection[], q: string, t: (k: string) => string) {
  return sections.flatMap((s) => s.pages.map((p) => ({ page: p, section: s })))
    .filter(({ page, section }) =>
      t(page.labelKey).toLowerCase().includes(q) || t(section.labelKey).toLowerCase().includes(q)
      || page.href.includes(q));
}

/** sections: the mode's, listed before anything is typed; all: every page this
 *  role may open (the full console's), searched in either mode. */
function SearchDialog({ sections, all, onClose }: { sections: NavSection[]; all: NavSection[]; onClose: () => void }) {
  const { t } = useTranslation();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const q = query.trim().toLowerCase();
  const hits = q ? searchHits(all, q, t) : sections.flatMap((s) => s.pages.slice(0, 1).map((p) => ({ page: p, section: s })));

  useEffect(() => { inputRef.current?.focus(); }, []);
  useEffect(() => { setIndex(0); }, [query]);

  function go(href: string) {
    onClose();
    router.push(href);
  }

  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label={t("nav.search")}
        onMouseDown={(e) => e.stopPropagation()}>
        <div className="palette-input">
          <Icon name="search" size={16} />
          <input ref={inputRef} value={query} placeholder={t("nav.search_placeholder")}
            aria-label={t("nav.search")}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") onClose();
              if (e.key === "ArrowDown") { e.preventDefault(); setIndex((i) => Math.min(i + 1, hits.length - 1)); }
              if (e.key === "ArrowUp") { e.preventDefault(); setIndex((i) => Math.max(i - 1, 0)); }
              if (e.key === "Enter" && hits[index]) go(hits[index].page.href);
            }} />
          <kbd>Esc</kbd>
        </div>
        <ul className="palette-list" role="listbox">
          {hits.map(({ page, section }, i) => (
            <li key={page.href} role="option" aria-selected={i === index}>
              <button type="button" className={i === index ? "on" : ""} onMouseEnter={() => setIndex(i)}
                onClick={() => go(page.href)}>
                <span>{t(page.labelKey)}</span>
                <small>{t(section.labelKey)}</small>
              </button>
            </li>
          ))}
          {hits.length === 0 && <li className="palette-empty">{t("sidebar.no_match")}</li>}
        </ul>
      </div>
    </div>
  );
}

export function TopBar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { t } = useTranslation();
  const [searching, setSearching] = useState(false);
  const [menu, setMenu] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [pending, setPending] = useState(0);
  const [stops, setStops] = useState<KillOverviewT | null>(null);
  // simple mode: open incidents (platform and agent) and the protection coverage
  const [incidents, setIncidents] = useState(0);
  const [coverage, setCoverage] = useState<CoverageSummary | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const [mode] = useConsoleMode();
  const simple = mode === "simple";

  const role = user?.role;
  const sections = visibleSections(role, !!user?.is_operator, mode);
  const tabs = sections.filter((s) => !s.utility);
  const utilities = sections.filter((s) => s.utility);
  const active = sectionOf(pathname, role, !!user?.is_operator, mode)?.key;
  const reviewer = isReviewer(role);

  useEffect(() => {
    const th = loadTheme();
    setTheme(th);
    applyTheme(th);
  }, []);

  // the Inbox count and the stop line: refreshed on each page and every minute
  const refresh = useCallback(() => {
    if (!reviewer) return;
    listPendingApprovals().then((l) => setPending(l.length)).catch(() => {});
    killOverview().then(setStops).catch(() => {});
    if (!simple) return;
    // the same incidents the Inbox lists as open: the platform's not resolved, the agents' unresolved
    Promise.allSettled([
      listIncidentsPage(0, 100).then((p) => p.items.filter((i) => i.status !== "resolved").length),
      listAgentIncidents({ unresolved_only: true, limit: 1 }).then((p) => p.total),
    ]).then((r) => setIncidents(r.reduce((n, x) => n + (x.status === "fulfilled" ? x.value : 0), 0)));
    if (role === "admin") {
      api.get<{ coverage?: { summary: CoverageSummary } }>("/system/setup")
        .then(({ data }) => setCoverage(data.coverage?.summary ?? null))
        .catch(() => setCoverage(null));
    }
  }, [reviewer, simple, role]);
  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 60_000);
    return () => window.clearInterval(id);
  }, [refresh, pathname]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearching(true);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!menu) return;
    function onDown(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenu(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menu]);
  useEffect(() => { setMenu(false); }, [pathname]);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
    try { window.localStorage.setItem(THEME_KEY, JSON.stringify(next)); } catch { /* not kept */ }
  }

  const stopCount = stops?.active?.length ?? 0;
  const waiting = pending + incidents;
  const protection = coverage ? protectionState(coverage) : null;

  return (
    <>
      <header className="appbar">
        <div className="appbar-row">
          <Link href={homeFor(role, mode)} className="appbar-brand" aria-label="Provenza">
            <Logo />
          </Link>
          <nav className="appbar-tabs" aria-label={t("nav.main")}>
            {tabs.map((s) => (
              <Link key={s.key} href={s.pages[0].href}
                className={`appbar-tab${active === s.key ? " active" : ""}`}
                aria-current={active === s.key ? "page" : undefined}>
                {t(s.labelKey)}
                {s.key === "inbox" && pending > 0 && <span className="appbar-badge">{pending}</span>}
              </Link>
            ))}
          </nav>
          <span className="appbar-space" />
          <button type="button" className="appbar-search" onClick={() => setSearching(true)}
            aria-label={t("nav.search")}>
            <Icon name="search" size={15} />
            <span className="appbar-search-text">{t("nav.search_placeholder")}</span>
            <kbd>Ctrl K</kbd>
          </button>
          {simple && protection && (
            <Link href="/settings" className={`appbar-protect appbar-protect-${protection}`}
              aria-label={t(`nav.simple.protection_${protection}`)}
              title={t("nav.simple.protection_hint", { ok: coverage?.ok, attention: coverage?.attention, missing: coverage?.missing })}>
              <Icon name={protection === "ok" ? "shield_ok" : "shield"} size={15} />
              <span className="appbar-protect-text">{t(`nav.simple.protection_${protection}`)}</span>
            </Link>
          )}
          {role === "admin" && (
            <Link href="/kill-switch" className="appbar-stop" title={t("nav.stop_all_hint")}>
              <Icon name="stop" size={15} />
              <span className="appbar-stop-text">{t("nav.stop_all")}</span>
            </Link>
          )}
          {simple && reviewer && (
            <Link href="/inbox" className={`appbar-icon appbar-bell${pageMatches("/inbox", pathname) ? " active" : ""}`}
              title={t("nav.simple.waiting", { count: waiting })} aria-label={t("nav.simple.waiting", { count: waiting })}>
              <Icon name="bell" size={17} />
              {waiting > 0 && <span className="appbar-badge" aria-hidden="true">{waiting > 99 ? "99+" : waiting}</span>}
            </Link>
          )}
          {utilities.map((s) => (
            <Link key={s.key} href={s.pages[0].href} title={t(s.labelKey)} aria-label={t(s.labelKey)}
              className={`appbar-icon${active === s.key ? " active" : ""}`}>
              <Icon name={s.icon} size={17} />
            </Link>
          ))}
          <div className="appbar-user" ref={menuRef}>
            <button type="button" className="appbar-icon" aria-haspopup="menu" aria-expanded={menu}
              aria-label={t("nav.account")} onClick={() => setMenu((v) => !v)}>
              <Icon name="user" size={17} />
            </button>
            {menu && (
              <div className="appbar-menu" role="menu">
                <div className="appbar-menu-head">
                  <b>{user?.name ?? "—"}</b>
                  <span>{user?.email}</span>
                  <span>{t(`sidebar.role_${role ?? "user"}`)} · {user?.org_name || `org-${user?.org_id ?? "—"}`}</span>
                </div>
                <Link href="/profile" role="menuitem">{t("sidebar.nav.profile")}</Link>
                <div className="appbar-menu-row"><LanguageSwitcher /></div>
                <button type="button" role="menuitem" onClick={toggleTheme}>
                  <Icon name={theme === "dark" ? "sun" : "moon"} size={15} />
                  {theme === "dark" ? t("sidebar.theme_light", "Light theme") : t("sidebar.theme_dark", "Dark theme")}
                </button>
                <button type="button" role="menuitem" onClick={logout}>
                  <Icon name="logout" size={15} />{t("sidebar.logout")}
                </button>
              </div>
            )}
          </div>
        </div>
        <nav className="appbar-tabs-narrow" aria-label={t("nav.main")}>
          {tabs.map((s) => (
            <Link key={s.key} href={s.pages[0].href} className={`appbar-tab${active === s.key ? " active" : ""}`}>
              {t(s.labelKey)}
              {s.key === "inbox" && pending > 0 && <span className="appbar-badge">{pending}</span>}
            </Link>
          ))}
        </nav>
      </header>
      {stopCount > 0 && (
        <div className="stop-line" role="alert">
          <Icon name="stop" size={15} />
          <span>
            {stops?.all_agents_stopped || stops?.traffic_stopped
              ? t("nav.stopped_org")
              : t("nav.stopped_some", { count: stopCount })}
          </span>
          {!pageMatches("/kill-switch", pathname) && <Link href="/kill-switch">{t("nav.stopped_open")}</Link>}
        </div>
      )}
      {searching && (
        <SearchDialog sections={sections} all={visibleSections(role, !!user?.is_operator)}
          onClose={() => setSearching(false)} />
      )}
    </>
  );
}
