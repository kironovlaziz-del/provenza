// The console's navigation, in one place. The top bar (components/TopBar.tsx)
// shows the sections: four tabs - Inbox, AI, Rules, Evidence - then Settings
// and Help behind icons. A section with several pages shows them as tabs under
// the page title (components/PageHeader.tsx); a "hub" section (Settings, Help)
// lists its pages on its own first page instead, and its other pages link back
// to it. Pages keep their own URLs.
//
// adminOnly: admins; reviewOnly: admins and approvers; operatorOnly: admins of
// the organization that runs the installation (User.is_operator) - pages with
// data of every organization. The oversight roles (auditor, compliance) read
// what admins read. A section is shown when the user may open at least one of
// its main pages; it links to the first of them.
//
// more: a page for occasional use. It is not a tab of its own but sits behind
// the section's "More" link, and search still finds it.
//
// Simple mode (lib/console_mode.ts, the default) shows SIMPLE_SECTIONS instead:
// four tabs - AI agents, Rules, Audit log, Shadow AI - then Settings and Help.
// Its pages are pages of SECTIONS with the same role rules; every other page
// still opens by its address (canOpen does not depend on the mode).

import type { ConsoleMode } from "./console_mode";

export type Role = "admin" | "approver" | "user" | "auditor" | "compliance" | string | undefined;

const OVERSIGHT = ["auditor", "compliance"];

export interface NavPage {
  href: string;
  labelKey: string;
  adminOnly?: boolean;
  reviewOnly?: boolean;
  operatorOnly?: boolean;
  /** Behind the section's "More" link instead of a tab of its own. */
  more?: boolean;
  /** For a hub's page list: the group it is listed under (nav.group.<key>). */
  group?: string;
}

export interface NavSection {
  key: string;
  labelKey: string;
  icon: string;
  pages: NavPage[];
  /** Settings, Help: the first page lists the others; no tabs. */
  hub?: boolean;
  /** Settings, Help: an icon in the top bar, not one of the four tabs. */
  utility?: boolean;
}

/** Kept for callers that walk groups; there is one group now. */
export interface NavGroup {
  key: string;
  labelKey: string;
  sections: NavSection[];
}

const P = (href: string, label: string, extra: Partial<NavPage> = {}): NavPage => ({
  href, labelKey: `sidebar.nav.${label}`, ...extra,
});

export const SECTIONS: NavSection[] = [
  {
    key: "inbox", labelKey: "nav.inbox", icon: "inbox", pages: [
      P("/inbox", "inbox", { reviewOnly: true }),
      P("/approvals", "approvals", { reviewOnly: true }),
      P("/incidents", "incidents", { reviewOnly: true }),
    ],
  },
  {
    key: "ai", labelKey: "nav.ai", icon: "registry", pages: [
      P("/inventory", "inventory"),
      P("/agents", "agents"),
      P("/providers", "providers"),
      P("/shadow-ai", "shadow_ai"),
      P("/agents-found", "agents_found", { reviewOnly: true }),
      P("/agent-observability", "agent_observability"),
      P("/connections", "connections", { more: true }),
      P("/devices", "devices", { reviewOnly: true, more: true }),
      P("/agent-map", "agent_map", { more: true }),
      P("/agent-chains", "agent_chains", { more: true }),
      P("/use-cases", "use_cases", { more: true }),
      P("/teams", "teams", { more: true }),
      P("/discovery", "discovery", { adminOnly: true, more: true }),
    ],
  },
  {
    key: "rules", labelKey: "nav.rules", icon: "policies", pages: [
      P("/policy-hierarchy", "policy_hierarchy", { reviewOnly: true }),
      P("/agent-policies", "agent_policies", { adminOnly: true }),
      P("/tool-registry", "tool_registry", { adminOnly: true }),
      P("/agent-breaker", "agent_breaker", { adminOnly: true }),
      P("/agent-behavior", "agent_behavior", { adminOnly: true }),
    ],
  },
  {
    key: "evidence", labelKey: "nav.evidence", icon: "audit", pages: [
      P("/audit", "audit", { reviewOnly: true }),
      P("/compliance", "compliance", { reviewOnly: true }),
      P("/kill-switch", "kill_switch", { reviewOnly: true }),
    ],
  },
  {
    key: "settings", labelKey: "nav.settings", icon: "settings", hub: true, utility: true, pages: [
      P("/settings", "settings"),
      P("/profile", "profile", { group: "you" }),
      P("/users", "users", { adminOnly: true, group: "people" }),
      P("/notifications", "notifications", { adminOnly: true, group: "people" }),
      P("/gateway", "gateway", { adminOnly: true, group: "gateways" }),
      P("/runtime", "runtime", { adminOnly: true, group: "gateways" }),
      P("/agent-identity", "agent_identity", { adminOnly: true, group: "gateways" }),
      P("/attestation", "attestation", { adminOnly: true, group: "gateways" }),
      P("/ingestion-sources", "ingestion_sources", { adminOnly: true, group: "gateways" }),
      P("/domain-catalog", "domain_catalog", { adminOnly: true, group: "gateways" }),
      P("/encryption-keys", "encryption_keys", { adminOnly: true, group: "data" }),
      P("/retention", "retention", { adminOnly: true, group: "data" }),
      P("/export-keys", "export_keys", { adminOnly: true, group: "data" }),
      P("/system-status", "system_status", { adminOnly: true, group: "system" }),
      P("/observability", "observability", { operatorOnly: true, group: "system" }),
    ],
  },
  {
    key: "help", labelKey: "nav.help", icon: "help", hub: true, utility: true, pages: [
      P("/help", "help"),
    ],
  },
];

/** A page of SECTIONS (its role rules), under another label or hub group. */
function pick(href: string, extra: Partial<NavPage> = {}): NavPage {
  const page = SECTIONS.flatMap((s) => s.pages).find((p) => p.href === href);
  if (!page) throw new Error(`navigation: ${href} is not a page of the console`);
  return { ...page, more: false, group: undefined, ...extra };
}

export const SIMPLE_SECTIONS: NavSection[] = [
  { key: "agents", labelKey: "nav.simple.agents", icon: "registry", pages: [pick("/agents")] },
  {
    key: "rules", labelKey: "nav.rules", icon: "policies", pages: [
      // levels, rule packs and the signed policy
      pick("/policy-hierarchy"),
      // what agents reach through Provenza: AI models, MCP and HTTP tools, other agents, external APIs
      pick("/gateway"),
    ],
  },
  { key: "audit", labelKey: "nav.simple.audit", icon: "audit", pages: [pick("/audit")] },
  { key: "shadow", labelKey: "nav.simple.shadow_ai", icon: "search", pages: [pick("/shadow-ai")] },
  {
    key: "settings", labelKey: "nav.settings", icon: "settings", hub: true, utility: true, pages: [
      pick("/settings"),
      pick("/profile", { group: "you" }),
      pick("/users", { group: "people" }),
      pick("/notifications", { group: "people" }),
    ],
  },
  { key: "help", labelKey: "nav.help", icon: "help", hub: true, utility: true, pages: [pick("/help")] },
];

export function sectionsFor(mode: ConsoleMode = "full"): NavSection[] {
  return mode === "simple" ? SIMPLE_SECTIONS : SECTIONS;
}

export const NAV: NavGroup[] = [{ key: "main", labelKey: "nav.main", sections: SECTIONS }];

export function canSee(page: NavPage, role: Role, operator = false): boolean {
  if (page.operatorOnly) return role === "admin" && operator;
  // the oversight roles (auditor, compliance) read what admins read
  if (page.adminOnly) return role === "admin" || OVERSIGHT.includes(role as string);
  if (page.reviewOnly) return role === "admin" || role === "approver" || OVERSIGHT.includes(role as string);
  return true;
}

export function pageMatches(href: string, pathname: string | null | undefined): boolean {
  return !!pathname && (pathname === href || pathname.startsWith(href + "/"));
}

/** The sections this role sees, each with its visible pages only (its "more"
 *  pages after its main ones). A section is shown when one of its main pages
 *  is visible. */
export function visibleSections(role: Role, operator = false, mode: ConsoleMode = "full"): NavSection[] {
  return sectionsFor(mode)
    .map((s) => {
      const pages = s.pages.filter((p) => canSee(p, role, operator));
      return { ...s, pages: [...pages.filter((p) => !p.more), ...pages.filter((p) => p.more)] };
    })
    .filter((s) => s.pages.some((p) => !p.more));
}

export function visibleNav(role: Role, operator = false): NavGroup[] {
  return [{ ...NAV[0], sections: visibleSections(role, operator) }];
}

/** The section of this address in the mode's navigation; none for a page the
 *  mode does not show (it still opens, without section tabs). */
export function sectionOf(
  pathname: string | null | undefined,
  role: Role,
  operator = false,
  mode: ConsoleMode = "full",
): NavSection | undefined {
  // the help articles live under /help/<slug>
  return visibleSections(role, operator, mode).find((s) => s.pages.some((p) => pageMatches(p.href, pathname)));
}

/** Where a sign-in lands. Simple mode: the agents, for everyone. Full console:
 *  the Inbox for whoever decides (admins, approvers, auditors, compliance), the
 *  AI list for everybody else. */
export function homeFor(role: Role, mode: ConsoleMode = "full"): string {
  if (mode === "simple") return "/agents";
  return role === "user" || !role ? "/inventory" : "/inbox";
}

/** Decides or oversees (admins, approvers, auditors, compliance): the Inbox,
 *  the waiting count and the stop line are theirs. */
export function isReviewer(role: Role): boolean {
  return role === "admin" || role === "approver" || OVERSIGHT.includes(role as string);
}

/** Addresses that only send the visitor on (to a page of the navigation). */
export const REDIRECT_PAGES = ["/dashboard"];

/** May this role open this address? Pages the navigation does not show the
 *  role answer with "no access" instead of a page full of refused requests. */
export function canOpen(pathname: string | null | undefined, role: Role, operator = false): boolean {
  if (!pathname || REDIRECT_PAGES.some((h) => pageMatches(h, pathname))) return true;
  return !!sectionOf(pathname, role, operator);
}
