// The console's navigation, in one place: the sidebar lists sections, and a
// section with several pages shows them as tabs under the page title
// (components/PageHeader.tsx). Pages keep their own URLs.
//
// adminOnly: admins; reviewOnly: admins and approvers; operatorOnly: admins of
// the organization that runs the installation (User.is_operator) - pages with
// data of every organization. A section is shown when the user may open at
// least one of its main pages; it links to the first of them.
//
// more: a page for occasional use (a setting, a technical view). It is not a
// tab of its section but sits behind the section's "More" link, and search
// still finds it. Keep the tabs to what people use every day.

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
}

export interface NavSection {
  key: string;
  labelKey: string;
  icon: string;
  pages: NavPage[];
}

export interface NavGroup {
  key: string;
  labelKey: string;
  sections: NavSection[];
}

const P = (href: string, label: string, extra: Partial<NavPage> = {}): NavPage => ({
  href, labelKey: `sidebar.nav.${label}`, ...extra,
});

export const NAV: NavGroup[] = [
  {
    key: "overview",
    labelKey: "sidebar.sections.overview",
    sections: [
      { key: "dashboard", labelKey: "sidebar.nav.dashboard", icon: "overview", pages: [P("/dashboard", "dashboard")] },
      { key: "incidents", labelKey: "sidebar.sec.incidents", icon: "alert", pages: [P("/incidents", "incidents")] },
      { key: "approvals", labelKey: "sidebar.sec.approvals", icon: "check",
        pages: [P("/approvals", "approvals", { reviewOnly: true })] },
      { key: "kill_switch", labelKey: "sidebar.nav.kill_switch", icon: "stop",
        pages: [P("/kill-switch", "kill_switch", { reviewOnly: true })] },
    ],
  },
  {
    key: "visibility",
    labelKey: "sidebar.sections.visibility",
    sections: [
      { key: "inventory", labelKey: "sidebar.sec.inventory", icon: "registry", pages: [
        P("/inventory", "inventory"),
        P("/providers", "providers"),
        P("/connections", "connections"),
        P("/use-cases", "use_cases", { more: true }),
      ] },
      { key: "agents", labelKey: "sidebar.sec.agents", icon: "agent", pages: [
        P("/agents", "agents"),
        P("/teams", "teams", { more: true }),
        P("/tool-registry", "tool_registry", { adminOnly: true, more: true }),
        P("/agent-identity", "agent_identity", { adminOnly: true, more: true }),
        P("/attestation", "attestation", { adminOnly: true, more: true }),
        P("/agent-behavior", "agent_behavior", { adminOnly: true, more: true }),
        P("/agent-breaker", "agent_breaker", { adminOnly: true, more: true }),
      ] },
      { key: "discovery", labelKey: "sidebar.sec.discovery", icon: "discovery", pages: [
        P("/agents-found", "agents_found", { reviewOnly: true }),
        P("/devices", "devices", { reviewOnly: true }),
        P("/discovery", "discovery", { adminOnly: true }),
      ] },
      { key: "shadow_ai", labelKey: "sidebar.sec.shadow_ai", icon: "security", pages: [
        P("/shadow-ai", "shadow_ai"),
        P("/domain-catalog", "domain_catalog", { adminOnly: true, more: true }),
      ] },
      { key: "monitoring", labelKey: "sidebar.sec.monitoring", icon: "activity", pages: [
        P("/agent-observability", "agent_observability"),
        P("/agent-map", "agent_map"),
        P("/agent-chains", "agent_chains"),
      ] },
    ],
  },
  {
    key: "control",
    labelKey: "sidebar.sections.control",
    sections: [
      { key: "policies", labelKey: "sidebar.sec.policies", icon: "policies", pages: [
        P("/policy-hierarchy", "policy_hierarchy", { reviewOnly: true }),
        P("/agent-policies", "agent_policies", { adminOnly: true }),
      ] },
      { key: "compliance", labelKey: "sidebar.sec.compliance", icon: "compliance", pages: [P("/compliance", "compliance")] },
      { key: "gateways", labelKey: "sidebar.sec.gateways", icon: "gateway", pages: [
        P("/gateway", "gateway", { adminOnly: true }),
        P("/runtime", "runtime", { adminOnly: true }),
      ] },
    ],
  },
  {
    key: "evidence",
    labelKey: "sidebar.sections.evidence",
    sections: [
      { key: "audit", labelKey: "sidebar.sec.audit", icon: "audit", pages: [P("/audit", "audit")] },
    ],
  },
  {
    key: "settings",
    labelKey: "sidebar.sections.settings",
    sections: [
      { key: "users", labelKey: "sidebar.sec.users", icon: "users", pages: [P("/users", "users", { adminOnly: true })] },
      { key: "settings", labelKey: "sidebar.sec.settings", icon: "settings", pages: [
        P("/profile", "profile"),
        P("/notifications", "notifications", { adminOnly: true }),
        P("/system-status", "system_status", { adminOnly: true }),
        P("/observability", "observability", { operatorOnly: true }),
        P("/export-keys", "export_keys", { adminOnly: true, more: true }),
        P("/encryption-keys", "encryption_keys", { adminOnly: true, more: true }),
        P("/retention", "retention", { adminOnly: true, more: true }),
        P("/ingestion-sources", "ingestion_sources", { adminOnly: true, more: true }),
      ] },
    ],
  },
];

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

/** The groups and sections this role sees, each section with its visible
 *  pages only (its "more" pages after its main ones). A section is shown when
 *  one of its main pages is visible. */
export function visibleNav(role: Role, operator = false): NavGroup[] {
  return NAV.map((g) => ({
    ...g,
    sections: g.sections
      .map((s) => {
        const pages = s.pages.filter((p) => canSee(p, role, operator));
        return { ...s, pages: [...pages.filter((p) => !p.more), ...pages.filter((p) => p.more)] };
      })
      .filter((s) => s.pages.some((p) => !p.more)),
  })).filter((g) => g.sections.length > 0);
}

export function sectionOf(
  pathname: string | null | undefined,
  role: Role,
  operator = false,
): NavSection | undefined {
  for (const g of visibleNav(role, operator)) {
    for (const s of g.sections) {
      if (s.pages.some((p) => pageMatches(p.href, pathname))) return s;
    }
  }
  return undefined;
}
