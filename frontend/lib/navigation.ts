// The console's navigation, in one place: the sidebar lists sections, and a
// section with several pages shows them as tabs under the page title
// (components/PageHeader.tsx). Pages keep their own URLs.
//
// adminOnly: admins; reviewOnly: admins and approvers. A section is shown when
// the user may open at least one of its pages; it links to the first of them.

export type Role = "admin" | "approver" | "user" | string | undefined;

export interface NavPage {
  href: string;
  labelKey: string;
  adminOnly?: boolean;
  reviewOnly?: boolean;
  /** Optional feature flag; when the flag is off the page is hidden. */
  feature?: "content_safety";
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
      { key: "approvals", labelKey: "sidebar.sec.approvals", icon: "check", pages: [P("/approvals", "approvals")] },
      { key: "kill_switch", labelKey: "sidebar.nav.kill_switch", icon: "stop",
        pages: [P("/kill-switch", "kill_switch", { reviewOnly: true })] },
    ],
  },
  {
    key: "visibility",
    labelKey: "sidebar.sections.visibility",
    sections: [
      { key: "discovery", labelKey: "sidebar.sec.discovery", icon: "discovery", pages: [
        P("/agents-found", "agents_found", { reviewOnly: true }),
        P("/shadow-ai", "shadow_ai"),
        P("/devices", "devices", { reviewOnly: true }),
        P("/discovery", "discovery", { adminOnly: true }),
        P("/domain-catalog", "domain_catalog", { adminOnly: true }),
      ] },
      { key: "monitoring", labelKey: "sidebar.sec.monitoring", icon: "activity", pages: [
        P("/agent-observability", "agent_observability"),
        P("/agent-map", "agent_map"),
        P("/agent-chains", "agent_chains"),
        P("/observability", "observability", { adminOnly: true }),
      ] },
      { key: "inventory", labelKey: "sidebar.sec.inventory", icon: "registry", pages: [
        P("/inventory", "inventory"),
        P("/use-cases", "use_cases"),
        P("/providers", "providers"),
        P("/connections", "connections"),
      ] },
      { key: "agents", labelKey: "sidebar.sec.agents", icon: "agent", pages: [
        P("/agents", "agents"),
        P("/teams", "teams"),
        P("/agent-identity", "agent_identity", { adminOnly: true }),
        P("/attestation", "attestation", { adminOnly: true }),
        P("/tool-registry", "tool_registry", { adminOnly: true }),
      ] },
    ],
  },
  {
    key: "control",
    labelKey: "sidebar.sections.control",
    sections: [
      { key: "policies", labelKey: "sidebar.sec.policies", icon: "policies", pages: [
        P("/policies", "policies"),
        P("/policy-hierarchy", "policy_hierarchy", { reviewOnly: true }),
        P("/agent-policies", "agent_policies", { adminOnly: true }),
        P("/pii-rules", "pii_rules", { reviewOnly: true, feature: "content_safety" }),
        P("/blocked-terms", "blocked_terms", { reviewOnly: true, feature: "content_safety" }),
        P("/intent-guardrail", "intent_guardrail", { adminOnly: true, feature: "content_safety" }),
        P("/compliance", "compliance"),
      ] },
      { key: "protection", labelKey: "sidebar.sec.protection", icon: "security", pages: [
        P("/agent-injection", "agent_injection", { adminOnly: true, feature: "content_safety" }),
        P("/agent-code-exec", "agent_code_exec", { adminOnly: true, feature: "content_safety" }),
        P("/agent-memory", "agent_memory", { adminOnly: true, feature: "content_safety" }),
        P("/agent-messages", "agent_messages", { adminOnly: true, feature: "content_safety" }),
        P("/agent-behavior", "agent_behavior", { adminOnly: true }),
        P("/agent-breaker", "agent_breaker", { adminOnly: true }),
      ] },
      { key: "gateways", labelKey: "sidebar.sec.gateways", icon: "gateway", pages: [
        P("/gateway", "gateway", { adminOnly: true }),
        P("/runtime", "runtime", { adminOnly: true }),
        P("/provider-chat", "provider_chat"),
      ] },
    ],
  },
  {
    key: "evidence",
    labelKey: "sidebar.sections.evidence",
    sections: [
      { key: "audit", labelKey: "sidebar.sec.audit", icon: "audit", pages: [
        P("/audit", "audit"),
        P("/requests", "requests"),
      ] },
    ],
  },
  {
    key: "settings",
    labelKey: "sidebar.sections.settings",
    sections: [
      { key: "settings", labelKey: "sidebar.sec.settings", icon: "settings", pages: [
        P("/profile", "profile"),
        P("/users", "users", { adminOnly: true }),
        P("/notifications", "notifications", { adminOnly: true }),
        P("/ingestion-sources", "ingestion_sources", { adminOnly: true }),
        P("/encryption-keys", "encryption_keys", { adminOnly: true }),
        P("/queue-ttl", "queue_ttl", { adminOnly: true }),
        P("/system-status", "system_status", { adminOnly: true }),
      ] },
    ],
  },
];

export function canSee(
  page: NavPage,
  role: Role,
  features: { content_safety: boolean } = { content_safety: true },
): boolean {
  if (page.feature && !features[page.feature]) return false;
  if (page.adminOnly) return role === "admin";
  if (page.reviewOnly) return role === "admin" || role === "approver";
  return true;
}

export function pageMatches(href: string, pathname: string | null | undefined): boolean {
  return !!pathname && (pathname === href || pathname.startsWith(href + "/"));
}

/** The groups and sections this role sees, each section with its visible pages only. */
export function visibleNav(
  role: Role,
  features: { content_safety: boolean } = { content_safety: true },
): NavGroup[] {
  return NAV.map((g) => ({
    ...g,
    sections: g.sections
      .map((s) => ({ ...s, pages: s.pages.filter((p) => canSee(p, role, features)) }))
      .filter((s) => s.pages.length > 0),
  })).filter((g) => g.sections.length > 0);
}

export function sectionOf(
  pathname: string | null | undefined,
  role: Role,
  features: { content_safety: boolean } = { content_safety: true },
): NavSection | undefined {
  for (const g of visibleNav(role, features)) {
    for (const s of g.sections) {
      if (s.pages.some((p) => pageMatches(p.href, pathname))) return s;
    }
  }
  return undefined;
}
