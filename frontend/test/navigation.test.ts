import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SECTIONS, SIMPLE_SECTIONS, canOpen, canSee, homeFor, isReviewer, sectionOf, visibleSections } from "@/lib/navigation";

const APP = join(__dirname, "..", "app", "(app)");
const ROUTES = readdirSync(APP).filter((d) => statSync(join(APP, d)).isDirectory()).map((d) => `/${d}`);
// redirects only: they send the visitor to a page that is in the navigation
const REDIRECTS = ["/dashboard"];

describe("navigation", () => {
  it("reaches every page of the console", () => {
    const listed = new Set(SECTIONS.flatMap((s) => s.pages.map((p) => p.href)));
    expect(ROUTES.filter((r) => !listed.has(r) && !REDIRECTS.includes(r))).toEqual([]);
    expect([...listed].filter((h) => !ROUTES.includes(h))).toEqual([]);
  });

  it("shows four tabs, then Settings and Help", () => {
    expect(SECTIONS.filter((s) => !s.utility).map((s) => s.key)).toEqual(["inbox", "ai", "rules", "evidence"]);
    expect(SECTIONS.filter((s) => s.utility).map((s) => s.key)).toEqual(["settings", "help"]);
  });

  it("starts a plain user on the AI list and everyone else on the Inbox", () => {
    expect(homeFor("user")).toBe("/inventory");
    for (const r of ["admin", "approver", "auditor", "compliance"]) expect(homeFor(r)).toBe("/inbox");
    expect(visibleSections("user").map((s) => s.key)).toEqual(["ai", "settings", "help"]);
  });

  it("keeps the role rules", () => {
    const page = (href: string) => SECTIONS.flatMap((s) => s.pages).find((p) => p.href === href)!;
    expect(canSee(page("/audit"), "user")).toBe(false);
    expect(canSee(page("/incidents"), "user")).toBe(false);
    expect(canSee(page("/users"), "approver")).toBe(false);
    expect(canSee(page("/users"), "auditor")).toBe(true);
    expect(canSee(page("/observability"), "admin", false)).toBe(false);
    expect(canSee(page("/observability"), "admin", true)).toBe(true);
  });

  it("answers no access for a page the role does not see", () => {
    expect(canOpen("/audit", "user")).toBe(false);
    expect(canOpen("/runtime", "approver")).toBe(false);
    expect(canOpen("/agents/12", "user")).toBe(true);
    expect(canOpen("/dashboard", "user")).toBe(true);
    expect(canOpen("/help/faq", "user")).toBe(true);
  });

  it("finds the section of a help article", () => {
    expect(sectionOf("/help/faq", "user")?.key).toBe("help");
    expect(sectionOf("/users", "admin")?.key).toBe("settings");
  });
});

describe("simple mode navigation", () => {
  const full = (href: string) => SECTIONS.flatMap((s) => s.pages).find((p) => p.href === href);

  it("shows four tabs, then Settings and Help", () => {
    expect(SIMPLE_SECTIONS.filter((s) => !s.utility).map((s) => s.key)).toEqual(["agents", "rules", "audit", "shadow"]);
    expect(SIMPLE_SECTIONS.filter((s) => s.utility).map((s) => s.key)).toEqual(["settings", "help"]);
  });

  it("uses pages of the full console with the same role rules", () => {
    for (const p of SIMPLE_SECTIONS.flatMap((s) => s.pages)) {
      const f = full(p.href)!;
      expect(f, p.href).toBeTruthy();
      expect([p.adminOnly, p.reviewOnly, p.operatorOnly]).toEqual([f.adminOnly, f.reviewOnly, f.operatorOnly]);
      expect(p.more).toBe(false);
    }
  });

  it("shows each role what it may open", () => {
    const keys = (role: string) => visibleSections(role, false, "simple").map((s) => s.key);
    expect(keys("user")).toEqual(["agents", "shadow", "settings", "help"]);
    expect(keys("approver")).toEqual(["agents", "rules", "audit", "shadow", "settings", "help"]);
    expect(keys("admin")).toEqual(["agents", "rules", "audit", "shadow", "settings", "help"]);
    const pages = (role: string, key: string) =>
      visibleSections(role, false, "simple").find((s) => s.key === key)!.pages.map((p) => p.href);
    expect(pages("approver", "rules")).toEqual(["/policy-hierarchy"]);
    expect(pages("admin", "rules")).toEqual(["/policy-hierarchy", "/gateway"]);
    expect(pages("user", "settings")).toEqual(["/settings", "/profile"]);
    expect(pages("admin", "settings")).toEqual(["/settings", "/profile", "/users", "/notifications"]);
  });

  it("starts everyone on the agents", () => {
    for (const r of ["user", "admin", "approver", "auditor", "compliance"]) expect(homeFor(r, "simple")).toBe("/agents");
  });

  it("finds a page's section, and none for a page it does not show", () => {
    expect(sectionOf("/gateway", "admin", false, "simple")?.key).toBe("rules");
    expect(sectionOf("/agents/12", "user", false, "simple")?.key).toBe("agents");
    expect(sectionOf("/agents-found", "admin", false, "simple")).toBeUndefined();
    expect(sectionOf("/inbox", "admin", false, "simple")).toBeUndefined();
  });

  it("still opens every page by its address", () => {
    expect(canOpen("/inbox", "admin")).toBe(true);
    expect(canOpen("/runtime", "admin")).toBe(true);
    expect(canOpen("/kill-switch", "approver")).toBe(true);
  });

  it("knows who decides or oversees", () => {
    for (const r of ["admin", "approver", "auditor", "compliance"]) expect(isReviewer(r)).toBe(true);
    expect(isReviewer("user")).toBe(false);
    expect(isReviewer(undefined)).toBe(false);
  });
});
