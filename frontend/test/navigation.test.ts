import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SECTIONS, canOpen, canSee, homeFor, sectionOf, visibleSections } from "@/lib/navigation";

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
