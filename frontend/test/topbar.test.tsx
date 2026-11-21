// The top bar (components/TopBar.tsx) in both modes: simple mode's tabs, what
// waits for a decision and whether the protection works; the full console's
// tabs without them.
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TopBar } from "@/components/TopBar";
import { saveMode } from "@/lib/console_mode";
import i18n from "@/lib/i18n";

let role = "admin";
let summary = { ok: 3, attention: 1, missing: 1, needs_action: 1 };
vi.mock("next/navigation", () => ({ usePathname: () => "/agents", useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role, name: "A", email: "a@provenza.dev" }, logout: vi.fn() }) }));
vi.mock("@/lib/approvals_api", () => ({ listPendingApprovals: async () => [{ id: 1 }, { id: 2 }] }));
vi.mock("@/lib/kill_switch_api", () => ({ killOverview: async () => ({ active: [] }) }));
vi.mock("@/lib/agent_api", () => ({ listAgentIncidents: async () => ({ items: [], total: 1 }) }));
vi.mock("@/lib/api", () => ({
  listIncidentsPage: async () => ({ items: [{ status: "open" }, { status: "resolved" }, { status: "investigating" }], total: 3 }),
  api: { get: async () => ({ data: { coverage: { items: [], summary } } }) },
}));

const nav = () => screen.getAllByRole("navigation", { name: "Main" })[0];

describe("top bar", () => {
  it("shows simple mode's tabs, the waiting count and the protection", async () => {
    render(<TopBar />);
    const tabs = within(nav()).getAllByRole("link").map((a) => a.textContent);
    expect(tabs).toEqual(["AI agents", "Rules", "Audit log", "Shadow AI"]);
    // 2 approvals + 2 open platform incidents + 1 unresolved agent incident
    const bell = await screen.findByRole("link", { name: "5 items are waiting for a decision" });
    expect(bell.getAttribute("href")).toBe("/inbox");
    const shield = await screen.findByText("Needs attention");
    expect(shield.closest("a")?.getAttribute("href")).toBe("/settings");
    expect(screen.getByRole("link", { name: /Stop all/ }).getAttribute("href")).toBe("/kill-switch");
  });

  it("says the protection works when only optional parts are missing", async () => {
    summary = { ok: 4, attention: 0, missing: 2, needs_action: 0 };
    render(<TopBar />);
    expect(await screen.findByText("Protected")).toBeTruthy();
    summary = { ok: 3, attention: 1, missing: 1, needs_action: 1 };
  });

  it("shows no protection to a non-admin, and nothing waiting to a plain user", async () => {
    role = "approver";
    const { unmount } = render(<TopBar />);
    await screen.findByRole("link", { name: "5 items are waiting for a decision" });
    expect(screen.queryByText("Needs attention")).toBeNull();
    expect(screen.queryByRole("link", { name: /Stop all/ })).toBeNull();
    unmount();
    role = "user";
    render(<TopBar />);
    expect(within(nav()).getAllByRole("link").map((a) => a.textContent)).toEqual(["AI agents", "Shadow AI"]);
    expect(screen.queryByRole("link", { name: /waiting for a decision/ })).toBeNull();
    role = "admin";
  });

  it("switches to the full console's tabs at once", async () => {
    render(<TopBar />);
    await screen.findByText("Needs attention");
    act(() => saveMode("full"));
    await waitFor(() =>
      expect(within(nav()).getAllByRole("link").map((a) => a.textContent?.replace(/\d+$/, "")))
        .toEqual(["Inbox", "AI", "Rules", "Evidence"]));
    expect(screen.queryByText("Needs attention")).toBeNull();
    expect(screen.queryByRole("link", { name: /waiting for a decision/ })).toBeNull();
  });

  it("says so when nothing waits", () => {
    expect(i18n.t("nav.simple.waiting", { count: 0 })).toBe("Nothing is waiting for a decision");
    expect(i18n.t("nav.simple.waiting", { count: 1 })).toBe("1 item is waiting for a decision");
  });

  it("finds every page in search, also those simple mode does not show", async () => {
    render(<TopBar />);
    fireEvent.click(screen.getByRole("button", { name: "Search" }));
    const box = screen.getByRole("dialog");
    expect(within(box).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "AgentsAI agents", "Policy hierarchyRules", "Audit LogAudit log", "Shadow AI SightingsShadow AI",
      "All settingsSettings", "HelpHelp"]);
    fireEvent.change(within(box).getByRole("textbox"), { target: { value: "kill" } });
    expect(within(box).getAllByRole("option").map((o) => o.textContent)).toEqual(["Kill switchEvidence"]);
  });
});
