// Shadow AI -> What works (components/ShadowSources.tsx): the sources that feed
// Shadow AI with the protection coverage's state, for admins only.
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ShadowSources } from "@/components/ShadowSources";

let role = "admin";
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role } }) }));
vi.mock("@/lib/api", () => ({
  api: {
    get: async () => ({
      data: {
        coverage: {
          items: [
            { key: "signed_policy", state: "ok", href: "/policy-hierarchy", optional: false, facts: { number: 3 } },
            { key: "endpoint_agents", state: "attention", href: "/ingestion-sources", optional: true,
              facts: { sources: 1, devices: 4, reporting: 0 } },
            { key: "browsers", state: "ok", href: "/ingestion-sources", optional: true,
              facts: { sources: 1, devices: 12, reporting: 9 } },
          ],
        },
      },
    }),
  },
}));

describe("shadow AI: what works", () => {
  it("shows the browser extension, the endpoint agent and the log import", async () => {
    const onImport = vi.fn();
    render(<ShadowSources onImport={onImport} />);
    expect(await screen.findByText("What works")).toBeTruthy();
    const rows = screen.getAllByRole("listitem");
    expect(rows.map((r) => r.querySelector("b")?.textContent)).toEqual([
      "Browser extension", "Endpoint agent on computers", "DNS and proxy logs"]);
    expect(rows[0].textContent).toContain("9 of 12 browsers reported this week.");
    expect(rows[0].querySelector("a")).toBeNull();
    expect(rows[1].textContent).toContain("No computer has reported in the last 2 hours (4 known).");
    expect(rows[1].querySelector("a")?.getAttribute("href")).toBe("/ingestion-sources");
    expect(screen.queryByText(/Signed policy/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Import logs" }));
    expect(onImport).toHaveBeenCalledTimes(1);
  });

  it("is not shown to other roles", () => {
    role = "approver";
    const { container } = render(<ShadowSources />);
    expect(container.innerHTML).toBe("");
    role = "admin";
  });
});
