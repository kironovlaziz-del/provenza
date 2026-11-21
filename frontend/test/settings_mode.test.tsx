// Settings (app/(app)/settings/page.tsx): simple mode lists the settings for
// you and for people, and switches to the full console, which lists them all.
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import SettingsPage from "@/app/(app)/settings/page";
import { loadMode } from "@/lib/console_mode";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings" }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role: "admin" } }) }));
vi.mock("@/components/SetupChecklist", () => ({ SetupChecklist: () => null }));

const groups = () => screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);

describe("settings and the console's mode", () => {
  it("lists simple mode's settings and opens the full console", () => {
    render(<SettingsPage />);
    expect(screen.getByText("Simple mode")).toBeTruthy();
    expect(groups()).toEqual(["You", "People and notifications"]);
    fireEvent.click(screen.getByRole("button", { name: "Open the full console" }));
    expect(loadMode()).toBe("full");
    expect(screen.getByText("Full console")).toBeTruthy();
    expect(groups()).toEqual(["You", "People and notifications", "Gateways, sensors and agent identity",
      "Keys and data", "System"]);
    fireEvent.click(screen.getByRole("button", { name: "Back to simple mode" }));
    expect(loadMode()).toBe("simple");
  });
});
