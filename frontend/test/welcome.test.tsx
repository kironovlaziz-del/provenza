// The welcome page at / (components/Welcome.tsx): its texts exist in every
// language, the call it plays runs through both scenarios, and it leads to
// the sign-in page.
import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import en from "@/locales/en.json";
import uz from "@/locales/uz.json";
import { Welcome, nextCall } from "@/components/Welcome";

type Tree = { [k: string]: unknown };

function shape(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(shape);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v as Tree).sort().map((k) => [k, shape((v as Tree)[k])]));
  return typeof v;
}

describe("welcome page", () => {
  it("has the same texts in English and Uzbek", () => {
    expect(shape(uz.welcome)).toEqual(shape(en.welcome));
    expect(en.welcome.caps).toHaveLength(8);
    for (const e of [...en.welcome.events, ...uz.welcome.events]) expect(["solid", "ghost", "dash"]).toContain(e.kind);
  });

  it("plays eight steps, holds the last one, then the other scenario", () => {
    let c = { mode: "allow" as const, step: 0, hold: 0 } as ReturnType<typeof nextCall>;
    for (let i = 0; i < 7; i++) c = nextCall(c);
    expect(c).toEqual({ mode: "allow", step: 7, hold: 0 });
    for (let i = 0; i < 3; i++) c = nextCall(c);
    expect(c.step).toBe(7);
    c = nextCall(c);
    expect(c).toEqual({ mode: "deny", step: 0, hold: 0 });
  });

  it("leads to the sign-in page and shows the refusal", async () => {
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    render(<Welcome />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("Every AI agent is checked before it acts.");
    const signIn = screen.getAllByRole("link").filter((a) => a.getAttribute("href") === "/login");
    expect(signIn.length).toBeGreaterThanOrEqual(3);
    act(() => screen.getByRole("button", { name: "Refused by policy" }).click());
    expect(screen.getByRole("button", { name: "Refused by policy" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText("Scenario: refused by policy")).toBeTruthy();
  });
});
