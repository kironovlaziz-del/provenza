// The console's mode (lib/console_mode.ts): simple unless the person chose
// the full console in this browser; a change shows everywhere at once.
import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MODE_KEY, loadMode, saveMode, useConsoleMode } from "@/lib/console_mode";

function Show() {
  const [mode] = useConsoleMode();
  return <span>{mode}</span>;
}

describe("console mode", () => {
  it("is simple by default", () => {
    expect(loadMode()).toBe("simple");
  });

  it("keeps the full console once chosen, and goes back", () => {
    saveMode("full");
    expect(window.localStorage.getItem(MODE_KEY)).toBe("full");
    expect(loadMode()).toBe("full");
    saveMode("simple");
    expect(loadMode()).toBe("simple");
  });

  it("treats an unknown stored value as simple", () => {
    window.localStorage.setItem(MODE_KEY, "something");
    expect(loadMode()).toBe("simple");
  });

  it("is simple when the browser refuses storage", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("denied"); });
    expect(loadMode()).toBe("simple");
  });

  it("updates every component at once, here and from another tab", () => {
    render(<Show />);
    expect(screen.getByText("simple")).toBeTruthy();
    act(() => saveMode("full"));
    expect(screen.getByText("full")).toBeTruthy();
    act(() => {
      window.localStorage.setItem(MODE_KEY, "simple");
      window.dispatchEvent(new StorageEvent("storage", { key: MODE_KEY }));
    });
    expect(screen.getByText("simple")).toBeTruthy();
  });
});
