// After signing in, the visitor comes back to the page that sent them to
// /login - only when that is a path of this site (no open redirect).
import { describe, expect, it } from "vitest";
import { loginUrl, nextAfterLogin } from "@/lib/auth";

function at(url: string) {
  window.history.replaceState(null, "", url);
}

describe("nextAfterLogin", () => {
  it("returns to the page that asked for the sign-in", () => {
    at("/login?next=" + encodeURIComponent("/inventory?stage=production"));
    expect(nextAfterLogin()).toBe("/inventory?stage=production");
  });

  it("goes to the dashboard for anything that is not a path of this site", () => {
    for (const next of ["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)",
                        "/login", "/login?next=/x", "", "inventory"]) {
      at("/login?next=" + encodeURIComponent(next));
      expect(nextAfterLogin(), next).toBe("/dashboard");
    }
    at("/login");
    expect(nextAfterLogin()).toBe("/dashboard");
  });
});

describe("loginUrl", () => {
  it("remembers where the visitor was", () => {
    at("/agents?tab=found");
    expect(loginUrl()).toBe("/login?next=" + encodeURIComponent("/agents?tab=found"));
    at("/");
    expect(loginUrl()).toBe("/login");
  });
});
