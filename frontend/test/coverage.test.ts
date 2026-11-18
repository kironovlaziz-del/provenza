import { describe, expect, it } from "vitest";
import en from "@/locales/en.json";
import uz from "@/locales/uz.json";
import { evidence, needsDashboard, type CoverageItem } from "@/lib/coverage";

const item = (key: string, state: CoverageItem["state"], facts: CoverageItem["facts"] = {}): CoverageItem =>
  ({ key, state, href: "/", optional: false, facts });

describe("evidence", () => {
  it("says why a signed policy needs attention", () => {
    expect(evidence(item("signed_policy", "attention", { number: 3, draft: 4, unsigned: 0, problem: false })).key)
      .toBe("signed_policy.attention_draft");
    expect(evidence(item("signed_policy", "attention", { number: 3, draft: null, unsigned: 2, problem: false })))
      .toEqual({ key: "signed_policy.attention_unsigned", values: { number: 3, draft: null, unsigned: 2, problem: false, count: 2 } });
    expect(evidence(item("signed_policy", "attention", { number: 3, draft: 4, unsigned: 2, problem: true })).key)
      .toBe("signed_policy.attention_problem");
  });
  it("tells a proxy waiting for its policy from one that is offline", () => {
    expect(evidence(item("proxy", "attention", { total: 1, online: 1, policy: false })).key).toBe("proxy.attention_policy");
    expect(evidence(item("proxy", "attention", { total: 2, online: 1, policy: true })).key).toBe("proxy.attention_offline");
  });
  it("uses the plain sentences otherwise", () => {
    expect(evidence(item("agents_confined", "attention")).key).toBe("agents_confined.attention");
    expect(evidence(item("browsers", "ok")).key).toBe("browsers.ok");
    expect(evidence(item("sensors", "missing")).key).toBe("sensors.missing");
  });
});

describe("needsDashboard", () => {
  it("shows on the dashboard only when something set up stopped working", () => {
    expect(needsDashboard({ ok: 3, attention: 0, missing: 4, needs_action: 2 })).toBe(false);
    expect(needsDashboard({ ok: 3, attention: 1, missing: 3, needs_action: 1 })).toBe(true);
    expect(needsDashboard(undefined)).toBe(false);
  });
});

describe("the sentences", () => {
  const keys = ["signed_policy", "proxy", "agents_signing", "agents_confined", "sensors", "endpoint_agents", "browsers"];
  const sentences = (k: string) => {
    if (k === "signed_policy") return ["ok", "missing", "attention_problem", "attention_draft", "attention_unsigned_one", "attention_unsigned_other"];
    if (k === "proxy") return ["ok", "missing", "attention_policy", "attention_offline"];
    return ["ok", "missing", "attention"];
  };
  for (const [name, loc] of [["en", en], ["uz", uz]] as const) {
    it(`exist in ${name}`, () => {
      const c = (loc as unknown as { coverage: Record<string, Record<string, string>> }).coverage;
      for (const k of keys) {
        expect(c[k].title, `${name} ${k}.title`).toBeTruthy();
        expect(c[k].fix, `${name} ${k}.fix`).toBeTruthy();
        for (const s of sentences(k)) expect(c[k][s], `${name} ${k}.${s}`).toBeTruthy();
      }
    });
  }
});
