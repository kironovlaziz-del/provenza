import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import en from "@/locales/en.json";
import uz from "@/locales/uz.json";
import { packFileName } from "@/lib/policy_packs_api";

describe("packFileName", () => {
  it("makes a safe YAML file name", () => {
    expect(packFileName("Guard: no exports / prod")).toBe("guard-no-exports-prod.yaml");
    expect(packFileName("../../etc")).toBe("etc.yaml");
    expect(packFileName("Ҳимоя")).toBe("rule-pack.yaml");
  });
});

describe("rule pack strings", () => {
  it("has the same keys in both languages", () => {
    expect(Object.keys(uz.packs).sort()).toEqual(Object.keys(en.packs).sort());
  });
  it("has every key the component uses", () => {
    const src = readFileSync("components/RulePacks.tsx", "utf8");
    const used = new Set([...src.matchAll(/"packs\.([a-z_]+)"/g)].map((m) => m[1]));
    for (const k of ["level_any", "level_org", "level_team", "level_agent", "kind_guard", "kind_profile"]) used.add(k);
    for (const k of used) expect(en.packs, k).toHaveProperty(k);
  });
  it("translates every pack error the backend returns", () => {
    const backend = readFileSync("../backend/app/services/rule_packs.py", "utf8");
    const codes = new Set([...backend.matchAll(/"(pack\.[a-z_]+)"/g)].map((m) => m[1]));
    expect(codes.size).toBeGreaterThan(5);
    for (const c of codes) {
      expect(en.errors, c).toHaveProperty([c]);
      expect(uz.errors, c).toHaveProperty([c]);
    }
  });
});
