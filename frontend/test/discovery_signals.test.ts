import { describe, expect, it } from "vitest";
import { portSignal, SHOWN_MODELS } from "@/lib/discovery_signals";

describe("what answered on a local model port", () => {
  it("a confirmed model API with its models, the first few shown", () => {
    const models = Array.from({ length: SHOWN_MODELS + 3 }, (_, i) => `m${i}`);
    const s = portSignal({ kind: "network", port: 11434, confirmed: true, api: "Ollama", models });
    expect(s).toEqual({ confirmed: true, api: "Ollama", models: models.slice(0, SHOWN_MODELS), more: 3 });
  });

  it("a port where no model API answered", () => {
    expect(portSignal({ kind: "network", confirmed: false, api: "Ollama", models: ["x"] })).toEqual({
      confirmed: false, api: null, models: ["x"], more: 0,
    });
  });

  it("nothing for older agents, other kinds, or odd values", () => {
    expect(portSignal({ kind: "network", port: 8080 })).toBeNull();
    expect(portSignal({ kind: "process", confirmed: true })).toBeNull();
    expect(portSignal(null)).toBeNull();
    expect(portSignal({ kind: "network", confirmed: "yes" })).toBeNull();
    expect(portSignal({ kind: "network", confirmed: true, api: 7, models: [1, "a"] })).toEqual({
      confirmed: true, api: null, models: ["a"], more: 0,
    });
  });
});
