import { describe, expect, it } from "vitest";
import { fmtAge, fmtLatency, fmtPercent, fmtRate } from "@/components/observability/format";

describe("monitoring formatters", () => {
  it("shows missing values as a dash, never as 0", () => {
    expect(fmtRate(null)).toBe("—");
    expect(fmtLatency(NaN)).toBe("—");
    expect(fmtAge(undefined)).toBe("—");
  });
  it("formats latency in ms below a second", () => {
    expect(fmtLatency(0.0123)).toBe("12 ms");
    expect(fmtLatency(0.0042)).toBe("4.2 ms");
  });
  it("formats ages in plain units", () => {
    expect(fmtAge(27.68)).toBe("28 s");
    expect(fmtAge(240)).toBe("4 min");
    expect(fmtAge(3 * 3600 + 300)).toBe("3 h 5 min");
    expect(fmtAge(5 * 86400)).toBe("5 d");
  });
  it("keeps small percentages honest", () => {
    expect(fmtPercent(0)).toBe("0 %");
    expect(fmtPercent(0.04)).toBe("<0.1 %");
  });
});
