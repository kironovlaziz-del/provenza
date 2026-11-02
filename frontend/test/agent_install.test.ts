import { describe, expect, it } from "vitest";
import { agentInstallCommand } from "@/lib/agent_install";

const O = "https://provenza.example.com";

describe("endpoint agent install commands", () => {
  it("fetches the script from this control plane and never carries the key", () => {
    const win = agentInstallCommand("windows", O);
    expect(win).toContain(`$s='${O}'`);
    expect(win).toContain("/api/v1/egress-sensor/download/install-agent.ps1");
    expect(win).toContain("-Server $s");
    for (const os of ["macos", "linux"] as const) {
      const sh = agentInstallCommand(os, O);
      expect(sh).toBe(`f=$(mktemp) && curl -fsSL ${O}/api/v1/egress-sensor/download/install-agent.sh -o "$f" && sudo sh "$f" --server ${O}`);
    }
    for (const os of ["windows", "macos", "linux"] as const) {
      expect(agentInstallCommand(os, O)).not.toMatch(/--key|-Key/);
    }
  });
});
