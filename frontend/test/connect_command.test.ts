import { describe, expect, it } from "vitest";
import { connectCommand } from "@/components/ConnectPanel";

describe("Agents -> Connect command", () => {
  it("is the sh one-liner for Linux, by default", () => {
    const sh = connectCommand("pvz_enr_abc", "cursor");
    expect(sh).toMatch(/^f=\$\(mktemp\) && curl -fsSL .*\/api\/v1\/agent-enrollment\/connect\.sh -o "\$f" && sh "\$f" cursor pvz_enr_abc$/);
    expect(connectCommand("pvz_enr_abc", "cursor", "linux")).toBe(sh);
  });

  it("is a PowerShell script block for Windows: no execution-policy change, the token as a named parameter", () => {
    const ps = connectCommand("pvz_enr_abc", "claude-code", "windows");
    expect(ps).toMatch(/^& \(\[scriptblock\]::Create\(\(irm ".*\/api\/v1\/agent-enrollment\/connect\.ps1"\)\)\) -Client claude-code -Token pvz_enr_abc$/);
    expect(ps).not.toMatch(/ExecutionPolicy|Bypass|iex|\| /i);
  });
});
