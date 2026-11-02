// The commands that install the endpoint agent on a workstation
// (agent/install/install-agent.{sh,ps1}, served by this control plane with
// the agent binaries at /api/v1/egress-sensor/download/). The key is not
// in them: the script asks for it with the input hidden.

export type AgentOS = "windows" | "macos" | "linux";

export const AGENT_OSES: AgentOS[] = ["windows", "macos", "linux"];

/** The control plane's origin: the configured API URL when set (the
 *  canonical domain), else the address the admin is on. */
export function controlPlaneOrigin(): string {
  const envURL = process.env.NEXT_PUBLIC_API_URL || "";
  return envURL.replace(/\/api\/v1\/?$/, "").replace(/\/$/, "") ||
    (typeof window !== "undefined" ? window.location.origin : "");
}

export function agentInstallCommand(os: AgentOS, origin: string): string {
  const base = `${origin}/api/v1/egress-sensor/download`;
  if (os === "windows") {
    // PowerShell as administrator; a script block, so no execution-policy change
    return `$s='${origin}'; & ([scriptblock]::Create((irm "$s/api/v1/egress-sensor/download/install-agent.ps1"))) -Server $s`;
  }
  return `f=$(mktemp) && curl -fsSL ${base}/install-agent.sh -o "$f" && sudo sh "$f" --server ${origin}`;
}
