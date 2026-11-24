// The agent's page -> Network (components/AgentNetwork.tsx): what it says
// before the agent runs under the sensor, the destinations it went to, and
// enforcing the checked ones - and only those.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentNetwork } from "@/components/AgentNetwork";
import type { AgentNetworkWorkloadT } from "@/lib/agent_network_api";

vi.mock("@/components/Dialog", () => ({ confirmDialog: async () => true }));
vi.mock("next/link", () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));

const api = vi.hoisted(() => ({
  getAgentNetwork: vi.fn(), observeAgentNetwork: vi.fn(), enforceAgentNetwork: vi.fn(),
  attachAgentUnit: vi.fn(), detachAgentUnit: vi.fn(),
}));
vi.mock("@/lib/agent_network_api", () => api);

const workload = (mode: "observe" | "enforce", allow: AgentNetworkWorkloadT["egress_allow"] = [], patterns: string[] = []) =>
  ({ id: 11, name: "agent-7", mode, dns: "any" as const, enabled: true, isolated: false, egress_allow: allow,
     cgroup_patterns: patterns });
const dest = (d: string, port: number, named = true) =>
  ({ dest: d, port, protocol: "tcp", count: 3, last_at: "2026-11-24T00:00:00Z", address: "104.18.7.192", named, blocked: false });

beforeEach(() => { Object.values(api).forEach((f) => f.mockReset()); });

describe("Agent network", () => {
  it("offers to observe an agent made before", async () => {
    api.getAgentNetwork.mockResolvedValue({ agent_id: 7, workload: null, running: [], destinations: [], hosts: [] });
    api.observeAgentNetwork.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [], hosts: [] });
    render(<AgentNetwork agentId={7} />);
    fireEvent.click(await screen.findByRole("button", { name: "Observe its network" }));
    await waitFor(() => expect(api.observeAgentNetwork).toHaveBeenCalledWith(7));
    expect(await screen.findByText("provenza-sensor --agent 7 run -- <command>")).toBeTruthy();
  });

  it("says it is not contained until it runs under the sensor", async () => {
    api.getAgentNetwork.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [], hosts: [] });
    render(<AgentNetwork agentId={7} />);
    expect(await screen.findByText(/Not contained yet: only its MCP calls go through Provenza/)).toBeTruthy();
    expect(screen.getByText("provenza-sensor --agent 7 run -- <command>")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /enforce/ })).toBeNull();
  });

  it("enforces the checked destinations only", async () => {
    api.getAgentNetwork.mockResolvedValue({
      agent_id: 7, workload: workload("observe"),
      running: [{ sensor_id: 1, sensor: "s1", hostname: "build-1", cgroups: 1, processes: 2, last_seen_at: null }],
      destinations: [dest("api.openai.com", 443), dest("140.82.112.3", 22, false)], hosts: [],
    });
    api.enforceAgentNetwork.mockResolvedValue({
      agent_id: 7, workload: workload("enforce", [{ dest: "api.openai.com", ports: [443], protocols: ["tcp"] }]),
      running: [], destinations: [], hosts: [],
    });
    render(<AgentNetwork agentId={7} />);
    expect(await screen.findByText("Runs under the sensor on build-1 (s1): everything it connects to is recorded.")).toBeTruthy();
    expect(screen.getByText(/address only/)).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox", { name: "Allow 140.82.112.3" }));
    fireEvent.click(screen.getByRole("button", { name: "Allow the 1 checked and enforce…" }));
    await waitFor(() => expect(api.enforceAgentNetwork).toHaveBeenCalledWith(7, [{ dest: "api.openai.com", port: 443, protocol: "tcp" }]));
    expect(await screen.findByText("Enforced")).toBeTruthy();
    expect(screen.getByText("api.openai.com:443 tcp")).toBeTruthy();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("attaches the service it runs as, from what the sensor listed, and detaches it", async () => {
    const units = [
      { kind: "service" as const, name: "billing-agent.service", runtime: null, id: null,
        cgroup: "system.slice/billing-agent.service", pattern: "system.slice/billing-agent.service", attached: false, taken_by: null },
      { kind: "service" as const, name: "ssh.service", runtime: null, id: null,
        cgroup: "system.slice/ssh.service", pattern: "system.slice/ssh.service", attached: false, taken_by: "agent-3" },
      { kind: "container" as const, name: "support-bot", runtime: "docker" as const, id: "a1a1a1a1a1a1",
        cgroup: "system.slice/docker-x.scope", pattern: "system.slice/docker-x.scope", attached: false, taken_by: null },
    ];
    const hosts = [{ sensor_id: 4, sensor: "s4", hostname: "vps-1", units }];
    api.getAgentNetwork.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [], hosts });
    api.attachAgentUnit.mockResolvedValue({
      agent_id: 7, workload: workload("observe", [], ["system.slice/billing-agent.service"]), running: [], destinations: [],
      hosts: [{ ...hosts[0], units: [{ ...units[0], attached: true }, units[1], units[2]] }],
    });
    api.detachAgentUnit.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [], hosts });
    render(<AgentNetwork agentId={7} />);
    expect(await screen.findByText("Not attached to anything yet.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Attach to a service or container…" }));
    expect(screen.getByText("governed by agent-3")).toBeTruthy();          // another workload's: no button for it
    expect(screen.getByText("docker: support-bot (a1a1a1a1a1a1)")).toBeTruthy();
    fireEvent.change(screen.getByRole("textbox", { name: "Search services and containers" }), { target: { value: "billing" } });
    expect(screen.queryByText("ssh.service")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Attach" }));
    await waitFor(() => expect(api.attachAgentUnit).toHaveBeenCalledWith(7, 4, "system.slice/billing-agent.service"));
    expect(await screen.findByText("billing-agent.service")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Detach" }));
    await waitFor(() => expect(api.detachAgentUnit).toHaveBeenCalledWith(7, "system.slice/billing-agent.service"));
    expect(await screen.findByText("Not attached to anything yet.")).toBeTruthy();
  });

  it("says where to install the sensor when no host listed anything", async () => {
    api.getAgentNetwork.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [], hosts: [] });
    render(<AgentNetwork agentId={7} />);
    fireEvent.click(await screen.findByRole("button", { name: "Attach to a service or container…" }));
    expect(screen.getByText(/No sensor has listed its services yet/)).toBeTruthy();
  });
});
