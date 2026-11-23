// The agent's page -> Network (components/AgentNetwork.tsx): what it says
// before the agent runs under the sensor, the destinations it went to, and
// enforcing the checked ones - and only those.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentNetwork } from "@/components/AgentNetwork";
import type { AgentNetworkWorkloadT } from "@/lib/agent_network_api";

vi.mock("@/components/Dialog", () => ({ confirmDialog: async () => true }));
vi.mock("next/link", () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));

const api = vi.hoisted(() => ({ getAgentNetwork: vi.fn(), observeAgentNetwork: vi.fn(), enforceAgentNetwork: vi.fn() }));
vi.mock("@/lib/agent_network_api", () => api);

const workload = (mode: "observe" | "enforce", allow: AgentNetworkWorkloadT["egress_allow"] = []) =>
  ({ id: 11, name: "agent-7", mode, dns: "any" as const, enabled: true, isolated: false, egress_allow: allow });
const dest = (d: string, port: number, named = true) =>
  ({ dest: d, port, protocol: "tcp", count: 3, last_at: "2026-11-24T00:00:00Z", address: "104.18.7.192", named, blocked: false });

beforeEach(() => { Object.values(api).forEach((f) => f.mockReset()); });

describe("Agent network", () => {
  it("offers to observe an agent made before", async () => {
    api.getAgentNetwork.mockResolvedValue({ agent_id: 7, workload: null, running: [], destinations: [] });
    api.observeAgentNetwork.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [] });
    render(<AgentNetwork agentId={7} />);
    fireEvent.click(await screen.findByRole("button", { name: "Observe its network" }));
    await waitFor(() => expect(api.observeAgentNetwork).toHaveBeenCalledWith(7));
    expect(await screen.findByText("provenza-sensor --agent 7 run -- <command>")).toBeTruthy();
  });

  it("says it is not contained until it runs under the sensor", async () => {
    api.getAgentNetwork.mockResolvedValue({ agent_id: 7, workload: workload("observe"), running: [], destinations: [] });
    render(<AgentNetwork agentId={7} />);
    expect(await screen.findByText(/Not contained yet: only its MCP calls go through Provenza/)).toBeTruthy();
    expect(screen.getByText("provenza-sensor --agent 7 run -- <command>")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /enforce/ })).toBeNull();
  });

  it("enforces the checked destinations only", async () => {
    api.getAgentNetwork.mockResolvedValue({
      agent_id: 7, workload: workload("observe"),
      running: [{ sensor_id: 1, sensor: "s1", hostname: "build-1", cgroups: 1, processes: 2, last_seen_at: null }],
      destinations: [dest("api.openai.com", 443), dest("140.82.112.3", 22, false)],
    });
    api.enforceAgentNetwork.mockResolvedValue({
      agent_id: 7, workload: workload("enforce", [{ dest: "api.openai.com", ports: [443], protocols: ["tcp"] }]),
      running: [], destinations: [],
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
});
