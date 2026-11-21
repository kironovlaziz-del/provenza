// AI agents -> Connect an agent (app/(app)/agents/connect/page.tsx): the
// approved tools are offered, the ticked ones become the token's rights, and
// starting over revokes the unused token.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ConnectAgentPage from "@/app/(app)/agents/connect/page";

const issueEnrollment = vi.fn(async (input: Record<string, unknown>) => ({
  id: 7, state: "open", token: "pvz_enr_x", require_hybrid: input.require_hybrid,
  allowed_tools: input.allowed_tools, expires_at: "2026-11-23T10:00:00Z", attestation: null,
}));
const revokeEnrollment = vi.fn(async () => ({}));
let tokenState = "open";
let tools = [
  { name: "deepwiki.read_wiki_structure", kind: "mcp", usable: true },
  { name: "deepwiki.ask_wiki_question", kind: "mcp", usable: true },
  { name: "deepwiki.read_wiki_contents", kind: "mcp", usable: false },
];
vi.mock("next/navigation", () => ({ usePathname: () => "/agents/connect" }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role: "admin" } }) }));
vi.mock("@/lib/agent_api", () => ({ listGatewayTools: async () => tools }));
vi.mock("@/lib/enrollment_api", () => ({
  issueEnrollment: (i: Record<string, unknown>) => issueEnrollment(i),
  revokeEnrollment: () => revokeEnrollment(),
  listEnrollments: async () => [{ id: 7, state: tokenState }],
}));
vi.mock("@/components/EnrollPanel", () => ({
  EnrollPanel: ({ token, hybrid }: { token: string; hybrid: boolean }) => <p>connect {token} {String(hybrid)}</p>,
}));

describe("connect an agent", () => {
  it("gives the ticked approved tools and shows the command step", async () => {
    render(<ConnectAgentPage />);
    const ask = await screen.findByRole("checkbox", { name: /deepwiki\.ask_wiki_question/ });
    expect(screen.queryByRole("checkbox", { name: /read_wiki_contents/ })).toBeNull();
    expect(screen.getByText(/1 tool awaits approval and cannot be given yet: deepwiki\.read_wiki_contents/)).toBeTruthy();
    fireEvent.click(ask);
    fireEvent.click(screen.getByRole("checkbox", { name: /deepwiki\.read_wiki_structure/ }));
    fireEvent.click(screen.getByRole("button", { name: "Next: connect" }));
    expect(await screen.findByText("connect pvz_enr_x true")).toBeTruthy();
    expect(issueEnrollment).toHaveBeenCalledWith({
      name: undefined, agent_type: "custom", capabilities: [], allowed_models: [], max_delegation_depth: 3,
      allowed_tools: ["deepwiki.ask_wiki_question", "deepwiki.read_wiki_structure"], require_hybrid: true, ttl_hours: 24,
    });
    expect(screen.getByText(/The agent gets these tools: deepwiki\.ask_wiki_question, deepwiki\.read_wiki_structure\./)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Start over" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Next: connect" })).toBeTruthy());
    expect(revokeEnrollment).toHaveBeenCalledTimes(1);
  });

  it("leaves a token the machine already used alone when starting over", async () => {
    tokenState = "used";
    render(<ConnectAgentPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Next: connect" }));
    fireEvent.click(await screen.findByRole("button", { name: "Start over" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Next: connect" })).toBeTruthy());
    expect(revokeEnrollment).not.toHaveBeenCalled();
    tokenState = "open";
  });

  it("connects without tools when none is approved, Ed25519 only when asked", async () => {
    tools = [];
    render(<ConnectAgentPage />);
    expect(await screen.findByText(/No approved tools yet/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/Post-quantum hybrid/));
    fireEvent.change(screen.getByLabelText("Name (optional)"), { target: { value: " cursor@desk " } });
    fireEvent.click(screen.getByRole("button", { name: "Next: connect" }));
    expect(await screen.findByText("connect pvz_enr_x false")).toBeTruthy();
    expect(issueEnrollment).toHaveBeenLastCalledWith(expect.objectContaining({ name: "cursor@desk", allowed_tools: [], require_hybrid: false }));
    expect(screen.getByText(/The agent gets no tools\./)).toBeTruthy();
  });
});
