// Argument rules in the policy hierarchy's form (tools.arguments): shown and
// saved as the server stores them, an incomplete rule blocks the save rather
// than being dropped, a rule the form would change opens as YAML, and the
// effective policy names the level of each rule.
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { argRuleFromRow, argRowFromRule, rowsRoundTrip } from "@/components/ArgumentRulesEditor";

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role: "admin" } }) }));
vi.mock("@/components/Dialog", () => ({ confirmDialog: async () => true }));
vi.mock("@/components/SignedPolicyPanel", () => ({ SignedPolicyPanel: () => null }));
vi.mock("@/lib/agent_api", () => ({ listAgents: async () => [] }));

const api = vi.hoisted(() => ({ overview: vi.fn(), getLayer: vi.fn(), previewLayer: vi.fn(), saveLayer: vi.fn() }));
vi.mock("@/lib/policy_layers_api", async (orig) => ({ ...(await orig<object>()), ...api }));

import PolicyHierarchyPage from "@/app/(app)/policy-hierarchy/page";

const refund = { tool: "payments.*", arg: "amount", op: "max", value: 100, effect: "require_approval" };
const layer = (document: object) => ({ scope: "org", team_id: null, agent_id: null, document, yaml: "", revision: 3,
  updated_at: null, updated_by: null });

function setup(document: object) {
  api.overview.mockResolvedValue({ org: { rules: 1, revision: 3 }, teams: [], agents: [] });
  api.getLayer.mockResolvedValue(layer(document));
  api.previewLayer.mockImplementation(async (_s: string, _id: unknown, body: { document?: object }) => ({
    ok: true, document: body.document ?? document, yaml: "", levels: [{ source: "organization", scope: "org", id: null }],
    effective: { fields: { "tools.arguments": { items: [{ value: refund, source: "organization" }] } }, ignored: [] },
  }));
  api.saveLayer.mockImplementation(async (_s: string, _id: unknown, body: { document: object }) => layer(body.document));
  render(<PolicyHierarchyPage />);
}

describe("argument rules in the policy hierarchy", () => {
  it("converts rows to rules and back without changing them", () => {
    expect(argRuleFromRow(argRowFromRule(refund)!)).toEqual(refund);
    const mail = { tool: "email.send", arg: "to", op: "domain_in", value: ["provenza.dev", "eu.provenza.dev"], effect: "deny" };
    expect(rowsRoundTrip([refund, mail])).toBe(true);
    expect(rowsRoundTrip([{ tool: "x", arg: "n", op: "in", value: [1, 2], effect: "deny" }])).toBe(false);
    expect(rowsRoundTrip([{ tool: "x", arg: "b", op: "equals", value: true, effect: "deny" }])).toBe(false);
    expect(argRuleFromRow({ tool: "x", arg: "", op: "max", value: "5", effect: "deny" })).toBeNull();
  });

  it("shows a level's rules, refuses to save an incomplete one and saves the rest as stored", async () => {
    setup({ tools: { arguments: [refund] } });
    expect(await screen.findByDisplayValue("payments.*")).toBeTruthy();
    // the effective policy names where each rule comes from
    await waitFor(() => expect(screen.getAllByText(/payments\.\* · amount/).length).toBeGreaterThan(0));

    fireEvent.click(screen.getByText(/Add constraint/));
    const save = screen.getByText("Save") as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(screen.getAllByText(/not complete/i).length).toBeGreaterThan(0);

    const tools = screen.getAllByPlaceholderText("db.query, payments.*");
    fireEvent.change(tools[1], { target: { value: "email.send" } });
    fireEvent.change(screen.getAllByPlaceholderText("sql, to, options.cc")[1], { target: { value: "to" } });
    fireEvent.change(screen.getAllByRole("combobox")[3], { target: { value: "domain_in" } });
    const values = screen.getAllByRole("textbox").filter((el) => (el as HTMLInputElement).value === "");
    fireEvent.change(values[values.length - 1], { target: { value: "provenza.dev, eu.provenza.dev" } });
    await waitFor(() => expect((screen.getByText("Save") as HTMLButtonElement).disabled).toBe(false));
    await act(async () => { fireEvent.click(screen.getByText("Save")); });
    const sent = api.saveLayer.mock.calls.at(-1)![2].document;
    expect(sent.tools.arguments).toEqual([refund, {
      tool: "email.send", arg: "to", op: "domain_in", value: ["provenza.dev", "eu.provenza.dev"], effect: "deny" }]);
  });

  it("opens a rule the form would change as YAML", async () => {
    setup({ tools: { arguments: [{ tool: "x", arg: "n", op: "in", value: [1, 2], effect: "deny" }] } });
    await waitFor(() => expect(document.querySelector("textarea")).not.toBeNull());
    expect(screen.queryByPlaceholderText("db.query, payments.*")).toBeNull();     // no form for it
  });
});
