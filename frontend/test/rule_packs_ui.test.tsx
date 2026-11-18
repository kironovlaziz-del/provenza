// The Rule packs tab (components/RulePacks.tsx): packs listed by kind, apply
// after a preview with the preview's revision, undo of a profile edited since
// only once confirmed.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role: "admin" } }) }));
vi.mock("@/components/Dialog", () => ({ confirmDialog: async () => true }));

const api = vi.hoisted(() => ({
  listPacks: vi.fn(), listApplications: vi.fn(), previewApply: vi.fn(), applyPack: vi.fn(),
  previewUndo: vi.fn(), undoApplication: vi.fn(), createPack: vi.fn(), updatePack: vi.fn(), deletePack: vi.fn(),
}));
vi.mock("@/lib/policy_packs_api", async (orig) => ({ ...(await orig<object>()), ...api }));

import { RulePacks } from "@/components/RulePacks";

const guard = { ref: "builtin:guard-secrets", builtin: true, name: "Guard: secrets", description: "No secrets",
  kind: "guard", level: "any", yaml: "tools:\n  deny: ['vault.*']\n", document: {} };
const profile = { ref: "builtin:team-support", builtin: true, name: "Team: support", description: null,
  kind: "profile", level: "team", yaml: "tools:\n  allow: ['kb.*']\n", document: {} };
const applied = { id: 7, pack_ref: profile.ref, pack_name: profile.name, kind: "profile", scope: "team", target_id: 3,
  applied_at: "2026-11-18T10:00:00Z", undone_at: null };

describe("rule packs tab", () => {
  it("applies a guard with the preview's revision and undoes a profile once confirmed", async () => {
    api.listPacks.mockResolvedValue({ builtin: [guard, profile], own: [] });
    api.listApplications.mockResolvedValue([applied]);
    api.previewApply.mockResolvedValue({ pack: guard, revision: 4, skipped: [],
      changes: [{ field: "tools.deny", before: [], after: ["vault.*"], added: ["vault.*"], removed: [] }] });
    api.applyPack.mockResolvedValue({ skipped: [] });
    api.previewUndo.mockResolvedValue({ application: applied, revision: 9, edited_since: true,
      changes: [{ field: "tools.allow", before: ["kb.*"], after: ["x.*"], added: ["x.*"], removed: ["kb.*"] }] });
    api.undoApplication.mockResolvedValue(undefined);
    const onChanged = vi.fn();
    render(<RulePacks overview={{ org: { rules: 0 }, teams: [{ id: 3, name: "Support", parent_id: null, rules: 1 }], agents: [] } as never}
      agents={[]} onChanged={onChanged} />);

    expect(await screen.findByText("Guard: secrets")).toBeTruthy();
    expect(screen.getByText("Profiles")).toBeTruthy();
    expect(screen.getByText("Guards")).toBeTruthy();

    fireEvent.click(screen.getAllByRole("button", { name: "Apply" }).at(-1)!);           // guards come after profiles
    expect(await screen.findByText("+ vault.*")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Apply" }).find((b) => b.className.includes("btn-primary") && !b.className.includes("btn-sm"))!);
    await waitFor(() => expect(api.applyPack).toHaveBeenCalledWith("builtin:guard-secrets", "org", null, 4));
    expect(onChanged).toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(await screen.findByText(/Puts back the policy Team: Support had/)).toBeTruthy();
    const confirmUndo = screen.getAllByRole("button", { name: "Undo" }).find((b) => b.className.includes("btn-primary"))!;
    expect((confirmUndo as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(confirmUndo);
    await waitFor(() => expect(api.undoApplication).toHaveBeenCalledWith(7, 9, true));
  });
});
