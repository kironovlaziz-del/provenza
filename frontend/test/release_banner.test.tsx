// The signed-policy banner (components/ReleaseBanner.tsx) follows a change
// made in this browser at once: signing the release takes the note away
// without a reload.
import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ReleaseBanner } from "@/components/ReleaseBanner";

let unsigned = 1;
const getReleaseState = vi.fn(async () => ({ in_force: null, draft: null, unsigned_count: unsigned }));
vi.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { role: "admin" }, session: { status: "active" } }) }));
vi.mock("@/lib/api", () => ({ CHANGED_EVENT: "provenza:changed" }));
vi.mock("@/lib/policy_release_api", () => ({ getReleaseState: () => getReleaseState() }));

describe("signed policy banner", () => {
  it("goes away as soon as the change is signed", async () => {
    render(<ReleaseBanner />);
    expect(await screen.findByRole("note")).toBeTruthy();
    unsigned = 0;                                       // the release was signed in this browser
    act(() => { window.dispatchEvent(new Event("provenza:changed")); });
    await waitFor(() => expect(screen.queryByRole("note")).toBeNull());
    expect(getReleaseState).toHaveBeenCalledTimes(2);
  });
});
