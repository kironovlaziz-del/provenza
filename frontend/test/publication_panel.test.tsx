// Audit Log -> Publication outside the server (app/(app)/audit/PublicationPanel.tsx):
// each target with the host it sends to, the last publication, and the
// settings an admin changes.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PublicationPanel } from "@/app/(app)/audit/PublicationPanel";
import type { PublicationSettingsT } from "@/lib/audit_api";

const base = (): PublicationSettingsT => ({
  interval_minutes: 60, min_interval: 5, max_interval: 1440, publications: 3,
  publishing_key: { fingerprint: "SHA256:abc", public_key: "-----BEGIN PUBLIC KEY-----" },
  targets: [
    { target: "rekor", enabled: true, configured: true, destination: "https://rekor.sigstore.dev", host: "rekor.sigstore.dev",
      public_instance: true, last_published_at: "2026-11-22T10:00:00Z", last_tree_size: 420,
      last_location: "https://search.sigstore.dev/?logIndex=7", last_error: null, last_error_at: null },
    { target: "github", enabled: false, configured: false, destination: null, host: null, last_published_at: null,
      last_tree_size: null, last_location: null, last_error: null, last_error_at: null },
    { target: "s3", enabled: false, configured: false, destination: null, host: null, last_published_at: null,
      last_tree_size: null, last_location: null, last_error: null, last_error_at: null },
  ],
});
const setPublication = vi.fn(async (input: Record<string, unknown>) => ({ ...base(), interval_minutes: input.interval_minutes as number }));
const publishNow = vi.fn(async () => ({ ...base(), result: { rekor: "published" } }));
vi.mock("@/lib/audit_api", () => ({
  getPublication: async () => base(),
  setPublication: (i: Record<string, unknown>) => setPublication(i),
  publishNow: () => publishNow(),
}));

describe("publication panel", () => {
  it("shows each target with where it sends", async () => {
    render(<PublicationPanel isAdmin={false} />);
    expect(await screen.findByText("Publication outside the server")).toBeTruthy();
    expect(screen.getByText("Sigstore Rekor")).toBeTruthy();
    expect(screen.getByText(/→ rekor\.sigstore\.dev/)).toBeTruthy();
    expect(screen.getByText(/420 records/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "View" }).getAttribute("href")).toBe("https://search.sigstore.dev/?logIndex=7");
    expect(screen.getByText(/Every hour · 3 publications/)).toBeTruthy();
    expect(screen.getByText("SHA256:abc")).toBeTruthy();
    expect(screen.queryByText("GitHub")).toBeNull();               // shown once it is set up
    expect(screen.queryByRole("button", { name: "Change" })).toBeNull();
  });

  it("lets an admin publish now and change the interval", async () => {
    render(<PublicationPanel isAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Publish now" }));
    expect(await screen.findByText("Published.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Change" }));
    fireEvent.change(screen.getByLabelText("How often"), { target: { value: "15" } });
    fireEvent.click(screen.getByLabelText(/Publish to Sigstore Rekor/));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(setPublication).toHaveBeenCalledWith(
      { interval_minutes: 15, rekor_enabled: false, rekor_url: null, rekor_public_key: null }));
  });
});
