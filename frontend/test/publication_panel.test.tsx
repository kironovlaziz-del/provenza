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
    { target: "s3", enabled: false, configured: false, destination: null, host: null, last_published_at: null,
      last_tree_size: null, last_location: null, last_error: null, last_error_at: null },
  ],
});
const setPublication = vi.fn(async (input: Record<string, unknown>) => ({ ...base(), interval_minutes: input.interval_minutes as number }));
const publishNow = vi.fn(async () => ({ ...base(), result: { rekor: "published" } }));
const setPublicationS3 = vi.fn(async (input: Record<string, unknown>) => {
  const b = base();
  b.targets[1] = { ...b.targets[1], enabled: true, configured: true, destination: "audit-bucket",
    host: "audit-bucket.s3.eu-central-1.amazonaws.com",
    settings: { endpoint: null, region: "eu-central-1", bucket: "audit-bucket", prefix: "provenza-audit/",
      access_key: input.access_key as string, retention_days: input.retention_days as number, lock_mode: "COMPLIANCE" } };
  return b;
});
vi.mock("@/lib/audit_api", () => ({
  getPublication: async () => base(),
  setPublication: (i: Record<string, unknown>) => setPublication(i),
  publishNow: () => publishNow(),
  setPublicationS3: (i: Record<string, unknown>) => setPublicationS3(i),
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
    expect(screen.queryByText("S3 (Object Lock)")).toBeNull();     // to others, shown once it is set up
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

  it("lets an admin set up S3 with Object Lock", async () => {
    render(<PublicationPanel isAdmin />);
    expect(await screen.findByText("S3 (Object Lock)")).toBeTruthy();
    expect(screen.getByText("not set up")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Set up S3 (Object Lock)" }));
    const save = screen.getByRole("button", { name: "Test and save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Region"), { target: { value: "eu-central-1" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "audit-bucket" } });
    fireEvent.change(screen.getByLabelText("Access key ID"), { target: { value: "AKIAEXAMPLE" } });
    fireEvent.change(screen.getByLabelText("Secret access key"), { target: { value: "secret-value-123" } });
    fireEvent.change(screen.getByLabelText("Keep each checkpoint locked for (days)"), { target: { value: "90" } });
    fireEvent.click(save);
    await waitFor(() => expect(setPublicationS3).toHaveBeenCalledWith({
      enabled: true, endpoint: null, region: "eu-central-1", bucket: "audit-bucket", prefix: "provenza-audit/",
      access_key: "AKIAEXAMPLE", secret_key: "secret-value-123", retention_days: 90 }));
    expect(await screen.findByText(/each locked for 90 days/)).toBeTruthy();
    expect(screen.getByText(/→ audit-bucket\.s3\.eu-central-1\.amazonaws\.com/)).toBeTruthy();
  });
});
