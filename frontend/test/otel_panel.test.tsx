// SIEM & OpenTelemetry -> OpenTelemetry (app/(app)/export-keys/OtelPanel.tsx):
// the state with the host it sends to, set up with a header whose value is
// never shown, kept when only the name is sent again, and switched off with
// what is stored.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OtelPanel } from "@/app/(app)/export-keys/OtelPanel";
import type { OtelExportT } from "@/lib/otel_export_api";

const off = (): OtelExportT => ({
  enabled: false, endpoint: null, logs_url: null, outbound_host: null, header_name: null, header_set: false,
  last_success_at: null, last_error: null, last_error_at: null, exported_total: 0, updated_at: null,
});
const on = (): OtelExportT => ({
  ...off(), enabled: true, endpoint: "https://otel.example.com:4318", logs_url: "https://otel.example.com:4318/v1/logs",
  outbound_host: "otel.example.com", header_name: "Authorization", header_set: true,
  last_success_at: "2026-11-23T10:00:00Z", exported_total: 42, last_error: "otel.http_error: HTTP 503: down",
  last_error_at: "2026-11-23T10:05:00Z",
});

let current: OtelExportT = off();
const setOtelExport = vi.fn(async (input: Record<string, unknown>) => {
  current = input.enabled ? on() : { ...on(), enabled: false };
  return current;
});
const testOtelExport = vi.fn(async () => ({ ok: true, note: null }));
vi.mock("@/lib/otel_export_api", () => ({
  getOtelExport: async () => current,
  setOtelExport: (i: Record<string, unknown>) => setOtelExport(i),
  testOtelExport: () => testOtelExport(),
}));

beforeEach(() => {
  setOtelExport.mockClear();
  testOtelExport.mockClear();
});

describe("OpenTelemetry panel", () => {
  it("sets the export up with a header whose value is sent once", async () => {
    current = off();
    render(<OtelPanel />);
    expect(await screen.findByText("not set up")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Set up" }));
    const save = screen.getByRole("button", { name: "Test and save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);                                   // no endpoint yet
    fireEvent.change(screen.getByLabelText("Collector endpoint (OTLP/HTTP)"),
      { target: { value: " https://otel.example.com:4318 " } });
    fireEvent.change(screen.getByLabelText("Header (optional)"), { target: { value: "Authorization" } });
    expect(save.disabled).toBe(true);                                   // a new header needs its value
    fireEvent.change(screen.getByLabelText("Header value"), { target: { value: "Bearer secret-token" } });
    fireEvent.click(save);
    await waitFor(() => expect(setOtelExport).toHaveBeenCalledWith({
      enabled: true, endpoint: "https://otel.example.com:4318", header_name: "Authorization",
      header_value: "Bearer secret-token" }));
    expect(await screen.findByText(/The collector took a test record/)).toBeTruthy();
    expect(screen.getByText(/→ otel\.example\.com/)).toBeTruthy();
    expect(screen.getByText(/42 records sent/)).toBeTruthy();
    expect(screen.getByText(/HTTP 503: down/)).toBeTruthy();
    expect(screen.getByText(/value stored, not shown/)).toBeTruthy();
    expect(screen.queryByText(/secret-token/)).toBeNull();
  });

  it("keeps the stored value, sends a test record, and switches off with what is stored", async () => {
    current = on();
    render(<OtelPanel />);
    fireEvent.click(await screen.findByRole("button", { name: "Send a test record" }));
    await waitFor(() => expect(testOtelExport).toHaveBeenCalled());
    expect(await screen.findByText("The collector took the test record.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Change" }));
    expect((screen.getByLabelText("Header value") as HTMLInputElement).value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Test and save" }));
    await waitFor(() => expect(setOtelExport).toHaveBeenLastCalledWith({
      enabled: true, endpoint: "https://otel.example.com:4318", header_name: "Authorization", header_value: null }));

    fireEvent.click(screen.getByRole("button", { name: "Change" }));
    fireEvent.change(screen.getByLabelText("Header (optional)"), { target: { value: "x-other" } });
    fireEvent.click(screen.getByRole("button", { name: "Switch off" }));
    await waitFor(() => expect(setOtelExport).toHaveBeenLastCalledWith({
      enabled: false, endpoint: "https://otel.example.com:4318", header_name: "Authorization", header_value: null }));
    expect(await screen.findByText("Switched off. Nothing more is sent.")).toBeTruthy();
  });
});
