// Runtime -> a sensor -> Commands: "Prepare BPF LSM" only where the kernel can
// run it but the boot line leaves it out, what to do once it is prepared, and
// the command always signed with the session key (passkey).
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { BpfLsmButton, BpfLsmHint } from "@/app/(app)/runtime/BpfLsm";

const post = vi.fn(async (url: string, body: Record<string, unknown>) =>
  url.endsWith("/commands/statement")
    ? { data: { statement: { session_id: 7, kind: body.kind, nonce: "n".repeat(22) } } }
    : { data: { id: 1, kind: body.kind } });
vi.mock("@/lib/api", () => ({ api: { post: (u: string, b: Record<string, unknown>) => post(u, b) } }));
const sign = vi.fn(async () => "sig");
vi.mock("@/lib/signing", () => ({ signWithSessionKey: () => sign() }));

beforeEach(() => { post.mockClear(); sign.mockClear(); });

describe("BPF LSM", () => {
  it("offers to prepare it only when the kernel can run it", () => {
    const onPrepare = vi.fn();
    const { rerender } = render(<BpfLsmButton state="inactive" busy={false} onPrepare={onPrepare} />);
    fireEvent.click(screen.getByRole("button", { name: "Prepare BPF LSM…" }));
    expect(onPrepare).toHaveBeenCalledTimes(1);
    for (const st of ["active", "prepared", "unavailable", null] as const) {
      rerender(<BpfLsmButton state={st} busy={false} onPrepare={onPrepare} />);
      expect(screen.queryByRole("button")).toBeNull();
    }
  });

  it("says to reboot once prepared, and nothing when there is nothing to do", () => {
    const { rerender, container } = render(<BpfLsmHint state="prepared" host="vps-1" />);
    expect(screen.getByText("BPF LSM is prepared: reboot vps-1 to turn it on.")).toBeTruthy();
    rerender(<BpfLsmHint state="inactive" host="vps-1" />);
    expect(screen.getByText(/BPF LSM is off in this host's boot line/)).toBeTruthy();
    for (const st of ["active", "unavailable", null] as const) {
      rerender(<BpfLsmHint state={st} host="vps-1" />);
      expect(container.textContent).toBe("");
    }
  });

  it("is sent signed with the session key", async () => {
    const { createSensorCommand } = await import("@/lib/egress_sensor_api");
    await createSensorCommand(3, "prepare-bpf-lsm");
    expect(post.mock.calls[0]).toEqual(["/egress-sensor/sensors/3/commands/statement", { kind: "prepare-bpf-lsm" }]);
    expect(sign).toHaveBeenCalledTimes(1);
    expect(post.mock.calls[1][0]).toBe("/egress-sensor/sensors/3/commands");
    expect(post.mock.calls[1][1]).toMatchObject({ kind: "prepare-bpf-lsm", signature: "sig" });
  });
});
