"use client";

// BPF LSM on a sensor's host (Runtime -> a sensor -> Commands): the button
// that prepares it for the next boot, shown only when the kernel can run it
// but its boot line leaves it out, and what to do once it is prepared. The
// command itself is signed with the administrator's passkey
// (lib/egress_sensor_api.ts, createSensorCommand); the sensor runs it in its
// own systemd unit and never reboots the host (docs/sensor-commands.md).
import React from "react";
import { useTranslation } from "react-i18next";
import type { BpfLsmState } from "@/lib/egress_sensor_api";

export function BpfLsmButton({ state, busy, onPrepare }: {
  state: BpfLsmState | null; busy: boolean; onPrepare: () => void;
}) {
  const { t } = useTranslation();
  if (state !== "inactive") return null;
  return (
    <button className="btn btn-sm" disabled={busy} onClick={onPrepare}>
      {t("rt.sensors.cmd_prepare_lsm")}
    </button>
  );
}

export function BpfLsmHint({ state, host }: { state: BpfLsmState | null; host: string }) {
  const { t } = useTranslation();
  if (state !== "inactive" && state !== "prepared") return null;
  return (
    <div className="hint-text" style={{ fontSize: 12, marginBottom: 8 }}>
      {state === "inactive" ? t("rt.sensors.lsm_inactive_hint") : t("rt.sensors.lsm_prepared_hint", { host })}
    </div>
  );
}
