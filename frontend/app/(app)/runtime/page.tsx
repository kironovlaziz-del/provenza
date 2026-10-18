"use client";

// Runtime: egress workloads on hosts (cgroup v2 paths) whose connections the
// Provenza egress sensor governs, the sensors themselves, and the
// connections they made or tried outside policy.
import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { confirmDialog } from "@/components/Dialog";
import { errorMessage as apiError } from "@/lib/errors";
import { SensorActivity } from "@/components/SensorActivity";
import { listAgents } from "@/lib/agent_api";
import type { Agent } from "@/lib/agent_types";
import {
  DNS_MODES, PROTOCOLS, RUNTIME_MODES, VIOLATION_ACTIONS,
  createSensorCommand, createWorkload, deleteWorkload,
  finalizeSigningKeyRotation, getSensorSettings, getSigningKey,
  listSensorCommands, listSensorWorkloads, listSensors, listViolations, listWorkloads,
  refreshSensor, registerSensor, revokeSensor, rotateSigningKey, updateSensor, updateSensorSettings, updateWorkload,
  type AllowT, type CommandKind, type CommandStatus, type CommandT, type DNSMode, type Protocol,
  type RuntimeMode, type SensorCreatedT, type SensorSettingsInput, type SensorSettingsT, type SensorT,
  type SensorWorkloadT, type SigningKeyT,
  type ViolationAction, type ViolationT, type WorkloadInput, type WorkloadT,
} from "@/lib/egress_sensor_api";

// Retention options for the Activity window. 0 disables pruning entirely;
// the backend accepts anything 0..365.
const RETENTION_OPTIONS = [0, 7, 30, 90, 365] as const;

function retentionLabel(t: (k: string) => string, days: number): string {
  if (days === 0) return t("rt.sensors.retention_forever");
  if (days === 365) return t("rt.sensors.retention_365d");
  return t(`rt.sensors.retention_${days}d`) || `${days}d`;
}

interface AllowRow { dest: string; ports: string; protocols: Protocol[] }

interface Draft {
  id: number | null;
  name: string;
  agentId: string;
  patterns: string;
  runAs: string;
  egress: AllowRow[];
  ingress: AllowRow[];
  dns: DNSMode;
  mode: RuntimeMode;
  isolated: boolean;
  isolatedReason: string;
  enabled: boolean;
}

const EMPTY_ALLOW: AllowRow = { dest: "", ports: "", protocols: [] };

const EMPTY: Draft = {
  id: null, name: "", agentId: "", patterns: "", runAs: "",
  egress: [{ ...EMPTY_ALLOW }], ingress: [],
  dns: "off", mode: "observe", isolated: false, isolatedReason: "", enabled: true,
};

const MODE_PILL: Record<RuntimeMode, string> = { observe: "pill-neutral", alert: "pill-medium", enforce: "pill-low" };

// Colour of each command status. Only "done" reads as safe, "failed" and
// "expired" read as a problem, everything in flight is neutral-to-warning.
const CMD_STATUS_PILL: Record<CommandStatus, string> = {
  pending: "pill-neutral",
  delivered: "pill-neutral",
  executing: "pill-medium",
  done: "pill-low",
  failed: "pill-critical",
  expired: "pill-critical",
};
const ACTION_PILL: Record<ViolationAction, string> = { observed: "pill-neutral", alerted: "pill-medium", blocked: "pill-critical" };

function rowFromAllow(a: AllowT, side: "egress" | "ingress"): AllowRow {
  return {
    dest: (side === "egress" ? a.dest : a.source) ?? "",
    ports: a.ports.join(", "),
    protocols: (a.protocols ?? []) as Protocol[],
  };
}

function toDraft(w: WorkloadT): Draft {
  return {
    id: w.id, name: w.name, agentId: w.agent_id ? String(w.agent_id) : "",
    patterns: w.cgroup_patterns.join("\n"),
    runAs: w.run_as_users.join("\n"),
    egress: w.egress_allow.length ? w.egress_allow.map((a) => rowFromAllow(a, "egress")) : [{ ...EMPTY_ALLOW }],
    ingress: w.ingress_allow.map((a) => rowFromAllow(a, "ingress")),
    dns: w.dns, mode: w.mode,
    isolated: w.isolated, isolatedReason: w.isolated_reason ?? "",
    enabled: w.enabled,
  };
}

/** The draft as the API takes it, or the key of what is wrong with it. */
function toInput(d: Draft): WorkloadInput | string {
  const patterns = d.patterns.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!d.name.trim()) return "rt.err_name";
  if (patterns.length === 0) return "rt.err_patterns";

  const build = (rows: AllowRow[], side: "egress" | "ingress"): AllowT[] | string => {
    const out: AllowT[] = [];
    for (const row of rows) {
      if (!row.dest.trim() && !row.ports.trim()) continue;
      if (!row.dest.trim()) return "rt.err_dest";
      const ports = row.ports.split(/[\s,]+/).filter(Boolean).map(Number);
      if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) return "rt.err_ports";
      const entry: AllowT = { ports, protocols: row.protocols };
      if (side === "egress") entry.dest = row.dest.trim();
      else entry.source = row.dest.trim();
      out.push(entry);
    }
    return out;
  };

  const egress = build(d.egress, "egress");
  if (typeof egress === "string") return egress;
  const ingress = build(d.ingress, "ingress");
  if (typeof ingress === "string") return ingress;

  const runAs = d.runAs.split("\n").map((s) => s.trim()).filter(Boolean);

  return {
    name: d.name.trim(),
    agent_id: d.agentId ? Number(d.agentId) : null,
    cgroup_patterns: patterns,
    run_as_users: runAs,
    egress_allow: egress,
    ingress_allow: ingress,
    dns: d.dns,
    mode: d.mode,
    isolated: d.isolated,
    isolated_reason: d.isolated ? (d.isolatedReason.trim() || null) : null,
    enabled: d.enabled,
  };
}

export default function RuntimePage() {
  const { t, i18n } = useTranslation();
  const [workloads, setWorkloads] = useState<WorkloadT[]>([]);
  const [showDeleted, setShowDeleted] = useState(false);
  const [violations, setViolations] = useState<ViolationT[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [filterWl, setFilterWl] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Egress sensors: hosts whose daemon enforces the policy above.
  const [sensors, setSensors] = useState<SensorT[]>([]);
  const [showRevokedSensors, setShowRevokedSensors] = useState(false);
  const [showRegister, setShowRegister] = useState(false);
  const [sensorName, setSensorName] = useState("");
  const [newKey, setNewKey] = useState<SensorCreatedT | null>(null);
  // Which sensor's details row is expanded (null = none). One at a time:
  // the point of the row is a focused view of one host, not a dashboard.
  const [expandedSensorId, setExpandedSensorId] = useState<number | null>(null);
  // Per-sensor workload snapshots, cached by sensor id. Loaded lazily when
  // a sensor is expanded; cleared on collapse so a re-open refetches.
  const [sensorWorkloads, setSensorWorkloads] = useState<Record<number, SensorWorkloadT[] | null>>({});

  // Organization policy settings; loaded once on mount and edited in place.
  const [settings, setSettings] = useState<SensorSettingsT | null>(null);
  const [settingsDraft, setSettingsDraft] = useState<SensorSettingsInput>({});
  const [settingsOpen, setSettingsOpen] = useState(false);

  // Command signing key: current fingerprint and, during a rotation, the
  // previous key and its deadline.
  const [signingKey, setSigningKey] = useState<SigningKeyT | null>(null);

  // Commands per sensor, cached like workloads: null while loading, an
  // array when fetched. Cleared on collapse so a re-open refetches.
  const [sensorCommands, setSensorCommands] = useState<Record<number, CommandT[] | null>>({});
  // The command history toggle per sensor in the details row.
  const [showCommandResult, setShowCommandResult] = useState<Record<number, boolean>>({});

  const loadWorkloads = useCallback(() => {
    listWorkloads(showDeleted).then(setWorkloads).catch((err) => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t, showDeleted]);
  const loadViolations = useCallback(() => {
    listViolations({
      workload_id: filterWl ? Number(filterWl) : undefined,
      action: (filterAction || undefined) as ViolationAction | undefined,
    }).then(setViolations).catch((err) => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t, filterWl, filterAction]);
  const loadSensors = useCallback(() => {
    listSensors(showRevokedSensors).then(setSensors).catch((err) => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t, showRevokedSensors]);

  const loadSettings = useCallback(() => {
    getSensorSettings()
      .then(s => {
        setSettings(s);
        setSettingsDraft({
          refresh_seconds: s.refresh_seconds,
          heartbeat_seconds: s.heartbeat_seconds,
          default_mode: s.default_mode,
          default_dns: s.default_dns,
          activity_retention_days: s.activity_retention_days,
          violation_retention_days: s.violation_retention_days,
        });
      })
      .catch(err => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t]);

  const loadSigningKey = useCallback(() => {
    getSigningKey()
      .then(setSigningKey)
      .catch(err => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t]);

  const loadCommands = useCallback((sensorId: number) => {
    listSensorCommands(sensorId)
      .then(rows => setSensorCommands(prev => ({ ...prev, [sensorId]: rows })))
      .catch(err => {
        setError(apiError(err, t, t("rt.load_failed")));
        setSensorCommands(prev => ({ ...prev, [sensorId]: [] }));
      });
  }, [t]);

  useEffect(loadWorkloads, [loadWorkloads]);
  useEffect(loadViolations, [loadViolations]);
  useEffect(loadSensors, [loadSensors]);
  useEffect(loadSettings, [loadSettings]);
  useEffect(loadSigningKey, [loadSigningKey]);

  // Poll the command history while a details row is open and something in
  // it is still in flight. When every command is terminal (done/failed/
  // expired) the interval stops on its own: there is nothing to watch.
  useEffect(() => {
    if (expandedSensorId === null) return;
    const rows = sensorCommands[expandedSensorId];
    if (!rows) return;
    const active = rows.some(c =>
      c.status === "pending" || c.status === "delivered" || c.status === "executing");
    if (!active) return;
    const id = window.setInterval(() => loadCommands(expandedSensorId), 5000);
    return () => window.clearInterval(id);
  }, [expandedSensorId, sensorCommands, loadCommands]);
  useEffect(() => { listAgents(500).then(setAgents).catch(() => setAgents([])); }, []);

  const agentName = useMemo(() => new Map(agents.map((a) => [a.id, a.name])), [agents]);
  const wlName = useMemo(() => new Map(workloads.map((w) => [w.id, w.name])), [workloads]);
  const fmt = (iso: string) => new Date(iso).toLocaleString(i18n.language);
  const dest = (v: ViolationT) => {
    if (v.dst_name) return `${v.kind.toUpperCase()} ${v.dst_name}`;
    if (!v.dst_ip) return "—";
    const ip = v.dst_ip.includes(":") ? `[${v.dst_ip}]` : v.dst_ip;
    const proto = v.protocol ? v.protocol.toUpperCase() + " " : "";
    return `${proto}${ip}${v.dst_port ? ":" + v.dst_port : ""}`;
  };

  function edit(d: Draft) {
    setDraft(d);
    setError(null);
    setNotice(null);
  }

  function setAllow(side: "egress" | "ingress", i: number, patch: Partial<AllowRow>) {
    if (!draft) return;
    const list = draft[side].map((r, j) => (j === i ? { ...r, ...patch } : r));
    setDraft({ ...draft, [side]: list });
  }

  function addAllow(side: "egress" | "ingress") {
    if (!draft) return;
    setDraft({ ...draft, [side]: [...draft[side], { ...EMPTY_ALLOW }] });
  }

  function removeAllow(side: "egress" | "ingress", i: number) {
    if (!draft) return;
    setDraft({ ...draft, [side]: draft[side].filter((_, j) => j !== i) });
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!draft) return;
    const input = toInput(draft);
    if (typeof input === "string") {
      setError(t(input));
      return;
    }
    if (input.mode === "enforce" && input.egress_allow.length === 0 && !input.isolated
        && !await confirmDialog(t("rt.confirm_enforce_empty"), { danger: true })) return;
    if (input.isolated && !await confirmDialog(t("rt.confirm_isolated"), { danger: true })) return;
    setBusy(true);
    setError(null);
    try {
      if (draft.id === null) {
        await createWorkload(input);
        setNotice(t("rt.created", { name: input.name }));
      } else {
        await updateWorkload(draft.id, input);
        setNotice(t("rt.saved", { name: input.name }));
      }
      setDraft(null);
      loadWorkloads();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally {
      setBusy(false);
    }
  }

  async function toggle(w: WorkloadT) {
    setBusy(true);
    setError(null);
    try {
      await updateWorkload(w.id, { enabled: !w.enabled });
      loadWorkloads();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally {
      setBusy(false);
    }
  }

  async function remove(w: WorkloadT) {
    if (!await confirmDialog(t("rt.confirm_delete", { name: w.name }), { danger: true })) return;
    setBusy(true);
    setError(null);
    try {
      await deleteWorkload(w.id);
      setNotice(t("rt.deleted", { name: w.name }));
      if (filterWl === String(w.id)) setFilterWl("");
      loadWorkloads();
      loadViolations();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally {
      setBusy(false);
    }
  }

  async function registerSensorSubmit(e: React.FormEvent) {
    e.preventDefault();
    const name = sensorName.trim();
    if (!name) { setError(t("rt.sensors.err_name")); return; }
    setBusy(true); setError(null);
    try {
      const created = await registerSensor(name);
      setNewKey(created);
      setShowRegister(false);
      setSensorName("");
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  async function toggleSensor(s: SensorT) {
    setBusy(true); setError(null);
    try {
      await updateSensor(s.id, { enabled: !s.enabled });
      loadSensors();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  /** Queue one command for a sensor. The sensor picks it up on its next
   *  heartbeat (up to refresh_seconds away), so nothing changes for a
   *  moment; the history table below shows the delivery. */
  async function queueCommand(s: SensorT, kind: CommandKind) {
    if (kind === "detach") {
      // Detach is the destructive one: two confirmations, and the second
      // explicitly names the host so the admin reads it.
      if (!await confirmDialog(t("rt.sensors.cmd_confirm_detach_1", { name: s.name }), { danger: true })) return;
      if (!await confirmDialog(t("rt.sensors.cmd_confirm_detach_2", { host: s.hostname ?? s.name }), { danger: true })) return;
    } else if (kind === "restart") {
      if (!await confirmDialog(t("rt.sensors.cmd_confirm_restart", { name: s.name }))) return;
    }
    setBusy(true); setError(null);
    try {
      await createSensorCommand(s.id, kind);
      setNotice(t("rt.sensors.cmd_queued", { kind: t(`rt.sensors.cmd_kind.${kind}`), name: s.name }));
      loadCommands(s.id);
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  async function forceRefresh(s: SensorT) {
    setBusy(true); setError(null);
    try {
      const res = await refreshSensor(s.id);
      setNotice(t("rt.sensors.refreshed", { name: s.name, n: res.new_revision }));
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  async function rotateKey() {
    if (!await confirmDialog(t("rt.sensors.rotate_confirm"), { danger: true })) return;
    setBusy(true); setError(null);
    try {
      const res = await rotateSigningKey();
      setNotice(t("rt.sensors.rotate_ok", { n: res.sensors_notified }));
      loadSigningKey();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  async function finalizeKey() {
    if (!await confirmDialog(t("rt.sensors.finalize_confirm"), { danger: true })) return;
    setBusy(true); setError(null);
    try {
      await finalizeSigningKeyRotation();
      setNotice(t("rt.sensors.finalize_ok"));
      loadSigningKey();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  async function saveSettings(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const updated = await updateSensorSettings(settingsDraft);
      setSettings(updated);
      setNotice(t("rt.sensors.settings_saved"));
      setSettingsOpen(false);
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  function cancelSettings() {
    if (settings) {
      setSettingsDraft({
        refresh_seconds: settings.refresh_seconds,
        heartbeat_seconds: settings.heartbeat_seconds,
        default_mode: settings.default_mode,
        default_dns: settings.default_dns,
        activity_retention_days: settings.activity_retention_days,
        violation_retention_days: settings.violation_retention_days,
      });
    }
    setSettingsOpen(false);
    setError(null);
  }

  function toggleSensorDetails(id: number) {
    if (expandedSensorId === id) {
      setExpandedSensorId(null);
      setSensorWorkloads(prev => { const next = { ...prev }; delete next[id]; return next; });
      setSensorCommands(prev => { const next = { ...prev }; delete next[id]; return next; });
      return;
    }
    setExpandedSensorId(id);
    // Fresh fetch on every expand: a heartbeat runs every 30s and the
    // numbers move, so a cached row goes stale between two clicks.
    setSensorWorkloads(prev => ({ ...prev, [id]: null }));
    listSensorWorkloads(id)
      .then(rows => setSensorWorkloads(prev => ({ ...prev, [id]: rows })))
      .catch(err => {
        setError(apiError(err, t, t("rt.load_failed")));
        setSensorWorkloads(prev => ({ ...prev, [id]: [] }));
      });
    setSensorCommands(prev => ({ ...prev, [id]: null }));
    loadCommands(id);
  }

  async function revoke(s: SensorT) {
    if (!await confirmDialog(t("rt.sensors.confirm_revoke", { name: s.name }), { danger: true })) return;
    setBusy(true); setError(null);
    try {
      await revokeSensor(s.id);
      setNotice(t("rt.sensors.revoked_ok", { name: s.name }));
      loadSensors();
    } catch (err) {
      setError(apiError(err, t, t("rt.save_failed")));
    } finally { setBusy(false); }
  }

  /** The uninstall reminder: copy the host-side command to the clipboard,
   *  tell the admin to run it there, then offer to revoke the key. There
   *  is no remote channel to the sensor: the control plane never asks a
   *  host to do anything. This is a reminder, not a command. */
  async function uninstallReminder(s: SensorT) {
    const host = s.hostname ?? s.name;
    const ready = await confirmDialog(
      t("rt.sensors.uninstall_hint", { host }),
      { confirmLabel: t("rt.sensors.copy_uninstall") },
    );
    if (!ready) return;

    const cmd = "sudo provenza-sensor --uninstall";
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(cmd);
      } catch {
        setNotice(t("rt.sensors.copy_manual"));
        return;
      }
    } else {
      setNotice(t("rt.sensors.copy_manual"));
      return;
    }
    setNotice(t("rt.sensors.uninstall_copied", { host }));

    // A second step: revoke is what makes the sensor disappear from this
    // list and stop matching a policy. Do it only after the host-side
    // uninstall has finished.
    if (await confirmDialog(t("rt.sensors.uninstall_revoke_now", { host }), { danger: true })) {
      await revoke(s);
    }
  }

  function copyKey(key: string) {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(key).then(
        () => setNotice(t("rt.sensors.copied")),
        () => setNotice(t("rt.sensors.copy_manual")),
      );
    } else {
      setNotice(t("rt.sensors.copy_manual"));
    }
  }

  /** The exact command an admin pastes into the sensor host's shell. It
   *  pulls install.sh from this control plane, which also serves the sensor
   *  binary built with it (/api/v1/egress-sensor/download/, checked against
   *  SHA256SUMS): the host needs neither Go nor git nor GitHub. It uses the
   *  origin the admin is already on. The key is not in it: the script asks
   *  for it with the input hidden, so it stays out of the shell history and
   *  the process list.
   *
   *  Prefer the configured control-plane URL (NEXT_PUBLIC_API_URL) so the
   *  command always points at the canonical domain, even when the admin
   *  reached the UI through a mirror or a raw IP. Strip /api/v1 to get the
   *  origin; fall back to window.location.origin if the env is unset. */
  function installCommand(): string {
    const envURL = process.env.NEXT_PUBLIC_API_URL || "";
    const origin = envURL.replace(/\/api\/v1\/?$/, "") ||
                   (typeof window !== "undefined" ? window.location.origin : "");
    const script = `${origin}/api/v1/egress-sensor/download/install.sh`;
    return `f=$(mktemp) && curl -fsSL ${script} -o "$f" && sudo bash "$f" --url ${origin}`;
  }

  function copyInstallCommand() {
    const cmd = installCommand();
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(cmd).then(
        () => setNotice(t("rt.sensors.install_copied")),
        () => setNotice(t("rt.sensors.copy_manual")),
      );
    } else {
      setNotice(t("rt.sensors.copy_manual"));
    }
  }

  function renderAllowTable(side: "egress" | "ingress") {
    if (!draft) return null;
    const label = side === "egress" ? t("rt.egress_allow") : t("rt.ingress_allow");
    const hint = side === "egress" ? t("rt.egress_allow_hint") : t("rt.ingress_allow_hint");
    const destLabel = side === "egress" ? t("rt.dest") : t("rt.source");
    return (
      <div className="field" style={{ margin: 0 }}>
        <label>{label}</label>
        <p className="hint-text" style={{ marginTop: 0 }}>{hint}</p>
        {draft[side].map((row, i) => (
          <div key={i} style={{ display: "flex", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
            <input className="mono" style={{ flex: "2 1 180px" }} placeholder={side === "egress" ? "10.0.0.5/32 or *.corp.internal" : "10.0.0.0/8"}
              aria-label={destLabel} value={row.dest} onChange={(e) => setAllow(side, i, { dest: e.target.value })} />
            <input className="mono" style={{ flex: "1 1 120px" }} placeholder={t("rt.ports_ph")}
              aria-label={t("rt.ports")} value={row.ports} onChange={(e) => setAllow(side, i, { ports: e.target.value })} />
            <div style={{ flex: "1 1 180px", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", fontSize: 13 }}>
              {PROTOCOLS.map((p) => (
                <label key={p} style={{ display: "flex", gap: 4, alignItems: "center", fontWeight: 400 }}>
                  <input
                    type="checkbox"
                    style={{ width: "auto" }}
                    checked={row.protocols.includes(p)}
                    onChange={(e) => {
                      const next = e.target.checked
                        ? [...row.protocols, p]
                        : row.protocols.filter((x) => x !== p);
                      setAllow(side, i, { protocols: next });
                    }}
                  />
                  <span>{p.toUpperCase()}</span>
                </label>
              ))}
            </div>
            <button type="button" className="btn btn-sm" aria-label={t("rt.remove_row")} onClick={() => removeAllow(side, i)}>×</button>
          </div>
        ))}
        {draft[side].length < 100 && (
          <button type="button" className="btn btn-sm" onClick={() => addAllow(side)}>
            {side === "egress" ? t("rt.add_dest") : t("rt.add_source")}
          </button>
        )}
      </div>
    );
  }

  return (
    <>
      <PageHeader title={t("rt.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("rt.intro")}</p>
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- policy settings ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("rt.sensors.settings_title")}</h2>
            {!settingsOpen && (
              <button className="btn btn-sm" disabled={busy || !settings} onClick={() => setSettingsOpen(true)}>
                {t("rt.sensors.settings_edit")}
              </button>
            )}
          </div>

          {settingsOpen ? (
            <div className="panel-body">
              <form onSubmit={saveSettings} className="ag-stack">
                <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                  <div className="field" style={{ margin: 0, flex: "1 1 200px" }}>
                    <label htmlFor="rt-set-refresh">{t("rt.sensors.set_refresh")}</label>
                    <select id="rt-set-refresh"
                      value={settingsDraft.refresh_seconds ?? 30}
                      onChange={(e) => setSettingsDraft({ ...settingsDraft, refresh_seconds: Number(e.target.value) })}>
                      {[30, 60, 120, 300].map(n => <option key={n} value={n}>{n}s</option>)}
                    </select>
                    <p className="hint-text">{t("rt.sensors.set_refresh_hint")}</p>
                  </div>

                  <div className="field" style={{ margin: 0, flex: "1 1 200px" }}>
                    <label htmlFor="rt-set-heartbeat">{t("rt.sensors.set_heartbeat")}</label>
                    <select id="rt-set-heartbeat"
                      value={settingsDraft.heartbeat_seconds ?? 30}
                      onChange={(e) => setSettingsDraft({ ...settingsDraft, heartbeat_seconds: Number(e.target.value) })}>
                      {[30, 60, 120].map(n => <option key={n} value={n}>{n}s</option>)}
                    </select>
                    <p className="hint-text">{t("rt.sensors.set_heartbeat_hint")}</p>
                  </div>

                  <div className="field" style={{ margin: 0, flex: "1 1 200px" }}>
                    <label htmlFor="rt-set-mode">{t("rt.sensors.set_default_mode")}</label>
                    <select id="rt-set-mode"
                      value={settingsDraft.default_mode ?? "observe"}
                      onChange={(e) => setSettingsDraft({ ...settingsDraft, default_mode: e.target.value as RuntimeMode })}>
                      {RUNTIME_MODES.map(m => <option key={m} value={m}>{t(`rt.modes.${m}`)}</option>)}
                    </select>
                    <p className="hint-text">{t("rt.sensors.set_default_mode_hint")}</p>
                  </div>

                  <div className="field" style={{ margin: 0, flex: "1 1 200px" }}>
                    <label htmlFor="rt-set-dns">{t("rt.sensors.set_default_dns")}</label>
                    <select id="rt-set-dns"
                      value={settingsDraft.default_dns ?? "off"}
                      onChange={(e) => setSettingsDraft({ ...settingsDraft, default_dns: e.target.value as DNSMode })}>
                      {DNS_MODES.map(m => <option key={m} value={m}>{t(`rt.dns.${m}`)}</option>)}
                    </select>
                    <p className="hint-text">{t("rt.sensors.set_default_dns_hint")}</p>
                  </div>

                  <div className="field" style={{ margin: 0, flex: "1 1 200px" }}>
                    <label htmlFor="rt-set-retention">{t("rt.sensors.set_retention")}</label>
                    <select id="rt-set-retention"
                      value={settingsDraft.activity_retention_days ?? 30}
                      onChange={(e) => setSettingsDraft({ ...settingsDraft, activity_retention_days: Number(e.target.value) })}>
                      {RETENTION_OPTIONS.map(n => (
                        <option key={n} value={n}>{retentionLabel(t, n)}</option>
                      ))}
                    </select>
                    <p className="hint-text">{t("rt.sensors.set_retention_hint")}</p>
                  </div>

                  <div className="field" style={{ margin: 0, flex: "1 1 200px" }}>
                    <label htmlFor="rt-set-violation-retention">{t("rt.sensors.set_violation_retention")}</label>
                    <select id="rt-set-violation-retention"
                      value={settingsDraft.violation_retention_days ?? 30}
                      onChange={(e) => setSettingsDraft({ ...settingsDraft, violation_retention_days: Number(e.target.value) })}>
                      {RETENTION_OPTIONS.map(n => (
                        <option key={n} value={n}>{retentionLabel(t, n)}</option>
                      ))}
                    </select>
                    <p className="hint-text">{t("rt.sensors.set_violation_retention_hint")}</p>
                  </div>
                </div>

                <p className="hint-text" style={{ margin: 0 }}>
                  {t("rt.sensors.set_load_hint", {
                    n: sensors.length,
                    rps: ((sensors.length * 2) / Math.max(1, settingsDraft.refresh_seconds ?? 30)).toFixed(2),
                  })}
                </p>

                <div className="ag-actions">
                  <button className="btn btn-primary" type="submit" disabled={busy}>{t("rt.save")}</button>
                  <button className="btn" type="button" onClick={cancelSettings}>{t("rt.cancel")}</button>
                </div>
              </form>
            </div>
          ) : (
            <div className="panel-body" style={{ fontSize: 13 }}>
              {settings ? (
                <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                  <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.set_refresh")}:</em> {settings.refresh_seconds}s</span>
                  <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.set_heartbeat")}:</em> {settings.heartbeat_seconds}s</span>
                  <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.set_default_mode")}:</em> {t(`rt.modes.${settings.default_mode}`)}</span>
                  <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.set_default_dns")}:</em> {t(`rt.dns.${settings.default_dns}`)}</span>
                  <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.set_retention")}:</em> {retentionLabel(t, settings.activity_retention_days)}</span>
                  <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.set_violation_retention")}:</em> {retentionLabel(t, settings.violation_retention_days)}</span>
                </div>
              ) : (
                <span className="hint-text">{t("rt.sensors.loading")}</span>
              )}
            </div>
          )}
        </section>

        {/* ---------------- signing key ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("rt.sensors.signing_key_title")}</h2>
          </div>

          <div className="panel-body" style={{ fontSize: 13 }}>
            {signingKey ? (
              <>
                <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "center" }}>
                  <span>
                    <em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.signing_key_current")}:</em>{" "}
                    <span className="mono ag-small">{signingKey.fingerprint}</span>
                  </span>
                  <button className="btn btn-sm btn-danger" disabled={busy} onClick={rotateKey}>
                    {t("rt.sensors.rotate_key")}
                  </button>
                </div>

                {signingKey.previous_public_key && (
                  <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--border, #333)" }}>
                    <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "center" }}>
                      <span>
                        <em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.signing_key_previous")}:</em>{" "}
                        <span className="mono ag-small">{signingKey.previous_fingerprint}</span>
                      </span>
                      {signingKey.previous_valid_until && (
                        <span className="hint-text">
                          {t("rt.sensors.signing_key_valid_until", {
                            when: fmt(signingKey.previous_valid_until),
                          })}
                        </span>
                      )}
                      <button className="btn btn-sm btn-danger" disabled={busy} onClick={finalizeKey}>
                        {t("rt.sensors.finalize_key")}
                      </button>
                    </div>
                    <p className="hint-text" style={{ marginTop: 6, marginBottom: 0 }}>
                      {t("rt.sensors.finalize_hint")}
                    </p>
                  </div>
                )}
              </>
            ) : (
              <span className="hint-text">{t("rt.sensors.loading")}</span>
            )}
          </div>
        </section>

        {/* ---------------- sensors ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("rt.sensors.title")}</h2>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <label style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400, fontSize: 13 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={showRevokedSensors}
                  onChange={(e) => setShowRevokedSensors(e.target.checked)} />
                <span>{t("rt.sensors.show_revoked")}</span>
              </label>
              {!showRegister && !newKey && (
                <button className="btn btn-sm btn-primary" onClick={() => { setShowRegister(true); setError(null); setNotice(null); }}>
                  {t("rt.sensors.register")}
                </button>
              )}
            </div>
          </div>

          {newKey && (
            <div className="panel-body" style={{ borderLeft: "3px solid var(--accent, #c8792a)" }}>
              <h3 style={{ margin: 0 }}>{t("rt.sensors.key_title", { name: newKey.name })}</h3>
              <p className="hint-text">{t("rt.sensors.key_hint")}</p>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
                <input readOnly value={newKey.api_key} onFocus={(e) => e.currentTarget.select()}
                  className="mono" style={{ flex: "1 1 260px", padding: "8px 12px" }}
                  aria-label={t("rt.sensors.key_title", { name: newKey.name })} />
                <button type="button" className="btn btn-sm" onClick={() => copyKey(newKey.api_key)}>{t("rt.sensors.copy")}</button>
              </div>

              <p className="hint-text" style={{ marginTop: 16, marginBottom: 4 }}>{t("rt.sensors.install_hint")}</p>
              <div style={{ display: "flex", gap: 8, alignItems: "flex-start", flexWrap: "wrap" }}>
                <textarea readOnly value={installCommand()} onFocus={(e) => e.currentTarget.select()}
                  className="mono" rows={2}
                  style={{ flex: "1 1 380px", padding: "8px 12px", resize: "vertical", fontSize: 12 }}
                  aria-label={t("rt.sensors.install_command")} />
                <button type="button" className="btn btn-sm btn-primary" onClick={() => copyInstallCommand()}>
                  {t("rt.sensors.copy_install")}
                </button>
              </div>

              <div className="ag-actions" style={{ marginTop: 12 }}>
                <button className="btn btn-primary" onClick={() => { setNewKey(null); loadSensors(); }}>{t("rt.sensors.key_saved")}</button>
              </div>
            </div>
          )}

          {showRegister && !newKey && (
            <div className="panel-body">
              <form onSubmit={registerSensorSubmit} className="ag-stack">
                <h3 style={{ margin: 0 }}>{t("rt.sensors.register")}</h3>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-sensor-name">{t("rt.sensors.name")}</label>
                  <input id="rt-sensor-name" maxLength={255} required value={sensorName}
                    onChange={(e) => setSensorName(e.target.value)} />
                  <p className="hint-text">{t("rt.sensors.name_hint")}</p>
                </div>
                <div className="ag-actions">
                  <button className="btn btn-primary" type="submit" disabled={busy}>{t("rt.sensors.register")}</button>
                  <button className="btn" type="button" onClick={() => { setShowRegister(false); setSensorName(""); setError(null); }}>{t("rt.cancel")}</button>
                </div>
              </form>
            </div>
          )}

          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("rt.sensors.name")}</th>
                  <th>{t("rt.sensors.host")}</th>
                  <th>{t("rt.sensors.version")}</th>
                  <th>{t("rt.sensors.enforcing")}</th>
                  <th>{t("rt.sensors.hooks")}</th>
                  <th>{t("rt.sensors.last_seen")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {sensors.length === 0 && (
                  <tr className="empty-row"><td colSpan={7} className="hint-text" style={{ padding: 20 }}>{t("rt.sensors.none")}</td></tr>
                )}
                {sensors.map((s) => {
                  const revoked = s.revoked_at !== null;
                  const inactive = revoked || !s.enabled;
                  return (
                    <>
                    <tr key={s.id} style={inactive ? { opacity: 0.6 } : undefined}>
                      <td data-label={t("rt.sensors.name")}>
                        <button
                          type="button"
                          className="btn btn-sm"
                          style={{ padding: "0 6px", marginRight: 6 }}
                          aria-expanded={expandedSensorId === s.id}
                          aria-label={t("rt.sensors.toggle_details")}
                          onClick={() => toggleSensorDetails(s.id)}
                        >
                          {expandedSensorId === s.id ? "▾" : "▸"}
                        </button>
                        <strong>{s.name}</strong>
                        {revoked && <div><span className="pill pill-critical">{t("rt.sensors.revoked")}</span></div>}
                        {!revoked && !s.enabled && <div><span className="pill pill-neutral">{t("rt.disabled")}</span></div>}
                        <div className="hint-text mono" style={{ fontSize: 11 }}>{s.key_prefix}…</div>
                      </td>
                      <td data-label={t("rt.sensors.host")} className="mono ag-small">{s.hostname ?? "—"}</td>
                      <td data-label={t("rt.sensors.version")} className="ag-small">
                        {s.version ?? "—"}
                        {s.kernel && <div className="hint-text" style={{ fontSize: 11 }}>{s.kernel}</div>}
                      </td>
                      <td data-label={t("rt.sensors.enforcing")}>
                        {s.enforcing === null ? <span className="hint-text">—</span> : (
                          <span className={`pill ${s.enforcing ? "pill-low" : "pill-neutral"}`}>
                            {s.enforcing ? t("rt.sensors.yes") : t("rt.sensors.no")}
                          </span>
                        )}
                      </td>
                      <td data-label={t("rt.sensors.hooks")} className="ag-small">
                        {s.hooks && s.hooks.length > 0 ? s.hooks.length : "—"}
                        {s.warnings && s.warnings.length > 0 && (
                          <div className="hint-text" style={{ fontSize: 11 }} title={s.warnings.join("\n")}>⚠ {s.warnings.length}</div>
                        )}
                        {s.errors && s.errors.length > 0 && (
                          <div className="hint-text" style={{ fontSize: 11, color: "var(--danger, #c0392b)" }} title={s.errors.join("\n")}>✕ {s.errors.length}</div>
                        )}
                      </td>
                      <td data-label={t("rt.sensors.last_seen")} className="ag-period">
                        {s.last_seen_at ? fmt(s.last_seen_at) : <span className="hint-text">{t("rt.sensors.never")}</span>}
                      </td>
                      <td>
                        <div className="ag-row-actions">
                          {!revoked && (
                            <button className="btn btn-sm" disabled={busy} onClick={() => forceRefresh(s)}>
                              {t("rt.sensors.force_refresh")}
                            </button>
                          )}
                          {!revoked && (
                            <button className="btn btn-sm" disabled={busy} onClick={() => toggleSensor(s)}>
                              {s.enabled ? t("rt.disable") : t("rt.enable")}
                            </button>
                          )}
                          {!revoked && (
                            <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => revoke(s)}>{t("rt.sensors.revoke")}</button>
                          )}
                          {!revoked && (
                            <button className="btn btn-sm" disabled={busy} onClick={() => uninstallReminder(s)}>{t("rt.sensors.uninstall")}</button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expandedSensorId === s.id && (
                      <tr className="sensor-details-row">
                        <td colSpan={7} style={{ padding: "14px 20px 18px 52px" }}>
                          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55 }}>
                                {t("rt.sensors.hooks_list")}
                              </div>
                              {s.hooks && s.hooks.length > 0
                                ? <div className="mono" style={{ fontSize: 12, lineHeight: 1.6, wordBreak: "break-word" }}>
                                    <span style={{ opacity: 0.6 }}>({s.hooks.length})</span> {[...s.hooks].sort().join(" · ")}
                                  </div>
                                : <div style={{ fontSize: 12, opacity: 0.5, fontStyle: "italic" }}>{t("rt.sensors.never")}</div>}
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55 }}>
                                ⚠ {t("rt.sensors.warnings_list")}
                              </div>
                              {s.warnings && s.warnings.length > 0
                                ? s.warnings.map((w, i) => (
                                    <div key={i} style={{ fontSize: 12, lineHeight: 1.6 }}>{w}</div>
                                  ))
                                : <div style={{ fontSize: 12, opacity: 0.5, fontStyle: "italic" }}>{t("rt.sensors.never")}</div>}
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55, color: s.errors && s.errors.length > 0 ? "var(--danger, #c0392b)" : undefined }}>
                                ✕ {t("rt.sensors.errors_list")}
                              </div>
                              {s.errors && s.errors.length > 0
                                ? s.errors.map((e, i) => (
                                    <div key={i} style={{ fontSize: 12, lineHeight: 1.6, color: "var(--danger, #c0392b)" }}>{e}</div>
                                  ))
                                : <div style={{ fontSize: 12, opacity: 0.5, fontStyle: "italic" }}>{t("rt.sensors.never")}</div>}
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55 }}>
                                {t("rt.sensors.runtime_section")}
                              </div>
                              <div style={{ display: "flex", gap: 18, flexWrap: "wrap", fontSize: 12 }}>
                                <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.kernel")}</em> {s.kernel ?? "—"}</span>
                                <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.config_version")}</em> {s.config_version ?? "—"}</span>
                                <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.dropped_events")}</em> {s.dropped_events}</span>
                                <span><em style={{ opacity: 0.6, fontStyle: "normal" }}>{t("rt.sensors.last_seen")}</em> {s.last_seen_at ? fmt(s.last_seen_at) : t("rt.sensors.never")}</span>
                              </div>
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55 }}>
                                {t("rt.sensors.workloads_snapshot")}
                              </div>
                              {sensorWorkloads[s.id] === undefined || sensorWorkloads[s.id] === null ? (
                                <div style={{ fontSize: 12, opacity: 0.6 }}>{t("rt.sensors.loading")}</div>
                              ) : sensorWorkloads[s.id]!.length === 0 ? (
                                <div style={{ fontSize: 12, opacity: 0.5, fontStyle: "italic" }}>{t("rt.sensors.no_workloads_snapshot")}</div>
                              ) : (
                                <table className="table-cards" style={{ fontSize: 12, marginTop: 4 }}>
                                  <thead>
                                    <tr>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.workload")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.snap_cgroups")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.snap_processes")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.snap_dns")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.snap_updated")}</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {sensorWorkloads[s.id]!.map(wl => (
                                      <tr key={wl.workload_id}>
                                        <td style={{ padding: "4px 8px" }}>
                                          <strong>#{wl.workload_id}</strong> {wl.workload_name}
                                        </td>
                                        <td style={{ padding: "4px 8px" }}>{wl.cgroups}</td>
                                        <td style={{ padding: "4px 8px" }}>{wl.processes}</td>
                                        <td style={{ padding: "4px 8px" }} className="mono">
                                          {wl.dns_port === null
                                            ? <span style={{ opacity: 0.5 }}>—</span>
                                            : <span>
                                                :{wl.dns_port}{" "}
                                                <span style={{ opacity: 0.7 }}>
                                                  {wl.dns_allowed}/{wl.dns_total}
                                                  {wl.dns_denied > 0 && <span style={{ color: "var(--danger, #c0392b)" }}> ({t("rt.sensors.snap_denied")} {wl.dns_denied})</span>}
                                                </span>
                                              </span>}
                                        </td>
                                        <td style={{ padding: "4px 8px", opacity: 0.6 }}>{fmt(wl.updated_at)}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              )}
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55 }}>
                                {t("rt.sensors.commands_section")}
                              </div>

                              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                                <button className="btn btn-sm" disabled={busy}
                                  onClick={() => queueCommand(s, "dump-state")}>
                                  {t("rt.sensors.cmd_dump")}
                                </button>
                                <button className="btn btn-sm" disabled={busy}
                                  onClick={() => queueCommand(s, "restart")}>
                                  {t("rt.sensors.cmd_restart")}
                                </button>
                                <button className="btn btn-sm btn-danger" disabled={busy}
                                  onClick={() => queueCommand(s, "detach")}>
                                  {t("rt.sensors.cmd_detach")}
                                </button>
                              </div>

                              {sensorCommands[s.id] === undefined || sensorCommands[s.id] === null ? (
                                <div style={{ fontSize: 12, opacity: 0.6 }}>{t("rt.sensors.loading")}</div>
                              ) : sensorCommands[s.id]!.length === 0 ? (
                                <div style={{ fontSize: 12, opacity: 0.5, fontStyle: "italic" }}>{t("rt.sensors.cmd_none")}</div>
                              ) : (
                                <table className="table-cards" style={{ fontSize: 12 }}>
                                  <thead>
                                    <tr>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.cmd_col_kind")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.cmd_col_status")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.cmd_col_issued")}</th>
                                      <th style={{ padding: "4px 8px" }}>{t("rt.sensors.cmd_col_acked")}</th>
                                      <th style={{ padding: "4px 8px" }} />
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {sensorCommands[s.id]!.map(c => (
                                      <React.Fragment key={c.id}>
                                        <tr>
                                          <td style={{ padding: "4px 8px" }}>{t(`rt.sensors.cmd_kind.${c.kind}`)}</td>
                                          <td style={{ padding: "4px 8px" }}>
                                            <span className={`pill ${CMD_STATUS_PILL[c.status]}`}>
                                              {t(`rt.sensors.cmd_status.${c.status}`)}
                                            </span>
                                          </td>
                                          <td style={{ padding: "4px 8px", opacity: 0.6 }}>{fmt(c.issued_at)}</td>
                                          <td style={{ padding: "4px 8px", opacity: 0.6 }}>{c.acked_at ? fmt(c.acked_at) : "—"}</td>
                                          <td style={{ padding: "4px 8px" }}>
                                            {c.result && (
                                              <button className="btn btn-sm"
                                                onClick={() => setShowCommandResult(prev => ({ ...prev, [c.id]: !prev[c.id] }))}>
                                                {showCommandResult[c.id] ? t("rt.sensors.cmd_hide_result") : t("rt.sensors.cmd_show_result")}
                                              </button>
                                            )}
                                            {c.error && (
                                              <span style={{ color: "var(--danger, #c0392b)", fontSize: 11 }}>{c.error}</span>
                                            )}
                                          </td>
                                        </tr>
                                        {showCommandResult[c.id] && c.result && (
                                          <tr>
                                            <td colSpan={5} style={{ padding: "4px 8px" }}>
                                              <pre className="mono" style={{ fontSize: 11, lineHeight: 1.5, maxHeight: 320, overflow: "auto", margin: 0, padding: 8 }}>
                                                {JSON.stringify(c.result, null, 2)}
                                              </pre>
                                            </td>
                                          </tr>
                                        )}
                                      </React.Fragment>
                                    ))}
                                  </tbody>
                                </table>
                              )}
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, opacity: 0.55 }}>
                                {t("rt.sensors.activity_section")}
                              </div>
                              <SensorActivity sensor={s} />
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ---------------- workloads ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("rt.workloads")}</h2>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <label style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400, fontSize: 13 }}>
                <input type="checkbox" style={{ width: "auto" }} checked={showDeleted}
                  onChange={(e) => setShowDeleted(e.target.checked)} />
                <span>{t("rt.show_deleted")}</span>
              </label>
              {!draft && <button className="btn btn-sm btn-primary" onClick={() => edit({ ...EMPTY, egress: [{ ...EMPTY_ALLOW }], ingress: [] })}>{t("rt.new")}</button>}
            </div>
          </div>

          {draft && (
            <div className="panel-body">
              <form onSubmit={save} className="ag-stack">
                <h3 style={{ margin: 0 }}>{draft.id === null ? t("rt.new") : t("rt.edit", { name: draft.name })}</h3>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-name">{t("rt.name")}</label>
                  <input id="rt-name" maxLength={255} required value={draft.name}
                    onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
                </div>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-agent">{t("rt.agent")}</label>
                  <select id="rt-agent" value={draft.agentId} onChange={(e) => setDraft({ ...draft, agentId: e.target.value })}>
                    <option value="">{t("rt.no_agent")}</option>
                    {agents.filter((a) => a.status !== "retired").map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                  </select>
                  <p className="hint-text">{t("rt.agent_hint")}</p>
                </div>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-patterns">{t("rt.patterns")}</label>
                  <textarea id="rt-patterns" className="mono" rows={3} value={draft.patterns}
                    placeholder="system.slice/billing-agent.service"
                    onChange={(e) => setDraft({ ...draft, patterns: e.target.value })} />
                  <p className="hint-text">{t("rt.patterns_hint")}</p>
                </div>

                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-runas">{t("rt.run_as_users")}</label>
                  <textarea id="rt-runas" className="mono" rows={2} value={draft.runAs}
                    placeholder="svc-billing&#10;ci-runner"
                    onChange={(e) => setDraft({ ...draft, runAs: e.target.value })} />
                  <p className="hint-text">{t("rt.run_as_users_hint")}</p>
                </div>

                {renderAllowTable("egress")}
                {renderAllowTable("ingress")}

                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-dns">{t("rt.dns_mode")}</label>
                  <select id="rt-dns" value={draft.dns} onChange={(e) => setDraft({ ...draft, dns: e.target.value as DNSMode })}>
                    {DNS_MODES.map((m) => <option key={m} value={m}>{t(`rt.dns.${m}`)}</option>)}
                  </select>
                  <p className="hint-text">{t(`rt.dns_hint.${draft.dns}`)}</p>
                </div>

                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-mode">{t("rt.mode")}</label>
                  <select id="rt-mode" value={draft.mode} onChange={(e) => setDraft({ ...draft, mode: e.target.value as RuntimeMode })}>
                    {RUNTIME_MODES.map((m) => <option key={m} value={m}>{t(`rt.modes.${m}`)}</option>)}
                  </select>
                  <p className="hint-text">{t(`rt.mode_hint.${draft.mode}`)}</p>
                </div>

                <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
                  <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={draft.isolated}
                    onChange={(e) => setDraft({ ...draft, isolated: e.target.checked })} />
                  <span>{t("rt.isolated")}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("rt.isolated_hint")}</span></span>
                </label>

                {draft.isolated && (
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="rt-isolated-reason">{t("rt.isolated_reason")}</label>
                    <input id="rt-isolated-reason" maxLength={500} value={draft.isolatedReason}
                      onChange={(e) => setDraft({ ...draft, isolatedReason: e.target.value })} />
                  </div>
                )}

                <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                  <input type="checkbox" style={{ width: "auto" }} checked={draft.enabled}
                    onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
                  <span>{t("rt.enabled")}</span>
                </label>

                <div className="ag-actions">
                  <button className="btn btn-primary" type="submit" disabled={busy}>{t("rt.save")}</button>
                  <button className="btn" type="button" onClick={() => setDraft(null)}>{t("rt.cancel")}</button>
                </div>
              </form>
            </div>
          )}

          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("rt.name")}</th>
                  <th>{t("rt.agent")}</th>
                  <th>{t("rt.patterns")}</th>
                  <th>{t("rt.allow")}</th>
                  <th>{t("rt.dns_mode")}</th>
                  <th>{t("rt.mode")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {workloads.length === 0 && (
                  <tr className="empty-row"><td colSpan={7} className="hint-text" style={{ padding: 20 }}>{t("rt.no_workloads")}</td></tr>
                )}
                {workloads.map((w) => {
                  const deleted = w.deleted_at !== null;
                  const inactive = deleted || !w.enabled;
                  return (
                    <tr key={w.id} style={inactive ? { opacity: 0.6 } : undefined}>
                      <td data-label={t("rt.name")}>
                        <strong>{w.name}</strong>
                        {deleted && <div><span className="pill pill-critical">{t("rt.deleted_pill")}</span></div>}
                        {!deleted && !w.enabled && <div><span className="pill pill-neutral">{t("rt.disabled")}</span></div>}
                        {w.isolated && <div><span className="pill pill-medium">{t("rt.isolated_pill")}</span></div>}
                      </td>
                      <td data-label={t("rt.agent")}>
                        {w.agent_id ? <Link href={`/agents/${w.agent_id}`}>{agentName.get(w.agent_id) ?? `#${w.agent_id}`}</Link> : "—"}
                      </td>
                      <td data-label={t("rt.patterns")} className="mono ag-small">
                        {w.cgroup_patterns.map((p) => <div key={p}>{p}</div>)}
                        {w.run_as_users.length > 0 && (
                          <div className="hint-text" style={{ fontSize: 11 }}>{t("rt.as_users", { list: w.run_as_users.join(", ") })}</div>
                        )}
                      </td>
                      <td data-label={t("rt.allow")} className="mono ag-small">
                        {w.egress_allow.length === 0 && <span className="hint-text">{t("rt.nothing_allowed")}</span>}
                        {w.egress_allow.map((a, i) => (
                          <div key={i}>
                            {a.dest} {a.ports.length ? `: ${a.ports.join(", ")}` : `: ${t("rt.any_port")}`}
                            {a.protocols.length > 0 && <span className="hint-text"> [{a.protocols.join(",")}]</span>}
                          </div>
                        ))}
                        {w.ingress_allow.length > 0 && (
                          <div className="hint-text" style={{ fontSize: 11 }}>
                            {t("rt.ingress_summary", { count: w.ingress_allow.length })}
                          </div>
                        )}
                      </td>
                      <td data-label={t("rt.dns_mode")} className="ag-small">{t(`rt.dns.${w.dns}`)}</td>
                      <td data-label={t("rt.mode")}><span className={`pill ${MODE_PILL[w.mode]}`}>{t(`rt.modes.${w.mode}`)}</span></td>
                      <td>
                        <div className="ag-row-actions">
                          {!deleted && <button className="btn btn-sm" disabled={busy} onClick={() => edit(toDraft(w))}>{t("rt.edit_btn")}</button>}
                          {!deleted && <button className="btn btn-sm" disabled={busy} onClick={() => toggle(w)}>{w.enabled ? t("rt.disable") : t("rt.enable")}</button>}
                          {!deleted && <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => remove(w)}>{t("rt.delete")}</button>}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ---------------- violations ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("rt.violations")}</h2>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <select aria-label={t("rt.filter_workload")} value={filterWl} onChange={(e) => setFilterWl(e.target.value)}>
                <option value="">{t("rt.all_workloads")}</option>
                {workloads.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
              </select>
              <select aria-label={t("rt.filter_action")} value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
                <option value="">{t("rt.all_actions")}</option>
                {VIOLATION_ACTIONS.map((a) => <option key={a} value={a}>{t(`rt.actions.${a}`)}</option>)}
              </select>
              <button className="btn btn-sm" onClick={loadViolations}>{t("rt.refresh")}</button>
            </div>
          </div>
          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("rt.last_seen")}</th>
                  <th>{t("rt.workload")}</th>
                  <th>{t("rt.kind")}</th>
                  <th>{t("rt.action")}</th>
                  <th>{t("rt.destination")}</th>
                  <th>{t("rt.process")}</th>
                  <th>{t("rt.count")}</th>
                </tr>
              </thead>
              <tbody>
                {violations.length === 0 && (
                  <tr className="empty-row"><td colSpan={7} className="hint-text" style={{ padding: 20 }}>{t("rt.no_violations")}</td></tr>
                )}
                {violations.map((v) => (
                  <tr key={v.id}>
                    <td data-label={t("rt.last_seen")} className="ag-period">{fmt(v.created_at)}</td>
                    <td data-label={t("rt.workload")}>
                      {v.workload_id ? (wlName.get(v.workload_id) ?? `#${v.workload_id}`) : <span className="hint-text">{t("rt.deleted_workload")}</span>}
                    </td>
                    <td data-label={t("rt.kind")} className="ag-small">{v.kind}</td>
                    <td data-label={t("rt.action")}><span className={`pill ${ACTION_PILL[v.action]}`}>{t(`rt.actions.${v.action}`)}</span></td>
                    <td data-label={t("rt.destination")} className="mono ag-small">{dest(v)}</td>
                    <td data-label={t("rt.process")} className="ag-small">
                      <span className="mono">{v.comm ?? "?"}</span>
                      {v.cgroup && <div className="hint-text mono" style={{ fontSize: 11, wordBreak: "break-all" }}>{v.cgroup}</div>}
                    </td>
                    <td data-label={t("rt.count")}>{v.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
