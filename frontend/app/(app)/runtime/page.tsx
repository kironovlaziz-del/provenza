"use client";

// Runtime: workloads - processes on hosts, named by their cgroup v2 paths -
// whose outbound connections the Provenza runtime daemon governs, and the
// connections they made or tried outside their policy.

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { confirmDialog } from "@/components/Dialog";
import { errorMessage as apiError } from "@/lib/errors";
import { listAgents } from "@/lib/agent_api";
import type { Agent } from "@/lib/agent_types";
import {
  RUNTIME_MODES, VIOLATION_ACTIONS, createWorkload, deleteWorkload, listViolations, listWorkloads, updateWorkload,
  type RuntimeMode, type ViolationAction, type ViolationT, type WorkloadInput, type WorkloadT,
} from "@/lib/runtime_api";

interface AllowRow { cidr: string; ports: string }

interface Draft {
  id: number | null;
  name: string;
  agentId: string;
  patterns: string;
  allow: AllowRow[];
  allowDns: boolean;
  mode: RuntimeMode;
  enabled: boolean;
}

const EMPTY: Draft = {
  id: null, name: "", agentId: "", patterns: "", allow: [{ cidr: "", ports: "" }],
  allowDns: true, mode: "observe", enabled: true,
};

const MODE_PILL: Record<RuntimeMode, string> = { observe: "pill-neutral", alert: "pill-medium", enforce: "pill-low" };
const ACTION_PILL: Record<ViolationAction, string> = { observed: "pill-neutral", alerted: "pill-medium", blocked: "pill-critical" };

function toDraft(w: WorkloadT): Draft {
  return {
    id: w.id, name: w.name, agentId: w.agent_id ? String(w.agent_id) : "",
    patterns: w.cgroup_patterns.join("\n"),
    allow: w.egress_allow.length ? w.egress_allow.map((a) => ({ cidr: a.cidr, ports: a.ports.join(", ") }))
      : [{ cidr: "", ports: "" }],
    allowDns: w.allow_dns, mode: w.mode, enabled: w.enabled,
  };
}

/** The draft as the API takes it, or the key of what is wrong with it. */
function toInput(d: Draft): WorkloadInput | string {
  const patterns = d.patterns.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!d.name.trim()) return "rt.err_name";
  if (patterns.length === 0) return "rt.err_patterns";
  const allow = [];
  for (const row of d.allow) {
    if (!row.cidr.trim() && !row.ports.trim()) continue;
    if (!row.cidr.trim()) return "rt.err_cidr";
    const ports = row.ports.split(/[\s,]+/).filter(Boolean).map(Number);
    if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) return "rt.err_ports";
    allow.push({ cidr: row.cidr.trim(), ports });
  }
  return {
    name: d.name.trim(), agent_id: d.agentId ? Number(d.agentId) : null, cgroup_patterns: patterns,
    egress_allow: allow, allow_dns: d.allowDns, mode: d.mode, enabled: d.enabled,
  };
}

export default function RuntimePage() {
  const { t, i18n } = useTranslation();
  const [workloads, setWorkloads] = useState<WorkloadT[]>([]);
  const [violations, setViolations] = useState<ViolationT[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [filterWl, setFilterWl] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadWorkloads = useCallback(() => {
    listWorkloads().then(setWorkloads).catch((err) => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t]);
  const loadViolations = useCallback(() => {
    listViolations({
      workload_id: filterWl ? Number(filterWl) : undefined,
      action: (filterAction || undefined) as ViolationAction | undefined,
    }).then(setViolations).catch((err) => setError(apiError(err, t, t("rt.load_failed"))));
  }, [t, filterWl, filterAction]);
  useEffect(loadWorkloads, [loadWorkloads]);
  useEffect(loadViolations, [loadViolations]);
  useEffect(() => { listAgents(500).then(setAgents).catch(() => setAgents([])); }, []);

  const agentName = useMemo(() => new Map(agents.map((a) => [a.id, a.name])), [agents]);
  const wlName = useMemo(() => new Map(workloads.map((w) => [w.id, w.name])), [workloads]);
  const fmt = (iso: string) => new Date(iso).toLocaleString(i18n.language);
  const dest = (v: ViolationT) =>
    `${v.protocol.toUpperCase()} ${v.dst_ip.includes(":") ? `[${v.dst_ip}]` : v.dst_ip}:${v.dst_port}`;

  function edit(d: Draft) {
    setDraft(d);
    setError(null);
    setNotice(null);
  }

  function setAllow(i: number, patch: Partial<AllowRow>) {
    if (!draft) return;
    setDraft({ ...draft, allow: draft.allow.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!draft) return;
    const input = toInput(draft);
    if (typeof input === "string") {
      setError(t(input));
      return;
    }
    if (input.mode === "enforce" && input.egress_allow.length === 0
        && !await confirmDialog(t("rt.confirm_enforce_empty"), { danger: true })) return;
    setBusy(true);
    setError(null);
    try {
      if (draft.id === null) {
        await createWorkload(input);
        setNotice(t("rt.created", { name: input.name }));
      } else {
        const before = workloads.find((w) => w.id === draft.id);
        await updateWorkload(draft.id, {
          ...input,
          agent_id: input.agent_id ?? undefined,
          unlink_agent: input.agent_id === null && before?.agent_id != null,
        });
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

  return (
    <>
      <PageHeader title={t("rt.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("rt.intro")}</p>
        <p className="hint-text u-mb-16">
          {t("rt.daemon_key")} <Link href="/ingestion-sources">{t("sidebar.nav.ingestion_sources")}</Link>
        </p>
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- workloads ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("rt.workloads")}</h2>
            {!draft && <button className="btn btn-sm btn-primary" onClick={() => edit({ ...EMPTY, allow: [{ cidr: "", ports: "" }] })}>{t("rt.new")}</button>}
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
                  <label>{t("rt.allow")}</label>
                  <p className="hint-text" style={{ marginTop: 0 }}>{t("rt.allow_hint")}</p>
                  {draft.allow.map((row, i) => (
                    <div key={i} style={{ display: "flex", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                      <input className="mono" style={{ flex: "2 1 180px" }} placeholder="10.0.0.5/32" aria-label={t("rt.cidr")}
                        value={row.cidr} onChange={(e) => setAllow(i, { cidr: e.target.value })} />
                      <input className="mono" style={{ flex: "1 1 120px" }} placeholder={t("rt.ports_ph")} aria-label={t("rt.ports")}
                        value={row.ports} onChange={(e) => setAllow(i, { ports: e.target.value })} />
                      <button type="button" className="btn btn-sm" aria-label={t("rt.remove_row")}
                        onClick={() => setDraft({ ...draft, allow: draft.allow.filter((_, j) => j !== i) })}>×</button>
                    </div>
                  ))}
                  {draft.allow.length < 100 && (
                    <button type="button" className="btn btn-sm"
                      onClick={() => setDraft({ ...draft, allow: [...draft.allow, { cidr: "", ports: "" }] })}>{t("rt.add_row")}</button>
                  )}
                </div>

                <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
                  <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={draft.allowDns}
                    onChange={(e) => setDraft({ ...draft, allowDns: e.target.checked })} />
                  <span>{t("rt.allow_dns")}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("rt.allow_dns_hint")}</span></span>
                </label>

                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="rt-mode">{t("rt.mode")}</label>
                  <select id="rt-mode" value={draft.mode} onChange={(e) => setDraft({ ...draft, mode: e.target.value as RuntimeMode })}>
                    {RUNTIME_MODES.map((m) => <option key={m} value={m}>{t(`rt.modes.${m}`)}</option>)}
                  </select>
                  <p className="hint-text">{t(`rt.mode_hint.${draft.mode}`)}</p>
                </div>

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
                  <th>{t("rt.mode")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {workloads.length === 0 && (
                  <tr className="empty-row"><td colSpan={6} className="hint-text" style={{ padding: 20 }}>{t("rt.no_workloads")}</td></tr>
                )}
                {workloads.map((w) => (
                  <tr key={w.id} style={w.enabled ? undefined : { opacity: 0.6 }}>
                    <td data-label={t("rt.name")}>
                      <strong>{w.name}</strong>
                      {!w.enabled && <div><span className="pill pill-neutral">{t("rt.disabled")}</span></div>}
                    </td>
                    <td data-label={t("rt.agent")}>
                      {w.agent_id ? <Link href={`/agents/${w.agent_id}`}>{agentName.get(w.agent_id) ?? `#${w.agent_id}`}</Link> : "—"}
                    </td>
                    <td data-label={t("rt.patterns")} className="mono ag-small">
                      {w.cgroup_patterns.map((p) => <div key={p}>{p}</div>)}
                    </td>
                    <td data-label={t("rt.allow")} className="mono ag-small">
                      {w.egress_allow.length === 0 && <span className="hint-text">{t("rt.nothing_allowed")}</span>}
                      {w.egress_allow.map((a) => (
                        <div key={a.cidr + a.ports.join()}>{a.cidr} {a.ports.length ? `: ${a.ports.join(", ")}` : `: ${t("rt.any_port")}`}</div>
                      ))}
                      <div className="hint-text">{w.allow_dns ? t("rt.dns_yes") : t("rt.dns_no")}</div>
                    </td>
                    <td data-label={t("rt.mode")}><span className={`pill ${MODE_PILL[w.mode]}`}>{t(`rt.modes.${w.mode}`)}</span></td>
                    <td>
                      <div className="ag-row-actions">
                        <button className="btn btn-sm" disabled={busy} onClick={() => edit(toDraft(w))}>{t("rt.edit_btn")}</button>
                        <button className="btn btn-sm" disabled={busy} onClick={() => toggle(w)}>{w.enabled ? t("rt.disable") : t("rt.enable")}</button>
                        <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => remove(w)}>{t("rt.delete")}</button>
                      </div>
                    </td>
                  </tr>
                ))}
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
                  <th>{t("rt.host")}</th>
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
                    <td data-label={t("rt.last_seen")} className="ag-period">
                      {fmt(v.last_seen_at)}
                      <div className="hint-text" style={{ fontSize: 11 }}>{t("rt.first_seen", { when: fmt(v.first_seen_at) })}</div>
                    </td>
                    <td data-label={t("rt.workload")}>
                      {v.workload_id ? (wlName.get(v.workload_id) ?? `#${v.workload_id}`) : <span className="hint-text">{t("rt.deleted_workload")}</span>}
                      {v.agent_id && <div className="ag-small"><Link href={`/agents/${v.agent_id}`}>{agentName.get(v.agent_id) ?? `#${v.agent_id}`}</Link></div>}
                    </td>
                    <td data-label={t("rt.host")}>{v.host}</td>
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
