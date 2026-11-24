"use client";

// The agent's own network (docs/egress-lockdown.md, "The agent's network"):
// every agent has a workload in observe mode from the start. Attached to the
// service or container it runs as - picked from what the host's sensor
// lists - everything it connects to is recorded, nothing is blocked; this
// panel lists where it went, and an administrator allows those destinations
// and enforces in one step. Without the sensor only its MCP calls go
// through Provenza, and the panel says so.

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { errorMessage } from "@/lib/errors";
import { usePollWhileVisible } from "@/lib/use_poll";
import {
  attachAgentUnit, detachAgentUnit, enforceAgentNetwork, getAgentNetwork, observeAgentNetwork,
  type AgentDestinationT, type AgentHostT, type AgentNetworkT, type HostUnitT,
} from "@/lib/agent_network_api";

const key = (d: AgentDestinationT) => `${d.dest}|${d.port ?? ""}|${d.protocol ?? ""}`;

/** how a listed service or container reads */
export function unitLabel(u: HostUnitT): string {
  if (u.kind === "service") return u.name ?? u.cgroup;
  const what = u.name ? `${u.name} (${u.id})` : (u.id ?? u.cgroup);
  return `${u.runtime ?? "container"}: ${what}`;
}

/** The services and containers the sensors listed: pick what the agent runs as. */
function AttachPicker({ hosts, busy, onAttach, onClose }: {
  hosts: AgentHostT[]; busy: boolean; onAttach: (sensorId: number, cgroup: string) => void; onClose: () => void;
}) {
  const { t } = useTranslation();
  const [sensorId, setSensorId] = useState<number>(hosts[0]?.sensor_id ?? 0);
  const [q, setQ] = useState("");
  const host = hosts.find((h) => h.sensor_id === sensorId) ?? hosts[0];
  if (!host) {
    return (
      <div>
        <p className="hint-text">{t("agent_net.no_hosts")}</p>
        <button type="button" className="btn btn-sm" onClick={onClose}>{t("common.cancel")}</button>
      </div>
    );
  }
  const needle = q.trim().toLowerCase();
  const units = host.units.filter((u) => !needle || unitLabel(u).toLowerCase().includes(needle)
    || u.cgroup.toLowerCase().includes(needle));
  return (
    <div className="ag-stack" style={{ border: "1px solid var(--border)", borderRadius: 6, padding: 10 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {hosts.length > 1 && (
          <select className="input" aria-label={t("agent_net.host")} value={host.sensor_id}
            onChange={(e) => setSensorId(Number(e.target.value))}>
            {hosts.map((h) => <option key={h.sensor_id} value={h.sensor_id}>{h.hostname ?? h.sensor}</option>)}
          </select>
        )}
        {hosts.length === 1 && <strong>{host.hostname ?? host.sensor}</strong>}
        <input className="input" placeholder={t("agent_net.search")} aria-label={t("agent_net.search")}
          value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1, minWidth: 160 }} />
        <button type="button" className="btn btn-sm" onClick={onClose}>{t("common.cancel")}</button>
      </div>
      {units.length === 0 ? <p className="hint-text">{t("agent_net.no_units")}</p> : (
        <div style={{ maxHeight: 280, overflowY: "auto" }}>
          {units.map((u) => (
            <div key={u.cgroup} style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 0" }}>
              <span className="pill">{t(`agent_net.kind_${u.kind}`)}</span>
              <span className="mono" style={{ fontSize: 12, flex: 1 }} title={u.cgroup}>{unitLabel(u)}</span>
              {u.attached ? <span className="hint-text">{t("agent_net.attached")}</span>
                : u.taken_by ? <span className="hint-text">{t("agent_net.taken_by", { name: u.taken_by })}</span>
                : <button type="button" className="btn btn-sm" disabled={busy}
                    onClick={() => onAttach(host.sensor_id, u.cgroup)}>{t("agent_net.attach")}</button>}
            </div>
          ))}
        </div>
      )}
      {host.units.some((u) => u.kind === "container") && <p className="hint-text ag-small">{t("agent_net.container_hint")}</p>}
    </div>
  );
}

export function AgentNetwork({ agentId }: { agentId: number }) {
  const { t, i18n } = useTranslation();
  const [net, setNet] = useState<AgentNetworkT | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [picking, setPicking] = useState(false);
  // destinations left out of the allow list (all are in by default)
  const [unchecked, setUnchecked] = useState<Set<string>>(new Set());

  const load = useCallback(() => {
    getAgentNetwork(agentId).then((n) => { setNet(n); setError(null); })
      .catch((err) => setError(errorMessage(err, t, t("agent_net.load_failed"))));
  }, [agentId, t]);
  useEffect(load, [load]);
  usePollWhileVisible(load, 30_000);

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");

  async function observe() {
    setBusy(true);
    try { setNet(await observeAgentNetwork(agentId)); setError(null); }
    catch (err) { setError(errorMessage(err, t, t("agent_net.save_failed"))); }
    finally { setBusy(false); }
  }

  async function act(fn: () => Promise<AgentNetworkT>) {
    setBusy(true);
    try { setNet(await fn()); setError(null); setPicking(false); }
    catch (err) { setError(errorMessage(err, t, t("agent_net.save_failed"))); }
    finally { setBusy(false); }
  }

  async function enforce() {
    if (!net) return;
    const chosen = net.destinations.filter((d) => !unchecked.has(key(d)));
    if (!await confirmDialog(t("agent_net.confirm_enforce", { n: chosen.length }), { danger: true })) return;
    setBusy(true);
    try {
      setNet(await enforceAgentNetwork(agentId, chosen.map((d) => ({ dest: d.dest, port: d.port, protocol: d.protocol }))));
      setError(null);
    } catch (err) { setError(errorMessage(err, t, t("agent_net.save_failed"))); }
    finally { setBusy(false); }
  }

  const w = net?.workload ?? null;
  const observing = w?.mode === "observe";
  const chosen = net ? net.destinations.filter((d) => !unchecked.has(key(d))).length : 0;

  return (
    <section className="panel ag-section">
      <div className="panel-header">
        <h2>{t("agent_net.title")}</h2>
        {w && <span className={`pill ${w.mode === "enforce" ? "pill-low" : "pill-medium"}`}>{t(`agent_net.mode_${w.mode}`)}</span>}
      </div>
      <div className="panel-body ag-stack">
        {error && <p className="error-text">{error}</p>}
        {net && !w && (
          <div>
            <p className="hint-text">{t("agent_net.none")}</p>
            <button type="button" className="btn btn-sm" disabled={busy} onClick={observe}>{t("agent_net.observe")}</button>
          </div>
        )}
        {w && net && (
          <>
            {net.running.length === 0 ? (
              <p className="hint-text">{t("agent_net.not_contained")}</p>
            ) : (
              <p className="hint-text">
                {t("agent_net.running_on", {
                  hosts: net.running.map((r) => r.hostname ? `${r.hostname} (${r.sensor})` : r.sensor).join(", "),
                })}
              </p>
            )}

            <div>
              <div className="ag-label">{t("agent_net.runs_as")}</div>
              {w.cgroup_patterns.length === 0
                ? <p className="hint-text">{t("agent_net.runs_as_none")}</p>
                : w.cgroup_patterns.map((p) => {
                    const u = net.hosts.flatMap((h) => h.units).find((x) => x.pattern === p);
                    return (
                      <div key={p} style={{ display: "flex", gap: 8, alignItems: "center", padding: "2px 0" }}>
                        <span className="mono" style={{ fontSize: 12, flex: 1 }} title={p}>{u ? unitLabel(u) : p}</span>
                        <button type="button" className="btn btn-sm" disabled={busy}
                          onClick={() => act(() => detachAgentUnit(agentId, p))}>{t("agent_net.detach")}</button>
                      </div>
                    );
                  })}
              {picking
                ? <AttachPicker hosts={net.hosts} busy={busy} onClose={() => setPicking(false)}
                    onAttach={(sid, cg) => act(() => attachAgentUnit(agentId, sid, cg))} />
                : <button type="button" className="btn btn-sm" disabled={busy} onClick={() => setPicking(true)}>
                    {t("agent_net.attach_open")}
                  </button>}
              <p className="hint-text ag-small">
                {t("agent_net.run_alt")} <code>{`provenza-sensor --agent ${agentId} run -- <command>`}</code>
              </p>
            </div>

            {w.mode !== "observe" && (
              <div>
                <div className="ag-label">{t("agent_net.allowed")}</div>
                {w.egress_allow.length === 0
                  ? <p className="hint-text">{t("agent_net.allowed_none")}</p>
                  : <div className="mono" style={{ fontSize: 12, lineHeight: 1.6 }}>
                      {w.egress_allow.map((r, i) => (
                        <div key={i}>{r.dest}{r.ports?.length ? `:${r.ports.join(",")}` : ""}{r.protocols?.length ? ` ${r.protocols.join("/")}` : ""}</div>
                      ))}
                    </div>}
              </div>
            )}

            {net.destinations.length === 0 ? (
              <p className="hint-text">{observing ? t("agent_net.no_destinations") : t("agent_net.nothing_blocked")}</p>
            ) : (
              <div className="ag-table-wrap">
                <table className="table-cards">
                  <thead>
                    <tr>
                      {observing && <th aria-label={t("agent_net.col_allow")} />}
                      <th>{t("agent_net.col_dest")}</th>
                      <th>{t("agent_net.col_port")}</th>
                      <th>{t("agent_net.col_count")}</th>
                      <th>{t("agent_net.col_last")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {net.destinations.map((d) => (
                      <tr key={key(d)}>
                        {observing && (
                          <td data-label={t("agent_net.col_allow")}>
                            <input type="checkbox" aria-label={t("agent_net.allow_one", { dest: d.dest })}
                              checked={!unchecked.has(key(d))}
                              onChange={(e) => setUnchecked((prev) => {
                                const next = new Set(prev);
                                if (e.target.checked) next.delete(key(d)); else next.add(key(d));
                                return next;
                              })} />
                          </td>
                        )}
                        <td data-label={t("agent_net.col_dest")} className="mono" style={{ fontSize: 12 }}>
                          {d.dest}
                          {!d.named && <span className="hint-text" title={t("agent_net.address_only_hint")}> ({t("agent_net.address_only")})</span>}
                          {d.blocked && <> <span className="pill pill-critical">{t("agent_net.blocked")}</span></>}
                        </td>
                        <td data-label={t("agent_net.col_port")} className="mono" style={{ fontSize: 12 }}>
                          {d.port ?? "—"}{d.protocol ? `/${d.protocol}` : ""}
                        </td>
                        <td data-label={t("agent_net.col_count")}>{d.count}</td>
                        <td data-label={t("agent_net.col_last")} className="mono" style={{ fontSize: 12 }}>{fmt(d.last_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {observing && net.destinations.length > 0 && (
              <div>
                <button type="button" className="btn btn-sm btn-primary" disabled={busy || chosen === 0} onClick={enforce}>
                  {t("agent_net.enforce", { n: chosen })}
                </button>
                <p className="hint-text ag-small">{t("agent_net.enforce_hint")}</p>
              </div>
            )}
            <Link href="/runtime" className="ag-small">{t("agent_net.runtime_link", { name: w.name })} →</Link>
          </>
        )}
      </div>
    </section>
  );
}
