"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { listAgents } from "@/lib/agent_api";
import type { Agent } from "@/lib/agent_types";
import {
  breakerError,
  deleteAgentBreaker,
  getBreakerSettings,
  listBreakerChains,
  resumeChain,
  setAgentBreaker,
  terminateChain,
  updateOrgBreaker,
  type BreakerChain,
  type BreakerConfig,
  type BreakerField,
  type BreakerSettings,
} from "@/lib/breaker_api";

const FIELDS: BreakerField[] = ["window_seconds", "max_denials", "max_incidents", "max_attempts"];

function ConfigFields({
  value,
  onChange,
  bounds,
  disabled,
  idPrefix,
}: {
  value: BreakerConfig;
  onChange: (v: BreakerConfig) => void;
  bounds: BreakerSettings["bounds"];
  disabled?: boolean;
  idPrefix: string;
}) {
  const { t } = useTranslation();
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
      {FIELDS.map((f) => (
        <div className="field" key={f} style={{ margin: 0 }}>
          <label htmlFor={`${idPrefix}-${f}`}>{t(`breaker.fields.${f}`, f)}</label>
          <input
            id={`${idPrefix}-${f}`}
            type="number"
            min={bounds[f][0]}
            max={bounds[f][1]}
            disabled={disabled}
            value={value[f]}
            onChange={(e) => onChange({ ...value, [f]: Number(e.target.value) })}
          />
          <div className="hint-text" style={{ fontSize: 12 }}>
            {t(`breaker.help.${f}`, "")} ({bounds[f][0]}–{bounds[f][1]})
          </div>
        </div>
      ))}
    </div>
  );
}

function outOfBounds(cfg: BreakerConfig, bounds: BreakerSettings["bounds"]) {
  return FIELDS.some((f) => !Number.isFinite(cfg[f]) || cfg[f] < bounds[f][0] || cfg[f] > bounds[f][1]);
}

export default function AgentBreakerPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [settings, setSettings] = useState<BreakerSettings | null>(null);
  const [org, setOrg] = useState<BreakerConfig | null>(null);
  const [chains, setChains] = useState<BreakerChain[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [newOverride, setNewOverride] = useState<{ agentId: string; cfg: BreakerConfig | null }>({ agentId: "", cfg: null });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    Promise.all([getBreakerSettings(), listBreakerChains()])
      .then(([s, c]) => {
        setSettings(s);
        setOrg({
          enabled: s.org.enabled,
          window_seconds: s.org.window_seconds,
          max_attempts: s.org.max_attempts,
          max_denials: s.org.max_denials,
          max_incidents: s.org.max_incidents,
        });
        setChains(c);
      })
      .catch((e) => setError(breakerError(e, t("breaker.load_failed", "Could not load the circuit breaker."))));
  }, [t]);

  useEffect(() => {
    load();
    listAgents().then((a) => setAgents(a as Agent[])).catch(() => undefined);
  }, [load]);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (ok) setNotice(ok);
      load();
    } catch (e) {
      setError(breakerError(e, t("breaker.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  async function saveOrg() {
    if (!org) return;
    let confirmDisable = false;
    if (!org.enabled && settings?.org.enabled) {
      confirmDisable = window.confirm(
        t(
          "breaker.confirm_disable",
          "Turn the circuit breaker off? Failing agents will no longer be stopped automatically. This change is recorded in the audit log.",
        ),
      );
      if (!confirmDisable) return;
    }
    await run(() => updateOrgBreaker(org, confirmDisable || !org.enabled), t("breaker.saved", "Saved"));
  }

  if (!settings || !org) {
    return (
      <>
        <PageHeader title={t("breaker.title", "Circuit Breaker")} />
        <div className="content">
          <div className="hint-text">{error ?? t("common.loading", "Loading…")}</div>
        </div>
      </>
    );
  }

  const tripped = chains.filter((c) => c.status === "tripped");
  const history = chains.filter((c) => c.status !== "tripped");
  const overriddenIds = new Set(settings.overrides.map((o) => o.agent_id));
  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");

  const why = (c: BreakerChain) =>
    c.breaker_details
      ? c.breaker_details.exceeded
          .map((k) =>
            t(`breaker.why.${k}`, {
              count: c.breaker_details!.counts[k],
              limit: c.breaker_details!.thresholds[k],
              minutes: Math.round(c.breaker_details!.window_seconds / 60),
              defaultValue: `${k}: ${c.breaker_details!.counts[k]} ≥ ${c.breaker_details!.thresholds[k]}`,
            }),
          )
          .join("; ")
      : "—";

  const chainRow = (c: BreakerChain, actions: boolean) => (
    <tr key={c.id}>
      <td>
        <Link href={`/agent-chains/${c.id}`}>#{c.id}</Link>
        <div className="hint-text" style={{ fontSize: 11 }}>{c.root_task || ""}</div>
      </td>
      <td>{c.root_agent_name ?? `#${c.root_agent_id}`}</td>
      <td>{fmt(c.breaker_tripped_at)}</td>
      <td style={{ fontSize: 13 }}>{why(c)}</td>
      <td>{t(`chains.status_${c.status}`, c.status)}</td>
      {actions && isAdmin && (
        <td style={{ whiteSpace: "nowrap" }}>
          <button
            className="btn btn-sm btn-primary"
            disabled={busy}
            onClick={() => run(() => resumeChain(c.id), t("breaker.resumed", "Chain resumed"))}
          >
            {t("breaker.resume", "Resume")}
          </button>{" "}
          <button
            className="btn btn-sm"
            disabled={busy}
            onClick={() => {
              if (window.confirm(t("breaker.confirm_terminate", "Terminate this chain for good?")))
                run(() => terminateChain(c.id), t("breaker.terminated", "Chain terminated"));
            }}
          >
            {t("breaker.terminate", "Terminate")}
          </button>
        </td>
      )}
    </tr>
  );

  return (
    <>
      <PageHeader title={t("breaker.title", "Circuit Breaker")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "breaker.hint",
            "When an agent in a delegation chain starts failing — a storm of policy denials, a burst of incidents or a runaway loop — the breaker halts the whole chain (OWASP ASI08). It never closes by itself: an admin resumes or terminates the chain.",
          )}
        </p>

        {error && (
          <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}>
            <div className="panel-body" style={{ color: "#ef4444" }}>{error}</div>
          </div>
        )}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        {/* ---- halted chains ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>
              ⚡ {t("breaker.halted_title", "Halted chains")} ({tripped.length})
            </h2>
          </div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            {tripped.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("breaker.halted_empty", "No chain is halted right now.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("breaker.col_chain", "Chain")}</th>
                    <th>{t("breaker.col_root", "Root agent")}</th>
                    <th>{t("breaker.col_tripped", "Tripped")}</th>
                    <th>{t("breaker.col_why", "Why")}</th>
                    <th>{t("breaker.col_status", "Status")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>{tripped.map((c) => chainRow(c, true))}</tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- organization settings ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("breaker.org_title", "Organization thresholds")}</h2>
          </div>
          <div className="panel-body">
            <p className="hint-text" style={{ marginTop: 0 }}>
              {settings.org.source === "default"
                ? t("breaker.using_defaults", "Built-in defaults are in use. Saving stores them as your organization's settings.")
                : t("breaker.using_org", "Your organization's settings are in use.")}{" "}
              {t("breaker.threshold_rule", "A chain trips when a count reaches its threshold within the window.")}
            </p>
            <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
              <input
                type="checkbox"
                disabled={!isAdmin}
                checked={org.enabled}
                onChange={(e) => setOrg({ ...org, enabled: e.target.checked })}
                style={{ width: "auto" }}
              />
              <strong>{t("breaker.enabled", "Circuit breaker enabled")}</strong>
            </label>
            {!org.enabled && (
              <p style={{ color: "#ef4444", fontSize: 13 }}>
                {t("breaker.disabled_warning", "While disabled, failing agents are not stopped automatically.")}
              </p>
            )}
            <ConfigFields value={org} onChange={setOrg} bounds={settings.bounds} disabled={!isAdmin} idPrefix="org" />
            {isAdmin && (
              <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
                <button className="btn btn-primary btn-sm" disabled={busy || outOfBounds(org, settings.bounds)} onClick={saveOrg}>
                  {t("breaker.save", "Save")}
                </button>
                <button
                  className="btn btn-sm"
                  disabled={busy}
                  onClick={() => setOrg({ ...settings.defaults })}
                  title={t("breaker.reset_defaults_hint", "Fill the form with the built-in defaults (not saved yet)")}
                >
                  {t("breaker.reset_defaults", "Restore defaults")}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ---- per-agent overrides ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header">
            <h2>{t("breaker.overrides_title", "Per-agent overrides")}</h2>
          </div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <p className="hint-text" style={{ marginTop: 0 }}>
              {t(
                "breaker.overrides_hint",
                "An override applies to chains started by that agent (the root of the chain) — e.g. a busy support agent can get a higher attempt limit.",
              )}
            </p>
            {settings.overrides.length > 0 && (
              <table style={{ marginBottom: 12 }}>
                <thead>
                  <tr>
                    <th>{t("breaker.col_agent", "Agent")}</th>
                    <th>{t("breaker.enabled_short", "On")}</th>
                    {FIELDS.map((f) => (
                      <th key={f}>{t(`breaker.short.${f}`, f)}</th>
                    ))}
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {settings.overrides.map((o) => (
                    <tr key={o.agent_id}>
                      <td>{o.agent_name}</td>
                      <td>{o.enabled ? "✓" : "—"}</td>
                      {FIELDS.map((f) => (
                        <td key={f}>{o[f]}</td>
                      ))}
                      {isAdmin && (
                        <td>
                          <button
                            className="btn btn-sm"
                            disabled={busy}
                            onClick={() => run(() => deleteAgentBreaker(o.agent_id), t("breaker.saved", "Saved"))}
                          >
                            {t("breaker.remove", "Remove")}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {isAdmin && (
              <>
                <div className="field" style={{ maxWidth: 360 }}>
                  <label htmlFor="ov-agent">{t("breaker.add_override", "Add an override for")}</label>
                  <select
                    id="ov-agent"
                    value={newOverride.agentId}
                    onChange={(e) =>
                      setNewOverride({ agentId: e.target.value, cfg: e.target.value ? { ...org } : null })
                    }
                  >
                    <option value="">—</option>
                    {agents
                      .filter((a) => !overriddenIds.has(a.id))
                      .map((a) => (
                        <option key={a.id} value={a.id}>{a.name}</option>
                      ))}
                  </select>
                </div>
                {newOverride.cfg && (
                  <>
                    <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
                      <input
                        type="checkbox"
                        checked={newOverride.cfg.enabled}
                        onChange={(e) =>
                          setNewOverride({ ...newOverride, cfg: { ...newOverride.cfg!, enabled: e.target.checked } })
                        }
                        style={{ width: "auto" }}
                      />
                      {t("breaker.enabled", "Circuit breaker enabled")}
                    </label>
                    <ConfigFields
                      value={newOverride.cfg}
                      onChange={(cfg) => setNewOverride({ ...newOverride, cfg })}
                      bounds={settings.bounds}
                      idPrefix="ov"
                    />
                    <button
                      className="btn btn-primary btn-sm"
                      style={{ marginTop: 12 }}
                      disabled={busy || outOfBounds(newOverride.cfg, settings.bounds)}
                      onClick={() =>
                        run(async () => {
                          await setAgentBreaker(Number(newOverride.agentId), newOverride.cfg!);
                          setNewOverride({ agentId: "", cfg: null });
                        }, t("breaker.saved", "Saved"))
                      }
                    >
                      {t("breaker.save_override", "Save override")}
                    </button>
                  </>
                )}
              </>
            )}
          </div>
        </div>

        {/* ---- history ---- */}
        {history.length > 0 && (
          <div className="panel">
            <div className="panel-header">
              <h2>{t("breaker.history_title", "Earlier trips")}</h2>
            </div>
            <div className="panel-body" style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr>
                    <th>{t("breaker.col_chain", "Chain")}</th>
                    <th>{t("breaker.col_root", "Root agent")}</th>
                    <th>{t("breaker.col_tripped", "Tripped")}</th>
                    <th>{t("breaker.col_why", "Why")}</th>
                    <th>{t("breaker.col_status", "Status")}</th>
                  </tr>
                </thead>
                <tbody>{history.map((c) => chainRow(c, false))}</tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
