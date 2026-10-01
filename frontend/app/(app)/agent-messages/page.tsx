"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import {
  a2aError,
  addChannel,
  disableChannel,
  getA2AOverview,
  releaseMessage,
  saveA2ASettings,
  type A2AMode,
  type A2AOverview,
  type A2ASettings,
  type MsgStatus,
} from "@/lib/a2a_api";

const MODES: A2AMode[] = ["off", "monitor", "enforce"];
const STATUS_PILL: Record<string, string> = { accepted: "pill-low", quarantined: "pill-high", rejected: "pill-critical" };
const LIST: React.CSSProperties = { maxHeight: 420, overflowY: "auto", overflowX: "auto" };
const BOUNDS = { max_age_seconds: [30, 3600], message_ttl_seconds: [60, 86400] } as const;

export default function AgentMessagesPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<A2AOverview | null>(null);
  const [form, setForm] = useState<A2ASettings | null>(null);
  const [filter, setFilter] = useState<MsgStatus | "">("");
  const [chFrom, setChFrom] = useState<number | "">("");
  const [chTo, setChTo] = useState<number | "">("");
  const [chBoth, setChBoth] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getA2AOverview(filter)
      .then((d) => {
        setData(d);
        setForm({ ...d.settings });
      })
      .catch((e) => setError(a2aError(e, t("a2a.load_failed", "Could not load agent messages."))));
  }, [t, filter]);

  useEffect(load, [load]);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (ok) setNotice(ok);
      load();
    } catch (e) {
      setError(a2aError(e, t("a2a.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  function save() {
    if (!form || !data) return;
    if (form.mode === "enforce" && data.settings.mode !== "enforce") {
      const ok = window.confirm(
        t(
          "a2a.confirm_enforce",
          "Switch to enforce? Messages with an invalid signature, a reused nonce, a stale timestamp or no allowed route will be rejected, and poisoned payloads quarantined. Make sure the channels your agents need exist first.",
        ),
      );
      if (!ok) return;
    }
    run(() => saveA2ASettings(form), t("a2a.saved", "Saved"));
  }

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("a2a.title", "Agent Messages")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const c = data.counts_24h;
  const outOfBounds = (Object.keys(BOUNDS) as (keyof typeof BOUNDS)[]).some(
    (k) => form[k] < BOUNDS[k][0] || form[k] > BOUNDS[k][1],
  );

  return (
    <>
      <PageHeader title={t("a2a.title", "Agent Messages")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "a2a.hint",
            "Agents that talk to each other can be impersonated, replayed or fed altered messages (OWASP ASI07). Each message is registered with an envelope signed by the sender's key and verified again by the recipient before it acts: identity, freshness, single use, allowed route and unaltered content.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
          {(["accepted", "quarantined", "rejected"] as const).map((k) => (
            <div className="panel" key={k}><div className="panel-body">
              <div className="hint-text" style={{ fontSize: 12 }}>{t(`a2a.status_${k}`, k)} · 24h</div>
              <div style={{ fontSize: 24, fontWeight: 600 }}>{c[k] ?? 0}</div>
            </div></div>
          ))}
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("a2a.channels_active", "Active channels")}</div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{data.channels.filter((x) => x.enabled).length}</div>
          </div></div>
        </div>

        {/* ---- messages ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>{t("a2a.messages_title", "Messages")}</h2>
            <select value={filter} onChange={(e) => setFilter(e.target.value as MsgStatus | "")} style={{ width: "auto" }}>
              <option value="">{t("a2a.filter_all", "All statuses")}</option>
              {(["rejected", "quarantined", "accepted"] as const).map((s) => (
                <option key={s} value={s}>{t(`a2a.status_${s}`, s)}</option>
              ))}
            </select>
          </div>
          <div className="panel-body" style={LIST}>
            {data.messages.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("a2a.messages_empty", "No messages registered yet.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("a2a.col_time", "Time")}</th>
                    <th>{t("a2a.col_route", "From → To")}</th>
                    <th>{t("a2a.col_type", "Type")}</th>
                    <th>{t("a2a.col_reasons", "Reasons")}</th>
                    <th>{t("a2a.col_status", "Status")}</th>
                    {isAdmin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {data.messages.map((m) => (
                    <tr key={m.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmt(m.created_at)}</td>
                      <td>
                        {m.from_agent ?? `#${m.from_agent_id}`} → {m.to_agent ?? (m.to_agent_id ? `#${m.to_agent_id}` : "?")}
                        <div className="hint-text" style={{ fontSize: 11 }}>
                          {m.signature_valid ? `✔ ${t("a2a.signed", "signature valid")}` : `✖ ${t("a2a.unsigned", "signature not valid")}`}
                          {m.chain_id ? ` · #${m.chain_id}` : ""}
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {m.message_type ?? "—"}
                        {m.consumed_at && <div className="hint-text" style={{ fontSize: 11 }}>{t("a2a.received", "received")} {fmt(m.consumed_at)}</div>}
                      </td>
                      <td style={{ fontSize: 12, maxWidth: 380 }}>
                        {m.reasons.length === 0 ? <span className="hint-text">—</span> : m.reasons.map((r, i) => <div key={i}>{r}</div>)}
                        {m.findings.slice(0, 2).map((f, i) => (
                          <div key={`f${i}`} className="hint-text mono" style={{ fontSize: 11, wordBreak: "break-word" }}>
                            {t(`injection.label_${f.label}`, t(`codeexec.label_${f.label}`, f.label))}: {f.snippet}
                          </div>
                        ))}
                      </td>
                      <td><span className={`pill ${STATUS_PILL[m.status]}`}>{t(`a2a.status_${m.status}`, m.status)}</span></td>
                      {isAdmin && (
                        <td>
                          {m.status === "quarantined" && (
                            <button className="btn btn-sm btn-primary" disabled={busy}
                              onClick={() => {
                                if (window.confirm(t("a2a.confirm_release", "Release this message? The recipient will be allowed to act on it.")))
                                  run(() => releaseMessage(m.id), t("a2a.released", "Message released"));
                              }}>
                              {t("a2a.release", "Release")}
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- channels ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("a2a.channels_title", "Channels")}</h2></div>
          <div className="panel-body">
            <p className="hint-text" style={{ marginTop: 0, fontSize: 12 }}>
              {t("a2a.channels_hint", "Routes allowed in addition to agents sharing a delegation chain. Disabled channels stay in the list for the audit trail.")}
            </p>
            {isAdmin && (
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
                <select value={chFrom} onChange={(e) => setChFrom(e.target.value ? Number(e.target.value) : "")} style={{ width: "auto" }}>
                  <option value="">{t("a2a.from", "From…")}</option>
                  {data.agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
                <span>{chBoth ? "⇄" : "→"}</span>
                <select value={chTo} onChange={(e) => setChTo(e.target.value ? Number(e.target.value) : "")} style={{ width: "auto" }}>
                  <option value="">{t("a2a.to", "To…")}</option>
                  {data.agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
                <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input type="checkbox" checked={chBoth} onChange={(e) => setChBoth(e.target.checked)} style={{ width: "auto" }} />
                  {t("a2a.bidirectional", "both ways")}
                </label>
                <button className="btn btn-sm btn-primary"
                  disabled={busy || chFrom === "" || chTo === "" || chFrom === chTo}
                  onClick={() => run(() => addChannel(Number(chFrom), Number(chTo), chBoth), t("a2a.channel_added", "Channel added"))}>
                  {t("a2a.add_channel", "Add channel")}
                </button>
              </div>
            )}
            <div style={LIST}>
              {data.channels.length === 0 ? (
                <p className="hint-text" style={{ margin: 0 }}>{t("a2a.channels_empty", "No explicit channels.")}</p>
              ) : (
                <table>
                  <tbody>
                    {data.channels.map((ch) => (
                      <tr key={ch.id} style={{ opacity: ch.enabled ? 1 : 0.5 }}>
                        <td>{ch.from_agent ?? `#${ch.from_agent_id}`} {ch.bidirectional ? "⇄" : "→"} {ch.to_agent ?? `#${ch.to_agent_id}`}</td>
                        <td style={{ fontSize: 12 }} className="hint-text">{fmt(ch.created_at)}</td>
                        <td>
                          {ch.enabled ? (
                            isAdmin && (
                              <button className="btn btn-sm" disabled={busy}
                                onClick={() => {
                                  if (window.confirm(t("a2a.confirm_disable", "Disable this channel? In enforce mode these agents will no longer be able to message each other unless they share a chain.")))
                                    run(() => disableChannel(ch.id), t("a2a.channel_disabled", "Channel disabled"));
                                }}>
                                {t("a2a.disable", "Disable")}
                              </button>
                            )
                          ) : (
                            <span className="pill pill-neutral">{t("a2a.disabled", "disabled")}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        {/* ---- settings ---- */}
        <div className="panel">
          <div className="panel-header"><h2>{t("a2a.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 14 }}>
              {MODES.map((m) => (
                <label key={m} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <input type="radio" name="a2a-mode" checked={form.mode === m} disabled={!isAdmin}
                    onChange={() => setForm({ ...form, mode: m })} style={{ width: "auto", marginTop: 3 }} />
                  <span>
                    <strong>{t(`a2a.mode_${m}`, m)}</strong>
                    <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t(`a2a.mode_${m}_hint`, "")}</span>
                  </span>
                </label>
              ))}
            </div>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 14 }}>
              <input type="checkbox" checked={form.allow_same_chain} disabled={!isAdmin}
                onChange={(e) => setForm({ ...form, allow_same_chain: e.target.checked })} style={{ width: "auto", marginTop: 3 }} />
              <span>
                <strong>{t("a2a.allow_same_chain", "Agents in the same delegation chain may message each other")}</strong>
                <span className="hint-text" style={{ display: "block", fontSize: 12 }}>
                  {t("a2a.allow_same_chain_hint", "Off: only explicit channels are allowed.")}
                </span>
              </span>
            </label>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
              {(Object.keys(BOUNDS) as (keyof typeof BOUNDS)[]).map((k) => (
                <div className="field" key={k} style={{ margin: 0 }}>
                  <label htmlFor={`a2a-${k}`}>{t(`a2a.field_${k}`, k)}</label>
                  <input id={`a2a-${k}`} type="number" min={BOUNDS[k][0]} max={BOUNDS[k][1]} disabled={!isAdmin}
                    value={form[k]} onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} />
                  <div className="hint-text" style={{ fontSize: 12 }}>{t(`a2a.help_${k}`, "")} ({BOUNDS[k][0]}–{BOUNDS[k][1]})</div>
                </div>
              ))}
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }} disabled={busy || outOfBounds} onClick={save}>
                {t("a2a.save", "Save")}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
