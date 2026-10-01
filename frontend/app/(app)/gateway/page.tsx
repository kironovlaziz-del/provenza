"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import {
  addRoute,
  disableRoute,
  gatewayError,
  getGatewayOverview,
  saveGatewaySettings,
  type GatewayOverview,
  type GatewaySettings,
} from "@/lib/gateway_api";

const STATUS_PILL: Record<string, string> = {
  completed: "pill-low",
  filtered: "pill-high",
  blocked: "pill-critical",
  denied: "pill-critical",
  rate_limited: "pill-medium",
  failed: "pill-neutral",
};
const LIST: React.CSSProperties = { maxHeight: 420, overflowY: "auto", overflowX: "auto" };
const MODEL_RE = /^[A-Za-z0-9_.:/*?\-]{1,200}$/;

export default function GatewayPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [data, setData] = useState<GatewayOverview | null>(null);
  const [form, setForm] = useState<GatewaySettings | null>(null);
  const [termsText, setTermsText] = useState("");
  const [rModel, setRModel] = useState("");
  const [rProvider, setRProvider] = useState<number | "">("");
  const [rUpstream, setRUpstream] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getGatewayOverview()
      .then((d) => {
        setData(d);
        setForm({ ...d.settings });
        setTermsText(d.settings.blocked_terms.join("\n"));
      })
      .catch((e) => setError(gatewayError(e, t("gateway.load_failed", "Could not load the gateway."))));
  }, [t]);

  useEffect(load, [load]);

  const baseUrl = useMemo(() => {
    const b = (api.defaults.baseURL as string | undefined) || "/api/v1";
    const abs = b.startsWith("http") ? b : (typeof window !== "undefined" ? window.location.origin : "") + b;
    return abs.replace(/\/$/, "") + "/gateway/v1";
  }, []);

  async function run(action: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (ok) setNotice(ok);
      load();
    } catch (e) {
      setError(gatewayError(e, t("gateway.failed", "Could not save.")));
    } finally {
      setBusy(false);
    }
  }

  const fmt = (iso: string) => new Date(iso).toLocaleString();
  const terms = termsText.split("\n").map((s) => s.trim()).filter(Boolean);

  if (!data || !form) {
    return (
      <>
        <PageHeader title={t("gateway.title", "AI Gateway")} />
        <div className="content"><div className="hint-text">{error ?? t("common.loading", "Loading…")}</div></div>
      </>
    );
  }

  const c = data.counts_24h;
  const total = Object.values(c).reduce((a, b) => a + b, 0);
  const snippet = `import os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url="${baseUrl}",\n    api_key=os.environ["PROVENZA_AGENT_KEY"],  # the agent's own key\n)\nclient.chat.completions.create(model="${data.routes.find((r) => r.enabled)?.model ?? "gpt-4o-mini"}", messages=[...])`;

  return (
    <>
      <PageHeader title={t("gateway.title", "AI Gateway")} />
      <div className="content">
        <p className="hint-text" style={{ marginTop: 0 }}>
          {t(
            "gateway.hint",
            "An OpenAI-compatible endpoint for agents. Point an agent's base URL here and use its own key: every call is checked against its allowed models, the Prompt Firewall (PII masked before it leaves), prompt-injection in tool messages, rate limits, and the answer is checked for injected instructions and dangerous code.",
          )}
        </p>
        {error && <div className="panel" style={{ marginBottom: 16, borderColor: "#ef4444" }}><div className="panel-body" style={{ color: "#ef4444" }}>{error}</div></div>}
        {notice && <div className="hint-text" style={{ marginBottom: 16 }}>{notice}</div>}

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("gateway.connect_title", "Connect an agent")}</h2></div>
          <div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12, marginBottom: 6 }}>{t("gateway.base_url", "Base URL")}</div>
            <code className="mono" style={{ fontSize: 13, wordBreak: "break-all" }}>{baseUrl}</code>
            <pre className="mono" style={{ fontSize: 12, marginTop: 10, padding: 10, overflowX: "auto", border: "1px solid var(--border, #ddd)", borderRadius: 6 }}>{snippet}</pre>
            <div className="hint-text" style={{ fontSize: 12 }}>
              {t("gateway.connect_hint", "The key is the agent's key from Agent Identity (sent as Bearer or X-Agent-Key). Streaming is not supported yet.")}
            </div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, marginBottom: 20 }}>
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("gateway.calls", "Calls")} · 24h</div>
            <div style={{ fontSize: 24, fontWeight: 600 }}>{total}</div>
          </div></div>
          {(["completed", "blocked", "filtered", "failed"] as const).map((k) => (
            <div className="panel" key={k}><div className="panel-body">
              <div className="hint-text" style={{ fontSize: 12 }}>{t(`gateway.status_${k}`, k)}</div>
              <div style={{ fontSize: 24, fontWeight: 600 }}>{(c[k] ?? 0) + (k === "blocked" ? (c.denied ?? 0) + (c.rate_limited ?? 0) : 0)}</div>
            </div></div>
          ))}
          <div className="panel"><div className="panel-body">
            <div className="hint-text" style={{ fontSize: 12 }}>{t("gateway.tokens", "Tokens")} · 24h</div>
            <div style={{ fontSize: 18, fontWeight: 600 }}>{data.tokens_24h.prompt.toLocaleString()} / {data.tokens_24h.completion.toLocaleString()}</div>
            <div className="hint-text" style={{ fontSize: 11 }}>{t("gateway.tokens_hint", "in / out")}</div>
          </div></div>
        </div>

        {/* ---- calls ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("gateway.calls_title", "Recent calls")}</h2></div>
          <div className="panel-body" style={LIST}>
            {data.calls.length === 0 ? (
              <p className="hint-text" style={{ margin: 0 }}>{t("gateway.calls_empty", "No calls yet.")}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t("gateway.col_time", "Time")}</th>
                    <th>{t("gateway.col_agent", "Agent")}</th>
                    <th>{t("gateway.col_model", "Model")}</th>
                    <th>{t("gateway.col_status", "Status")}</th>
                    <th>{t("gateway.col_details", "Details")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.calls.map((x) => (
                    <tr key={x.id}>
                      <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmt(x.created_at)}</td>
                      <td>{x.agent_name ?? "—"}</td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {x.model}
                        {x.provider && <div className="hint-text" style={{ fontSize: 11 }}>{x.provider}</div>}
                      </td>
                      <td><span className={`pill ${STATUS_PILL[x.status] ?? "pill-neutral"}`}>{t(`gateway.status_${x.status}`, x.status)}</span></td>
                      <td style={{ fontSize: 12, maxWidth: 380 }}>
                        {x.reason && <div>{x.reason}</div>}
                        <div className="hint-text" style={{ fontSize: 11 }}>
                          {x.latency_ms != null ? `${x.latency_ms} ms` : ""}
                          {x.prompt_tokens != null ? ` · ${x.prompt_tokens}/${x.completion_tokens ?? 0} tok` : ""}
                          {x.flags.length ? ` · ${x.flags.join(", ")}` : ""}
                        </div>
                        {x.ai_request_id && <a href={`/requests/${x.ai_request_id}`} style={{ fontSize: 11 }}>{t("gateway.open_request", "request")} #{x.ai_request_id}</a>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ---- routes ---- */}
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-header"><h2>{t("gateway.routes_title", "Model routes")}</h2></div>
          <div className="panel-body">
            <p className="hint-text" style={{ marginTop: 0, fontSize: 12 }}>
              {t("gateway.routes_hint", "Which connection serves a model name. A pattern such as gpt-4o* is allowed; an exact name wins over a pattern. The agent must also have the model in its allowed models.")}
            </p>
            {isAdmin && (
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
                <input placeholder={t("gateway.model_ph", "model, e.g. gpt-4o-mini")} value={rModel} onChange={(e) => setRModel(e.target.value)} className="mono" style={{ width: 220 }} />
                <span>→</span>
                <select value={rProvider} onChange={(e) => setRProvider(e.target.value ? Number(e.target.value) : "")} style={{ width: "auto" }}>
                  <option value="">{t("gateway.pick_connection", "Connection…")}</option>
                  {data.providers.map((p) => (
                    <option key={p.id} value={p.id} disabled={p.status !== "active"}>
                      {p.name} ({p.type}){p.has_key ? "" : ` – ${t("gateway.no_key", "no key")}`}
                    </option>
                  ))}
                </select>
                <input placeholder={t("gateway.upstream_ph", "upstream name (optional)")} value={rUpstream} onChange={(e) => setRUpstream(e.target.value)} className="mono" style={{ width: 200 }} />
                <button className="btn btn-sm btn-primary"
                  disabled={busy || !MODEL_RE.test(rModel) || rProvider === ""}
                  onClick={() => run(async () => { await addRoute(rModel.trim(), Number(rProvider), rUpstream.trim() || null); setRModel(""); setRUpstream(""); },
                    t("gateway.route_added", "Route added"))}>
                  {t("gateway.add_route", "Add route")}
                </button>
              </div>
            )}
            <div style={LIST}>
              {data.routes.length === 0 ? (
                <p className="hint-text" style={{ margin: 0 }}>{t("gateway.routes_empty", "No routes - the gateway serves no model yet.")}</p>
              ) : (
                <table>
                  <tbody>
                    {data.routes.map((r) => (
                      <tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.5 }}>
                        <td className="mono">{r.model}</td>
                        <td>→ {r.provider ?? `#${r.provider_id}`}{r.upstream_model ? <span className="hint-text mono"> ({r.upstream_model})</span> : null}</td>
                        <td>
                          {r.enabled ? (
                            isAdmin && (
                              <button className="btn btn-sm" disabled={busy}
                                onClick={() => {
                                  if (window.confirm(t("gateway.confirm_disable", "Disable this route? Agents asking for this model will get 'model not routed'.")))
                                    run(() => disableRoute(r.id), t("gateway.route_disabled", "Route disabled"));
                                }}>
                                {t("gateway.disable", "Disable")}
                              </button>
                            )
                          ) : (
                            <span className="pill pill-neutral">{t("gateway.disabled", "disabled")}</span>
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
          <div className="panel-header"><h2>{t("gateway.settings_title", "Settings")}</h2></div>
          <div className="panel-body">
            {(["enabled", "scan_output"] as const).map((k) => (
              <label key={k} style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 10 }}>
                <input type="checkbox" checked={form[k]} disabled={!isAdmin}
                  onChange={(e) => setForm({ ...form, [k]: e.target.checked })} style={{ width: "auto", marginTop: 3 }} />
                <span>
                  <strong>{t(`gateway.${k}`, k)}</strong>
                  <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t(`gateway.${k}_hint`, "")}</span>
                </span>
              </label>
            ))}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="gw-rpm">{t("gateway.rpm", "Requests per minute, per agent")}</label>
                <input id="gw-rpm" type="number" min={1} max={6000} disabled={!isAdmin} value={form.rpm_per_agent}
                  onChange={(e) => setForm({ ...form, rpm_per_agent: Number(e.target.value) })} />
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="gw-max">{t("gateway.max_tokens", "Max tokens per answer")}</label>
                <input id="gw-max" type="number" min={16} max={200000} disabled={!isAdmin} value={form.max_tokens_cap}
                  onChange={(e) => setForm({ ...form, max_tokens_cap: Number(e.target.value) })} />
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label htmlFor="gw-terms">{t("gateway.blocked_terms", "Blocked terms (one per line)")}</label>
                <textarea id="gw-terms" rows={3} value={termsText} disabled={!isAdmin} onChange={(e) => setTermsText(e.target.value)}
                  style={{ width: "100%", fontSize: 13 }} />
              </div>
            </div>
            {isAdmin && (
              <button className="btn btn-primary btn-sm" style={{ marginTop: 12 }}
                disabled={busy || form.rpm_per_agent < 1 || form.rpm_per_agent > 6000 || form.max_tokens_cap < 16 || form.max_tokens_cap > 200000 || terms.length > 200 || terms.some((x) => x.length > 100)}
                onClick={() => run(() => saveGatewaySettings({ ...form, blocked_terms: terms }), t("gateway.saved", "Saved"))}>
                {t("gateway.save", "Save")}
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
