"use client";

// Intent guardrail (admins): a model on one of the organization's own
// connections reads each prompt - already masked by the Prompt Firewall -
// and says whether it asks for something forbidden, whatever the words.
// Llama Guard with its built-in categories, or any instruction model with
// the organization's own; monitor or enforce; where it runs; a try-out.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { api, listProviders } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";

type Kind = "llama_guard" | "instruct";
interface Category { code: string; description: string }
interface Settings {
  enabled: boolean;
  provider_id: number | null;
  model: string;
  kind: Kind;
  mode: "monitor" | "enforce";
  on_error: "allow" | "block";
  categories: Category[];
  blocked_categories: string[];
  timeout_ms: number;
  surfaces: string[];
  llama_guard_categories: Record<string, string>;
  example_categories: Category[];
}
interface Provider { id: number; name: string; type: string }
interface TryResult { safe: boolean; categories: string[]; flags: string[]; block: boolean; error: string | null; reason: string }

const SURFACES = ["playground", "gateway", "requests"];

export default function IntentGuardrailPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [st, setSt] = useState<Settings | null>(null);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [sample, setSample] = useState("");
  const [tried, setTried] = useState<TryResult | null>(null);

  useEffect(() => {
    api.get<Settings>("/guardrail/settings").then((r) => setSt(r.data)).catch(() => setSt(null));
    listProviders().then(setProviders).catch(() => setProviders([]));
  }, []);

  if (user?.role !== "admin") return <PageHeader title={t("guardrail.title")} />;
  if (!st) return <><PageHeader title={t("guardrail.title")} /><div className="content"><p className="hint-text">{t("common.loading")}</p></div></>;

  const set = (patch: Partial<Settings>) => { setSt({ ...st, ...patch }); setSaved(false); };
  const known = st.kind === "llama_guard"
    ? Object.entries(st.llama_guard_categories).map(([code, description]) => ({ code, description }))
    : st.categories.filter((c) => c.code.trim());
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  async function save() {
    if (!st) return;
    setBusy(true);
    setError(null);
    try {
      const { llama_guard_categories: _l, example_categories: _e, ...body } = st;
      const r = await api.put<Settings>("/guardrail/settings", {
        ...body, categories: st.kind === "instruct" ? st.categories.filter((c) => c.code.trim()) : [],
      });
      setSt(r.data);
      setSaved(true);
    } catch (e) {
      setError(errorMessage(e, t, t("guardrail.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function tryIt() {
    setBusy(true);
    setError(null);
    setTried(null);
    try {
      setTried((await api.post<TryResult>("/guardrail/test", { text: sample })).data);
    } catch (e) {
      setError(errorMessage(e, t, t("guardrail.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title={t("guardrail.title")} />
      <div className="content">
        <div className="panel u-mb-16">
          <div className="panel-body">
            <p className="hint-text">{t("guardrail.hint")}</p>
            <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input type="checkbox" style={{ width: "auto" }} checked={st.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
              {t("guardrail.enabled")}
            </label>
            <div className="form-row">
              <div className="field">
                <label htmlFor="gr-provider">{t("guardrail.provider")}</label>
                <select id="gr-provider" value={st.provider_id ?? ""} onChange={(e) => set({ provider_id: e.target.value ? Number(e.target.value) : null })}>
                  <option value="">—</option>
                  {providers.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.type})</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="gr-kind">{t("guardrail.kind")}</label>
                <select id="gr-kind" value={st.kind} onChange={(e) => set({ kind: e.target.value as Kind, blocked_categories: [],
                  categories: e.target.value === "instruct" && !st.categories.length ? st.example_categories : st.categories })}>
                  <option value="llama_guard">Llama Guard</option>
                  <option value="instruct">{t("guardrail.kind_instruct")}</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="gr-model">{t("guardrail.model")}</label>
                <input id="gr-model" className="mono" value={st.model} placeholder={st.kind === "llama_guard" ? "llama-guard3" : "qwen2.5:7b"}
                  onChange={(e) => set({ model: e.target.value })} />
              </div>
            </div>
            <p className="hint-text">{t("guardrail.provider_hint")}</p>

            <div className="form-row">
              <div className="field">
                <label htmlFor="gr-mode">{t("guardrail.mode")}</label>
                <select id="gr-mode" value={st.mode} onChange={(e) => set({ mode: e.target.value as Settings["mode"] })}>
                  <option value="monitor">{t("guardrail.mode_monitor")}</option>
                  <option value="enforce">{t("guardrail.mode_enforce")}</option>
                </select>
              </div>
              <div className="field">
                <label htmlFor="gr-err">{t("guardrail.on_error")}</label>
                <select id="gr-err" value={st.on_error} onChange={(e) => set({ on_error: e.target.value as Settings["on_error"] })}>
                  <option value="allow">{t("guardrail.on_error_allow")}</option>
                  <option value="block">{t("guardrail.on_error_block")}</option>
                </select>
              </div>
              <div className="field" style={{ maxWidth: 160 }}>
                <label htmlFor="gr-timeout">{t("guardrail.timeout")}</label>
                <input id="gr-timeout" type="number" min={500} max={30000} step={500} value={st.timeout_ms}
                  onChange={(e) => set({ timeout_ms: Number(e.target.value) })} />
              </div>
            </div>

            <div className="field">
              <label>{t("guardrail.surfaces")}</label>
              <div className="u-btn-row">
                {SURFACES.map((s) => (
                  <label key={s} style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400 }}>
                    <input type="checkbox" style={{ width: "auto" }} checked={st.surfaces.includes(s)}
                      onChange={() => set({ surfaces: toggle(st.surfaces, s) })} />
                    {t(`guardrail.surface.${s}`)}
                  </label>
                ))}
              </div>
            </div>

            {st.kind === "instruct" && (
              <div className="field">
                <label>{t("guardrail.categories")}</label>
                <p className="hint-text">{t("guardrail.categories_hint")}</p>
                <div className="ag-stack">
                  {st.categories.map((c, i) => (
                    <div key={i} className="u-btn-row">
                      <input className="mono" style={{ maxWidth: 200 }} value={c.code} placeholder="AUTHZ_BYPASS"
                        onChange={(e) => set({ categories: st.categories.map((x, j) => (j === i ? { ...x, code: e.target.value.toUpperCase() } : x)) })} />
                      <input value={c.description} placeholder={t("guardrail.description")}
                        onChange={(e) => set({ categories: st.categories.map((x, j) => (j === i ? { ...x, description: e.target.value } : x)) })} />
                      <button className="btn btn-sm" onClick={() => set({ categories: st.categories.filter((_, j) => j !== i),
                        blocked_categories: st.blocked_categories.filter((x) => x !== c.code) })}>×</button>
                    </div>
                  ))}
                  <div><button className="btn btn-sm" onClick={() => set({ categories: [...st.categories, { code: "", description: "" }] })}>{t("guardrail.add_category")}</button></div>
                </div>
              </div>
            )}

            <div className="field">
              <label>{t("guardrail.blocking")}</label>
              <p className="hint-text">{t("guardrail.blocking_hint")}</p>
              <div className="ag-stack">
                {known.map((c) => (
                  <label key={c.code} style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                    <input type="checkbox" style={{ width: "auto" }} checked={st.blocked_categories.includes(c.code)}
                      onChange={() => set({ blocked_categories: toggle(st.blocked_categories, c.code) })} />
                    <code className="mono">{c.code}</code> {c.description}
                  </label>
                ))}
              </div>
            </div>

            <div className="u-btn-row">
              <button className="btn btn-sm btn-primary" disabled={busy} onClick={save}>{busy ? t("common.loading") : t("guardrail.save")}</button>
              {saved && <span className="hint-text">{t("guardrail.saved")}</span>}
            </div>
            {error && <p className="error-text">{error}</p>}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h2>{t("guardrail.try")}</h2></div>
          <div className="panel-body">
            <p className="hint-text">{t("guardrail.try_hint")}</p>
            <textarea rows={4} value={sample} onChange={(e) => setSample(e.target.value)} />
            <div className="u-btn-row">
              <button className="btn btn-sm" disabled={busy || !sample.trim()} onClick={tryIt}>{t("guardrail.try_run")}</button>
            </div>
            {tried && (
              <p className="ag-small">
                <span className={`pill ${tried.error ? "pill-neutral" : tried.safe ? "pill-low" : "pill-critical"}`}>
                  {tried.error ? t("guardrail.unavailable") : tried.safe ? t("guardrail.safe") : t("guardrail.unsafe")}
                </span>
                {tried.categories.length > 0 && <span className="mono"> {tried.categories.join(", ")}</span>}
                {tried.block && <span> · {t("guardrail.would_block")}</span>}
                {tried.reason && <span className="hint-text"> · {tried.reason}</span>}
              </p>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
