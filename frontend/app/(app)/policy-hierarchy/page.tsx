"use client";

// Policy hierarchy: organization -> team (-> sub-team) -> agent. Each level
// is edited as a form or as YAML; the effective policy next to it shows
// where every value comes from and what a lower level tried but could not
// loosen.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import { listAgents } from "@/lib/agent_api";
import type { Agent } from "@/lib/agent_types";
import {
  FIELD_ORDER, getLayer, overview, previewLayer, saveLayer,
  type FieldValue, type LayerT, type OverviewT, type PolicyDocument, type PreviewT, type Scope,
} from "@/lib/policy_layers_api";

type Sel = { scope: Scope; id: number | null; label: string };
type Tri = "" | "on" | "off";
type FormState = {
  description: string; rpm: string; maxTokens: string; depth: string; models: string; providers: string;
  toolsAllow: string; toolsDeny: string; toolsApproval: string; terms: string; scanOutput: Tri; reqApproval: Tri;
};

const EMPTY_FORM: FormState = {
  description: "", rpm: "", maxTokens: "", depth: "", models: "", providers: "", toolsAllow: "", toolsDeny: "",
  toolsApproval: "", terms: "", scanOutput: "", reqApproval: "",
};

const split = (s: string) => Array.from(new Set(s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean)));
const join = (v?: string[]) => (v ?? []).join(", ");
const num = (s: string) => (s.trim() === "" ? undefined : Number(s));
const tri = (v?: boolean): Tri => (v === undefined ? "" : v ? "on" : "off");
const fromTri = (v: Tri) => (v === "" ? undefined : v === "on");

function docFromForm(f: FormState): PolicyDocument {
  const d: PolicyDocument = {};
  const put = <K extends keyof PolicyDocument>(section: K, key: string, value: unknown) => {
    if (value === undefined || (Array.isArray(value) && value.length === 0)) return;
    const cur = (d[section] ?? {}) as Record<string, unknown>;
    cur[key] = value;
    (d as Record<string, unknown>)[section] = cur;
  };
  if (f.description.trim()) d.description = f.description.trim();
  put("limits", "requests_per_minute", num(f.rpm));
  put("limits", "max_tokens", num(f.maxTokens));
  put("limits", "max_delegation_depth", num(f.depth));
  put("models", "allow", split(f.models));
  put("providers", "allow", split(f.providers));
  put("tools", "allow", split(f.toolsAllow));
  put("tools", "deny", split(f.toolsDeny));
  put("tools", "require_approval", split(f.toolsApproval));
  put("content", "blocked_terms", split(f.terms));
  put("content", "scan_output", fromTri(f.scanOutput));
  put("requests", "require_approval", fromTri(f.reqApproval));
  return d;
}

function formFromDoc(d: PolicyDocument): FormState {
  return {
    description: d.description ?? "",
    rpm: d.limits?.requests_per_minute?.toString() ?? "", maxTokens: d.limits?.max_tokens?.toString() ?? "",
    depth: d.limits?.max_delegation_depth?.toString() ?? "", models: join(d.models?.allow),
    providers: join(d.providers?.allow), toolsAllow: join(d.tools?.allow), toolsDeny: join(d.tools?.deny),
    toolsApproval: join(d.tools?.require_approval), terms: join(d.content?.blocked_terms),
    scanOutput: tri(d.content?.scan_output), reqApproval: tri(d.requests?.require_approval),
  };
}

/** The form cannot show an empty allow list ("allow nothing"): editing such a
 *  level as a form would drop it and loosen the policy - YAML only. */
function formCannotShow(d: PolicyDocument): boolean {
  return [d.models?.allow, d.providers?.allow, d.tools?.allow].some((v) => Array.isArray(v) && v.length === 0);
}

function apiError(err: unknown, t: ReturnType<typeof useTranslation>["t"], fallback: string) {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
  const d = detail as { code?: string; context?: { path?: string; detail?: string } } | undefined;
  if (d?.code?.startsWith("policy.") && d.context?.path) {
    return `${translateApiError({ code: d.code }, t, d.code)} — ${d.context.path}${d.context.detail ? `: ${d.context.detail}` : ""}`;
  }
  return msg ?? translateApiError(detail, t, fallback);
}

function Source({ s }: { s: string }) {
  const cls = s.startsWith("agent") ? "pill-accent" : s.startsWith("team") ? "pill-medium" : "pill-neutral";
  return <span className={`pill ${cls}`} style={{ fontSize: 10 }}>{s}</span>;
}

function EffectiveValue({ kind, v }: { kind: string; v?: FieldValue }) {
  const { t } = useTranslation();
  if (!v) return <span className="hint-text">{t("ph.not_restricted")}</span>;
  if ("value" in v) {
    const shown = typeof v.value === "boolean" ? (v.value ? t("ph.on") : t("ph.off")) : String(v.value);
    return <span><strong className="mono">{shown}</strong> <Source s={v.source} /></span>;
  }
  if ("constraints" in v) {
    return (
      <div className="ag-stack" style={{ gap: 4 }}>
        {v.constraints.map((c) => (
          <div key={c.source}><Source s={c.source} />{" "}
            <span className="mono" style={{ fontSize: 12 }}>{c.patterns.length ? c.patterns.join(", ") : t("ph.nothing")}</span></div>
        ))}
        {v.constraints.length > 1 && <span className="hint-text ag-small">{t("ph.every_level_must_allow")}</span>}
      </div>
    );
  }
  if (kind === "union" && v.items.length === 0) return <span className="hint-text">{t("ph.not_restricted")}</span>;
  return (
    <div className="ag-chips">
      {v.items.map((i) => <span key={i.value} className="pill pill-neutral mono" title={i.source}>{i.value} · {i.source}</span>)}
    </div>
  );
}

export default function PolicyHierarchyPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [ov, setOv] = useState<OverviewT | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [sel, setSel] = useState<Sel>({ scope: "org", id: null, label: "" });
  const [layer, setLayer] = useState<LayerT | null>(null);
  const [tab, setTab] = useState<"form" | "yaml">("form");
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [yamlText, setYamlText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [preview, setPreview] = useState<PreviewT | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const seq = useRef(0);

  const loadOverview = useCallback(() => {
    overview().then(setOv).catch((err) => setError(apiError(err, t, t("ph.load_failed"))));
  }, [t]);
  useEffect(() => {
    loadOverview();
    listAgents().then((res) => {
      const list = res as Agent[];
      setAgents(list);
      // opened from an agent's page: /policy-hierarchy?agent=ID
      const id = Number(new URLSearchParams(window.location.search).get("agent"));
      const a = list.find((x) => x.id === id);
      if (a) setSel({ scope: "agent", id: a.id, label: `${t("ph.agent")} ${a.name}` });
    }).catch(() => setAgents([]));
  }, [loadOverview, t]);

  const load = useCallback((s: Sel) => {
    setError(null);
    setNotice(null);
    getLayer(s.scope, s.id).then((l) => {
      setLayer(l);
      setForm(formFromDoc(l.document));
      setYamlText(l.yaml);
      setDirty(false);
      if (formCannotShow(l.document)) setTab("yaml");
    }).catch((err) => setError(apiError(err, t, t("ph.load_failed"))));
  }, [t]);
  useEffect(() => { load(sel); }, [sel, load]);

  const body = useMemo(() => (tab === "yaml" ? { yaml: yamlText } : { document: docFromForm(form) }), [tab, yamlText, form]);

  // live preview of the effective policy, a moment after typing stops
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const mine = ++seq.current;
      // only the answer to the latest draft is shown
      previewLayer(sel.scope, sel.id, body).then((p) => { if (mine === seq.current) setPreview(p); })
        .catch(() => undefined);
    }, 400);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [body, sel]);

  function pick(s: Sel) {
    if (dirty && !window.confirm(t("ph.discard_changes"))) return;
    setPreview(null);
    setSel(s);
  }

  async function switchTab(next: "form" | "yaml") {
    if (next === tab) return;
    try {
      if (next === "yaml") {
        if (!dirty && layer) {
          setYamlText(layer.yaml);  // nothing edited: the stored text, comments included
        } else {
          const p = await previewLayer(sel.scope, sel.id, { document: docFromForm(form) });
          if (p.ok) setYamlText(p.yaml ?? "");
        }
      } else {
        const p = await previewLayer(sel.scope, sel.id, { yaml: yamlText });
        if (!p.ok) { setError(t("ph.fix_yaml_first")); return; }
        if (formCannotShow(p.document ?? {})) { setError(t("ph.yaml_only")); return; }
        setForm(formFromDoc(p.document ?? {}));
      }
      setError(null);
      setTab(next);
    } catch (err) {
      setError(apiError(err, t, t("ph.load_failed")));
    }
  }

  async function save(clear = false) {
    if (!layer) return;
    if (clear && !window.confirm(t("ph.confirm_clear"))) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const l = await saveLayer(sel.scope, sel.id, clear ? { document: {} } : body, layer.revision);
      setLayer(l);
      setForm(formFromDoc(l.document));
      setYamlText(l.yaml);
      setDirty(false);
      setNotice(t("ph.saved", { revision: l.revision }));
      loadOverview();
    } catch (err) {
      setError(apiError(err, t, t("ph.save_failed")));
    } finally {
      setBusy(false);
    }
  }

  const f = (k: keyof FormState) => ({
    value: form[k],
    disabled: !isAdmin,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
      setForm({ ...form, [k]: e.target.value });
      setDirty(true);
    },
  });

  // teams as a tree
  const teamRows = useMemo(() => {
    const out: { id: number; name: string; rules: number; level: number }[] = [];
    const teams = ov?.teams ?? [];
    const walk = (pid: number | null, level: number) => {
      for (const x of teams.filter((y) => y.parent_id === pid).sort((a, b) => a.name.localeCompare(b.name))) {
        out.push({ ...x, level });
        walk(x.id, level + 1);
      }
    };
    walk(null, 0);
    return out;
  }, [ov]);
  const agentLevels = ov?.agents ?? [];
  const isSel = (s: Scope, id: number | null) => sel.scope === s && sel.id === id;
  const title = sel.scope === "org" ? t("ph.org") : sel.label;
  const triOptions = (
    <>
      <option value="">{t("ph.not_set")}</option>
      <option value="on">{t("ph.on")}</option>
      <option value="off">{t("ph.off")}</option>
    </>
  );

  return (
    <>
      <PageHeader title={t("ph.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("ph.intro")}</p>
        {error && <p className="error-text ag-banner">{error}</p>}
        {notice && <p className="hint-text ag-banner">{notice}</p>}

        <div className="ph-layout">
          {/* ---------------- levels ---------------- */}
          <aside className="panel ph-tree">
            <div className="panel-header"><h2>{t("ph.levels")}</h2></div>
            <div className="panel-body" style={{ display: "grid", gap: 4 }}>
              <button className={`ph-node${isSel("org", null) ? " active" : ""}`} onClick={() => pick({ scope: "org", id: null, label: "" })}>
                <span>{t("ph.org")}</span>{ov && ov.org.rules > 0 && <span className="pill pill-neutral">{ov.org.rules}</span>}
              </button>
              <div className="ag-label" style={{ marginTop: 10 }}>{t("ph.teams")}</div>
              {teamRows.length === 0 && <span className="hint-text ag-small">{t("ph.no_teams")}</span>}
              {teamRows.map((x) => (
                <button key={x.id} className={`ph-node${isSel("team", x.id) ? " active" : ""}`} style={{ paddingLeft: 10 + x.level * 14 }}
                  onClick={() => pick({ scope: "team", id: x.id, label: `${t("ph.team")} ${x.name}` })}>
                  <span>{x.level > 0 && <span className="hint-text">└ </span>}{x.name}</span>
                  {x.rules > 0 && <span className="pill pill-neutral">{x.rules}</span>}
                </button>
              ))}
              <div className="ag-label" style={{ marginTop: 10 }}>{t("ph.agents")}</div>
              {agentLevels.map((x) => (
                <button key={x.id} className={`ph-node${isSel("agent", x.id) ? " active" : ""}`}
                  onClick={() => pick({ scope: "agent", id: x.id, label: `${t("ph.agent")} ${x.name}` })}>
                  <span>{x.name}</span><span className="pill pill-neutral">{x.rules}</span>
                </button>
              ))}
              <select aria-label={t("ph.agent_level_for")} value=""
                onChange={(e) => {
                  const a = agents.find((y) => String(y.id) === e.target.value);
                  if (a) pick({ scope: "agent", id: a.id, label: `${t("ph.agent")} ${a.name}` });
                }}>
                <option value="">{t("ph.agent_level_for")}</option>
                {agents.filter((a) => a.status !== "retired").map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
              </select>
            </div>
          </aside>

          <div className="ag-stack" style={{ minWidth: 0 }}>
            {/* ---------------- editor ---------------- */}
            <section className="panel">
              <div className="panel-header">
                <h2>{title} {layer && layer.revision > 0 && <span className="hint-text" style={{ fontWeight: 400 }}>· rev {layer.revision}</span>}</h2>
                <div className="ag-actions">
                  <button className={`btn btn-sm${tab === "form" ? " btn-primary" : ""}`} onClick={() => switchTab("form")}>{t("ph.form")}</button>
                  <button className={`btn btn-sm${tab === "yaml" ? " btn-primary" : ""}`} onClick={() => switchTab("yaml")}>YAML</button>
                </div>
              </div>
              <div className="panel-body ag-stack">
                <p className="hint-text ag-small">{t(`ph.scope_hint_${sel.scope}`)}</p>
                {tab === "yaml" ? (
                  <textarea className="mono ag-wrap" rows={18} style={{ fontSize: 12 }} value={yamlText} disabled={!isAdmin}
                    spellCheck={false} placeholder={"limits:\n  max_tokens: 2000\ntools:\n  deny: [\"shell.*\"]"}
                    onChange={(e) => { setYamlText(e.target.value); setDirty(true); }} />
                ) : (
                  <>
                    <div className="ph-fields">
                      <div className="field"><label>{t("ph.f.requests_per_minute")}</label><input type="number" min={1} {...f("rpm")} /></div>
                      <div className="field"><label>{t("ph.f.max_tokens")}</label><input type="number" min={1} {...f("maxTokens")} /></div>
                      <div className="field"><label>{t("ph.f.max_delegation_depth")}</label><input type="number" min={0} max={10} {...f("depth")} /></div>
                    </div>
                    <div className="ph-fields">
                      <div className="field"><label>{t("ph.f.models_allow")}</label><input className="mono" placeholder="gpt-4o-mini, claude-*" {...f("models")} /></div>
                      <div className="field"><label>{t("ph.f.providers_allow")}</label><input className="mono" placeholder="openai, anthropic" {...f("providers")} /></div>
                    </div>
                    <div className="ph-fields">
                      <div className="field"><label>{t("ph.f.tools_allow")}</label><input className="mono" placeholder="kb.*, openai.chat" {...f("toolsAllow")} /></div>
                      <div className="field"><label>{t("ph.f.tools_deny")}</label><input className="mono" placeholder="shell.*" {...f("toolsDeny")} /></div>
                      <div className="field"><label>{t("ph.f.tools_require_approval")}</label><input className="mono" placeholder="email.send" {...f("toolsApproval")} /></div>
                    </div>
                    <div className="field"><label>{t("ph.f.blocked_terms")}</label><textarea rows={2} {...f("terms")} /></div>
                    <div className="ph-fields">
                      <div className="field"><label>{t("ph.f.scan_output")}</label><select {...f("scanOutput")}>{triOptions}</select></div>
                      {sel.scope === "org" && (
                        <div className="field"><label>{t("ph.f.requests_require_approval")}</label><select {...f("reqApproval")}>{triOptions}</select></div>
                      )}
                    </div>
                    <p className="hint-text ag-small">{t("ph.form_hint")}</p>
                  </>
                )}
                {preview && !preview.ok && preview.error && (
                  <p className="error-text ag-small">
                    {t(`errors.${preview.error.code}`, preview.error.code)}{preview.error.path ? ` — ${preview.error.path}` : ""}
                    {preview.error.detail ? `: ${preview.error.detail}` : ""}
                  </p>
                )}
                {isAdmin && (
                  <div className="ag-actions">
                    <button className="btn btn-primary" disabled={busy || !dirty || (preview !== null && !preview.ok)} onClick={() => save()}>{t("ph.save")}</button>
                    {layer && layer.revision > 0 && Object.keys(layer.document).length > 0 && (
                      <button className="btn" disabled={busy} onClick={() => save(true)}>{t("ph.clear")}</button>
                    )}
                    {dirty && <span className="hint-text ag-small">{t("ph.unsaved")}</span>}
                  </div>
                )}
              </div>
            </section>

            {/* ---------------- effective ---------------- */}
            <section className="panel">
              <div className="panel-header"><h2>{t("ph.effective")}</h2></div>
              {preview?.ok && preview.levels && (
                <div className="panel-body" style={{ paddingBottom: 10 }}>
                  <div className="ag-chips">
                    {preview.levels.map((lv, i) => (
                      <span key={i} className="ag-small">{i > 0 && "→ "}<Source s={lv.source} /></span>
                    ))}
                  </div>
                  {sel.scope === "org" && <p className="hint-text ag-small" style={{ marginTop: 6 }}>{t("ph.org_effective_hint")}</p>}
                </div>
              )}
              <div className="ag-table-wrap">
                <table className="table-cards">
                  <tbody>
                    {FIELD_ORDER.map(({ field, kind }) => (
                      <tr key={field}>
                        <td data-label={t(`ph.field.${field}`)} style={{ width: "34%" }}><span className="hint-text">{t(`ph.field.${field}`)}</span></td>
                        <td><EffectiveValue kind={kind} v={preview?.effective?.fields[field]} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {preview?.effective && preview.effective.ignored.length > 0 && (
                <div className="panel-body ag-footer">
                  <div className="ag-label">{t("ph.ignored")}</div>
                  {preview.effective.ignored.map((i, n) => (
                    <div key={n} className="ag-small" style={{ color: "var(--risk-medium)" }}>
                      <Source s={i.source} /> {t(`ph.field.${i.field}`)} = <span className="mono">{String(i.value)}</span>{" "}
                      — {t("ph.ignored_because", { level: i.because })}
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </div>
      </div>
    </>
  );
}
