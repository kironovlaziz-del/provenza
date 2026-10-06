"use client";

// Blocked terms, in one place: each term with where it applies (the whole
// organization, every agent, a team, one agent, one policy), how it is
// matched (whole word, seeing through disguises, or anywhere), and what it
// does (block, or only record). Categories switch groups on and off; hits
// are counted; CSV in and out; a tester shows what a sample would trip.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import {
  TERM_SCOPES, createCategory, createTerm, deleteCategory, deleteTerm, exportTermsCsv, importTermsCsv, termsOverview,
  testTerms, updateCategory, updateTerm,
  type BlockedTermT, type ImportResultT, type TermAction, type TermInput, type TermMatch, type TermScope,
  type TermTestT, type TermsOverviewT,
} from "@/lib/blocked_terms_api";

type Form = TermInput & { id: number | null };
const EMPTY: Form = {
  id: null, term: "", match: "word", action: "block", scope: "org", target_id: null, category_id: null,
  enabled: true, note: null,
};

function apiError(err: unknown, t: ReturnType<typeof useTranslation>["t"], fallback: string) {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
  return msg ?? translateApiError(detail, t, fallback);
}

function Highlighted({ text, spans }: { text: string; spans: { start: number; end: number }[] }) {
  const chars = Array.from(text); // the server counts code points
  const cut = (a: number, b?: number) => chars.slice(a, b).join("");
  const parts: React.ReactNode[] = [];
  let at = 0;
  [...spans].sort((x, y) => x.start - y.start).forEach((s, i) => {
    if (s.start < at) return;
    if (s.start > at) parts.push(cut(at, s.start));
    parts.push(<mark key={i} className="pii-hit">{cut(s.start, s.end)}</mark>);
    at = s.end;
  });
  parts.push(cut(at));
  return <div className="ag-code ag-wrap pii-sample">{parts}</div>;
}

export default function BlockedTermsPage() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [data, setData] = useState<TermsOverviewT | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [filter, setFilter] = useState({ q: "", scope: "", category: "", action: "" });
  const [newCategory, setNewCategory] = useState("");
  const [sample, setSample] = useState("");
  const [result, setResult] = useState<(TermTestT & { sample: string }) | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [importText, setImportText] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<ImportResultT | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const seq = useRef(0);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    termsOverview().then(setData).catch((err) => setError(apiError(err, t, t("bt.load_failed"))));
  }, [t]);
  useEffect(load, [load]);

  useEffect(() => {
    const mine = ++seq.current;
    if (!sample.trim()) { setResult(null); setTestError(null); return; }
    const timer = setTimeout(() => {
      const draft = form && form.term.trim() ? { term: form.term, match: form.match, action: form.action } : null;
      testTerms(sample, draft)
        .then((r) => { if (mine === seq.current) { setResult({ ...r, sample }); setTestError(null); } })
        .catch((err) => { if (mine === seq.current) setTestError(apiError(err, t, t("bt.failed"))); });
    }, 350);
    return () => clearTimeout(timer);
  }, [sample, form, t]);

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");
  const scopeLabel = (s: string, name?: string | null) => `${t(`bt.scope.${s}`)}${name ? `: ${name}` : ""}`;

  const shown = useMemo(() => {
    const q = filter.q.trim().toLowerCase();
    return (data?.terms ?? []).filter((x) =>
      (!q || x.term.toLowerCase().includes(q) || (x.note ?? "").toLowerCase().includes(q))
      && (!filter.scope || x.scope === filter.scope)
      && (!filter.action || x.action === filter.action)
      && (!filter.category || String(x.category_id ?? "none") === filter.category));
  }, [data, filter]);

  const targets = (scope: TermScope) =>
    scope === "team" ? data?.targets.teams : scope === "agent" ? data?.targets.agents
      : scope === "policy" ? data?.targets.policies : undefined;

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(done);
      load();
      return true;
    } catch (err) {
      setError(apiError(err, t, t("bt.failed")));
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!form) return;
    const body: TermInput = {
      term: form.term.trim(), match: form.match, action: form.action, scope: form.scope,
      target_id: ["team", "agent", "policy"].includes(form.scope) ? form.target_id : null,
      category_id: form.category_id, enabled: form.enabled, note: form.note?.trim() || null,
    };
    const ok = await act(() => (form.id ? updateTerm(form.id, body) : createTerm(body)), t("bt.saved"));
    if (ok) setForm(null);
  }

  function edit(x: BlockedTermT) {
    setForm({ id: x.id, term: x.term, match: x.match, action: x.action, scope: x.scope, target_id: x.target_id,
      category_id: x.category_id, enabled: x.enabled, note: x.note });
  }

  async function download() {
    try {
      const blob = await exportTermsCsv();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "blocked-terms.csv";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);  // some browsers start the download later
    } catch (err) {
      setError(apiError(err, t, t("bt.failed")));
    }
  }

  async function readFile(f: File | undefined) {
    if (!f) return;
    if (f.size > 2_000_000) { setError(t("bt.import_too_big")); return; }
    const text = await f.text();
    setImportText(text);
    setImportResult(null);
    setError(null);
    try {
      setImportResult(await importTermsCsv(text, true));
    } catch (err) {
      setError(apiError(err, t, t("bt.failed")));
    }
  }

  async function runImport() {
    if (importText === null) return;
    const ok = await act(async () => setImportResult(await importTermsCsv(importText, false)), t("bt.imported"));
    if (ok) setImportText(null);
  }

  const whyText = (why: string) => t(`errors.${why}`, why);

  return (
    <>
      <PageHeader title={t("bt.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("bt.intro")}</p>
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- terms ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("bt.terms")} <span className="hint-text" style={{ fontWeight: 400 }}>{data ? `· ${data.terms.length}` : ""}</span></h2>
            <div className="ag-actions">
              {isAdmin && !form && <button className="btn btn-sm btn-primary" onClick={() => setForm(EMPTY)}>{t("bt.add")}</button>}
              {isAdmin && <button className="btn btn-sm" onClick={() => fileRef.current?.click()}>{t("bt.import")}</button>}
              <button className="btn btn-sm" onClick={download}>{t("bt.export")}</button>
              <input ref={fileRef} type="file" accept=".csv,text/csv" hidden
                onChange={(e) => { readFile(e.target.files?.[0]); e.target.value = ""; }} />
            </div>
          </div>

          {importText !== null && importResult && (
            <div className="panel-body">
              <div className="ag-stack" style={{ gap: 8 }}>
                <div className="ag-label">{t("bt.import_preview")}</div>
                <p className="ag-small">{t("bt.import_counts", { added: importResult.added, skipped: importResult.skipped.length, errors: importResult.errors.length })}</p>
                {importResult.errors.length > 0 && (
                  <details className="ag-details"><summary>{t("bt.import_errors")}</summary>
                    {importResult.errors.slice(0, 50).map((x) => <div key={x.line} className="ag-small">{t("bt.line", { n: x.line })} {x.term && <code className="mono">{x.term}</code>} — {whyText(x.why)}</div>)}
                  </details>
                )}
                {importResult.skipped.length > 0 && (
                  <details className="ag-details"><summary>{t("bt.import_skipped")}</summary>
                    {importResult.skipped.slice(0, 50).map((x) => <div key={x.line} className="ag-small">{t("bt.line", { n: x.line })} <code className="mono">{x.term}</code> — {whyText(x.why)}</div>)}
                  </details>
                )}
                <div className="ag-actions">
                  <button className="btn btn-sm btn-primary" disabled={busy || importResult.added === 0} onClick={runImport}>{t("bt.import_confirm", { count: importResult.added })}</button>
                  <button className="btn btn-sm" onClick={() => { setImportText(null); setImportResult(null); }}>{t("bt.cancel")}</button>
                </div>
              </div>
            </div>
          )}

          {form && (
            <div className="panel-body">
              <form onSubmit={save} className="ag-stack" style={{ gap: 10 }}>
                <div className="ph-fields" style={{ gap: "10px 14px" }}>
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="bt-term">{t("bt.term")}</label>
                    <input id="bt-term" required maxLength={data?.limits.max_term_length ?? 200} value={form.term}
                      onChange={(e) => setForm({ ...form, term: e.target.value })} placeholder="Project Titan" />
                  </div>
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="bt-match">{t("bt.match")}</label>
                    <select id="bt-match" value={form.match} onChange={(e) => setForm({ ...form, match: e.target.value as TermMatch })}>
                      <option value="word">{t("bt.match_word")}</option>
                      <option value="substring">{t("bt.match_substring")}</option>
                    </select>
                  </div>
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="bt-action">{t("bt.action")}</label>
                    <select id="bt-action" value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as TermAction })}>
                      <option value="block">{t("bt.block")}</option>
                      <option value="monitor">{t("bt.monitor")}</option>
                    </select>
                  </div>
                </div>
                <p className="hint-text ag-small" style={{ marginTop: -4 }}>{t(`bt.match_hint_${form.match}`)}</p>
                <div className="ph-fields" style={{ gap: "10px 14px" }}>
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="bt-scope">{t("bt.where")}</label>
                    <select id="bt-scope" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as TermScope, target_id: null })}>
                      {TERM_SCOPES.map((s) => <option key={s} value={s}>{t(`bt.scope.${s}`)}</option>)}
                    </select>
                    <p className="hint-text">{t(`bt.scope_hint.${form.scope}`)}</p>
                  </div>
                  {targets(form.scope) && (
                    <div className="field" style={{ margin: 0 }}>
                      <label htmlFor="bt-target">{t(`bt.target.${form.scope}`)}</label>
                      <select id="bt-target" required value={form.target_id ?? ""}
                        onChange={(e) => setForm({ ...form, target_id: e.target.value ? Number(e.target.value) : null })}>
                        <option value="">{t("bt.choose")}</option>
                        {targets(form.scope)!.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
                      </select>
                    </div>
                  )}
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="bt-cat">{t("bt.category")}</label>
                    <select id="bt-cat" value={form.category_id ?? ""}
                      onChange={(e) => setForm({ ...form, category_id: e.target.value ? Number(e.target.value) : null })}>
                      <option value="">{t("bt.no_category")}</option>
                      {(data?.categories ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </div>
                </div>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="bt-note">{t("bt.note")}</label>
                  <input id="bt-note" maxLength={1000} value={form.note ?? ""} onChange={(e) => setForm({ ...form, note: e.target.value })} />
                </div>
                <label style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400 }}>
                  <input type="checkbox" style={{ width: "auto" }} checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                  {t("bt.enabled")}
                </label>
                <div className="ag-actions">
                  <button className="btn btn-primary" type="submit" disabled={busy || !form.term.trim()}>{t("bt.save")}</button>
                  <button className="btn" type="button" onClick={() => setForm(null)}>{t("bt.cancel")}</button>
                </div>
              </form>
            </div>
          )}

          <div className="panel-body bt-filters">
            <input type="search" placeholder={t("bt.search")} value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} aria-label={t("bt.search")} />
            <select value={filter.scope} onChange={(e) => setFilter({ ...filter, scope: e.target.value })} aria-label={t("bt.where")}>
              <option value="">{t("bt.all_scopes")}</option>
              {TERM_SCOPES.map((s) => <option key={s} value={s}>{t(`bt.scope.${s}`)}</option>)}
            </select>
            <select value={filter.category} onChange={(e) => setFilter({ ...filter, category: e.target.value })} aria-label={t("bt.category")}>
              <option value="">{t("bt.all_categories")}</option>
              <option value="none">{t("bt.no_category")}</option>
              {(data?.categories ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <select value={filter.action} onChange={(e) => setFilter({ ...filter, action: e.target.value })} aria-label={t("bt.action")}>
              <option value="">{t("bt.all_actions")}</option>
              <option value="block">{t("bt.block")}</option>
              <option value="monitor">{t("bt.monitor")}</option>
            </select>
          </div>

          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("bt.term")}</th>
                  <th>{t("bt.where")}</th>
                  <th>{t("bt.action")}</th>
                  <th>{t("bt.hits")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data && shown.length === 0 && (
                  <tr className="empty-row"><td colSpan={5} className="hint-text" style={{ padding: 20 }}>{data.terms.length ? t("bt.none_match") : t("bt.no_terms")}</td></tr>
                )}
                {shown.map((x) => (
                  <tr key={x.id} style={x.enabled ? undefined : { opacity: 0.6 }}>
                    <td data-label={t("bt.term")}>
                      <strong className="ag-wrap" style={{ display: "inline" }}>{x.term}</strong>
                      <div className="hint-text" style={{ fontSize: 11 }}>
                        {t(`bt.match_${x.match}`)}{x.category ? ` · ${x.category}` : ""}{!x.enabled ? ` · ${t("bt.off")}` : ""}
                      </div>
                      {x.note && <div className="hint-text ag-wrap" style={{ fontSize: 12 }}>{x.note}</div>}
                    </td>
                    <td data-label={t("bt.where")} className="ag-small">{scopeLabel(x.scope, x.target_name)}</td>
                    <td data-label={t("bt.action")}>
                      <span className={`pill ${x.action === "block" ? "pill-critical" : "pill-medium"}`}>{t(`bt.${x.action}`)}</span>
                    </td>
                    <td data-label={t("bt.hits")} className="ag-small">
                      {x.hits}{x.last_hit_at && <div className="hint-text" style={{ fontSize: 11 }}>{fmt(x.last_hit_at)}</div>}
                    </td>
                    <td>
                      {isAdmin && (
                        <div className="ag-row-actions">
                          <button className="btn btn-sm" disabled={busy} onClick={() => edit(x)}>{t("bt.edit")}</button>
                          <button className="btn btn-sm" disabled={busy}
                            onClick={() => act(() => updateTerm(x.id, { enabled: !x.enabled }), t("bt.saved"))}>
                            {x.enabled ? t("bt.disable") : t("bt.enable")}
                          </button>
                          <button className="btn btn-sm btn-danger" disabled={busy}
                            onClick={() => window.confirm(t("bt.confirm_delete", { term: x.term })) && act(() => deleteTerm(x.id), t("bt.deleted"))}>
                            {t("bt.delete")}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* ---------------- categories ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{t("bt.categories")}</h2></div>
          <div className="panel-body ag-stack" style={{ gap: 10 }}>
            {(data?.categories ?? []).length === 0 && <p className="hint-text ag-small">{t("bt.no_categories")}</p>}
            {(data?.categories ?? []).map((c) => (
              <div key={c.id} className="bt-cat">
                <label style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400, margin: 0 }}>
                  <input type="checkbox" style={{ width: "auto" }} disabled={!isAdmin || busy} checked={c.enabled}
                    onChange={() => act(() => updateCategory(c.id, { enabled: !c.enabled }), t("bt.saved"))} />
                  <strong>{c.name}</strong>
                  <span className="hint-text ag-small">{t("bt.category_terms", { count: c.terms })}{!c.enabled ? ` · ${t("bt.category_off")}` : ""}</span>
                </label>
                {isAdmin && (
                  <button className="btn btn-sm" disabled={busy}
                    onClick={() => window.confirm(t("bt.confirm_delete_category", { name: c.name })) && act(() => deleteCategory(c.id), t("bt.deleted"))}>
                    {t("bt.delete")}
                  </button>
                )}
              </div>
            ))}
            {isAdmin && (
              <form className="bt-cat-add" onSubmit={(e) => { e.preventDefault(); if (newCategory.trim()) act(() => createCategory(newCategory.trim()), t("bt.saved")).then((ok) => ok && setNewCategory("")); }}>
                <input maxLength={100} value={newCategory} placeholder={t("bt.new_category")} onChange={(e) => setNewCategory(e.target.value)} aria-label={t("bt.new_category")} />
                <button className="btn btn-sm" type="submit" disabled={busy || !newCategory.trim()}>{t("bt.add_category")}</button>
              </form>
            )}
          </div>
        </section>

        {/* ---------------- tester ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{form ? t("bt.test_with_draft") : t("bt.test")}</h2></div>
          <div className="panel-body ag-stack" style={{ gap: 10 }}>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="bt-sample">{t("bt.sample")}</label>
              <textarea id="bt-sample" rows={3} maxLength={20000} value={sample} placeholder={t("bt.sample_ph")}
                onChange={(e) => setSample(e.target.value)} />
              <p className="hint-text">{t("bt.sample_hint")}</p>
            </div>
            {testError && <p className="error-text ag-small">{testError}</p>}
            {result && result.sample === sample && sample.trim() && (result.hits.length === 0 ? (
              <p className="ag-small"><span className="pill pill-low">{t("bt.nothing_found")}</span></p>
            ) : (
              <>
                <Highlighted text={sample} spans={result.hits.flatMap((h) => h.spans)} />
                <div className="ag-stack" style={{ gap: 4 }}>
                  {result.hits.map((h, i) => (
                    <div key={`${h.id}-${i}`} className="ag-small">
                      <span className={`pill ${h.action === "block" ? "pill-critical" : "pill-medium"}`}>{t(`bt.${h.action}`)}</span>{" "}
                      <strong>{h.term}</strong> · {h.scope === "draft" ? t("bt.draft") : scopeLabel(h.scope, h.target_name)}
                      {h.category ? ` · ${h.category}` : ""} — {h.spans.map((s) => `«${s.text}»`).join(", ")}
                    </div>
                  ))}
                </div>
              </>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}
