"use client";

// PII rules of the prompt firewall: built-in types switched on or off, each
// masking or blocking, and the organization's own patterns - tested on a
// sample before saving, refused when they could run too long.

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import {
  createRule, deleteRule, piiOverview, saveBuiltin, testPii, updateRule,
  type PiiAction, type PiiOverviewT, type PiiRuleT, type PiiTestT,
} from "@/lib/pii_api";

type RuleForm = {
  id: number | null; revision: number | null; name: string; label: string; description: string;
  pattern: string; ignore_case: boolean; action: PiiAction; enabled: boolean;
};
const EMPTY: RuleForm = {
  id: null, revision: null, name: "", label: "", description: "", pattern: "", ignore_case: false,
  action: "mask", enabled: true,
};
// starting points for common identifiers; the admin adjusts them
const PRESETS: { key: string; name: string; label: string; pattern: string; sample: string }[] = [
  { key: "pinfl", name: "ПИНФЛ / JShShIR", label: "PINFL", pattern: "\\b[3-6]\\d{13}\\b", sample: "ПИНФЛ 31234567890123" },
  { key: "inn", name: "ИНН / STIR", label: "INN", pattern: "\\b[2-7]\\d{8}\\b", sample: "ИНН 301234567" },
  { key: "passport", name: "Passport (UZ)", label: "PASSPORT", pattern: "\\b[A-Z]{2}\\d{7}\\b", sample: "паспорт AB1234567" },
  { key: "contract", name: "Contract number", label: "CONTRACT", pattern: "\\b(?:ДОГ|DOG)-\\d{4}/\\d{1,6}\\b", sample: "по договору ДОГ-2026/1542" },
];

function apiError(err: unknown, t: ReturnType<typeof useTranslation>["t"], fallback: string) {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
  return msg ?? translateApiError(detail, t, fallback);
}

function Highlighted({ text, spans }: { text: string; spans: { start: number; end: number }[] }) {
  // the server counts characters (code points); JS strings count UTF-16 units
  const chars = Array.from(text);
  const cut = (a: number, b?: number) => chars.slice(a, b).join("");
  const parts: React.ReactNode[] = [];
  let at = 0;
  spans.forEach((s, i) => {
    if (s.start < at) return;
    if (s.start > at) parts.push(cut(at, s.start));
    parts.push(<mark key={i} className="pii-hit">{cut(s.start, s.end)}</mark>);
    at = s.end;
  });
  parts.push(cut(at));
  return <div className="ag-code ag-wrap pii-sample">{parts}</div>;
}

export default function PiiRulesPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [data, setData] = useState<PiiOverviewT | null>(null);
  const [draft, setDraft] = useState<Record<string, { enabled: boolean; action: PiiAction }>>({});
  const [form, setForm] = useState<RuleForm | null>(null);
  const [sample, setSample] = useState("");
  const [result, setResult] = useState<PiiTestT | null>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const seq = useRef(0);

  const load = useCallback(() => {
    piiOverview()
      .then((d) => {
        setData(d);
        setDraft(Object.fromEntries(d.builtin.map((b) => [b.type, { enabled: b.enabled, action: b.action }])));
      })
      .catch((err) => setError(apiError(err, t, t("pii.load_failed"))));
  }, [t]);
  useEffect(load, [load]);

  // live test: the sample through the firewall, with the rule being edited
  useEffect(() => {
    const mine = ++seq.current;  // also makes any answer still on its way stale
    if (!sample.trim()) { setResult(null); setTesting(false); setTestError(null); return; }
    const timer = setTimeout(() => {
      setTesting(true);
      const rule = form && form.pattern.trim()
        ? { label: form.label || undefined, pattern: form.pattern, ignore_case: form.ignore_case, action: form.action }
        : null;
      testPii(sample, rule, form?.id ?? null)
        .then((r) => { if (mine === seq.current) { setResult(r); setTestError(null); } })
        .catch((err) => { if (mine === seq.current) setTestError(apiError(err, t, t("pii.failed"))); })
        .finally(() => { if (mine === seq.current) setTesting(false); });
    }, 400);
    return () => clearTimeout(timer);
  }, [sample, form, t]);

  const dirty = !!data && data.builtin.some((b) => draft[b.type]
    && (draft[b.type].enabled !== b.enabled || draft[b.type].action !== b.action));

  async function saveTypes() {
    if (!data) return;
    const changes: Record<string, { enabled: boolean; action: PiiAction }> = {};
    for (const b of data.builtin) {
      const d = draft[b.type];
      if (d && (d.enabled !== b.enabled || d.action !== b.action)) changes[b.type] = d;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const d = await saveBuiltin(changes, data.revision);
      setData(d);
      setNotice(t("pii.saved"));
    } catch (err) {
      setError(apiError(err, t, t("pii.failed")));
      if ((err as { response?: { status?: number } })?.response?.status === 409) load();  // show what changed
    } finally {
      setBusy(false);
    }
  }

  function edit(r: PiiRuleT) {
    setForm({ id: r.id, revision: r.revision, name: r.name, label: r.label, description: r.description ?? "",
      pattern: r.pattern, ignore_case: r.ignore_case, action: r.action, enabled: r.enabled });
    setResult(null);
    setNotice(null);
  }

  function preset(p: (typeof PRESETS)[number]) {
    setForm({ ...EMPTY, name: p.name, label: p.label, pattern: p.pattern });
    setSample(p.sample);
  }

  async function saveRule(e: React.FormEvent) {
    e.preventDefault();
    if (!form) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    const body = {
      name: form.name.trim(), label: form.label.trim(), description: form.description.trim() || null,
      pattern: form.pattern, ignore_case: form.ignore_case, action: form.action, enabled: form.enabled,
    };
    try {
      if (form.id) await updateRule(form.id, { ...body, revision: form.revision ?? undefined });
      else await createRule(body);
      setForm(null);
      setNotice(t("pii.rule_saved"));
      load();
    } catch (err) {
      setError(apiError(err, t, t("pii.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function toggle(r: PiiRuleT) {
    setBusy(true);
    setError(null);
    try {
      await updateRule(r.id, { enabled: !r.enabled, revision: r.revision });
      load();
    } catch (err) {
      setError(apiError(err, t, t("pii.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function remove(r: PiiRuleT) {
    if (!window.confirm(t("pii.confirm_delete", { name: r.name }))) return;
    setBusy(true);
    setError(null);
    try {
      await deleteRule(r.id);
      if (form?.id === r.id) setForm(null);
      setNotice(t("pii.rule_deleted"));
      load();
    } catch (err) {
      setError(apiError(err, t, t("pii.failed")));
    } finally {
      setBusy(false);
    }
  }

  const ruleTest = result?.rule ?? null;
  const ruleErr = ruleTest && !ruleTest.ok
    ? t(`errors.${ruleTest.error}`, { defaultValue: ruleTest.error ?? "", detail: ruleTest.detail ?? "" }) : null;
  const names = data?.names;

  return (
    <>
      <PageHeader title={t("pii.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("pii.intro")}</p>
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- built-in types ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("pii.builtin")}</h2>
            {isAdmin && <button className="btn btn-sm btn-primary" disabled={!dirty || busy} onClick={saveTypes}>{t("pii.save")}</button>}
          </div>
          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("pii.type")}</th>
                  <th>{t("pii.example")}</th>
                  <th>{t("pii.on")}</th>
                  <th>{t("pii.action")}</th>
                </tr>
              </thead>
              <tbody>
                {(data?.builtin ?? []).map((b) => {
                  const d = draft[b.type] ?? { enabled: b.enabled, action: b.action };
                  return (
                    <tr key={b.type}>
                      <td data-label={t("pii.type")}>
                        <strong>{t(`pii.types.${b.type}`, b.type)}</strong>
                        <div className="hint-text mono" style={{ fontSize: 11 }}>[MASKED:{b.type}]</div>
                        {b.source === "names" && (
                          <div className="hint-text" style={{ fontSize: 11 }}>
                            {names?.ner_enabled ? t("pii.names_ner", { langs: names.ner_languages.join(", ") || "—" }) : t("pii.names_no_ner")}
                          </div>
                        )}
                      </td>
                      <td data-label={t("pii.example")} className="mono" style={{ fontSize: 12 }}>{b.example}</td>
                      <td data-label={t("pii.on")}>
                        <input type="checkbox" style={{ width: "auto" }} disabled={!isAdmin} checked={d.enabled}
                          aria-label={t("pii.on")}
                          onChange={(e) => setDraft({ ...draft, [b.type]: { ...d, enabled: e.target.checked } })} />
                      </td>
                      <td data-label={t("pii.action")}>
                        <select value={d.action} disabled={!isAdmin || !d.enabled} style={{ width: "auto" }}
                          onChange={(e) => setDraft({ ...draft, [b.type]: { ...d, action: e.target.value as PiiAction } })}>
                          <option value="mask">{t("pii.mask")}</option>
                          <option value="block">{t("pii.block")}</option>
                        </select>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ---------------- custom rules ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("pii.custom")}</h2>
            {isAdmin && !form && <button className="btn btn-sm btn-primary" onClick={() => setForm(EMPTY)}>{t("pii.new_rule")}</button>}
          </div>
          {isAdmin && !form && (
            <div className="panel-body" style={{ paddingBottom: 0 }}>
              <div className="ag-chips">
                <span className="hint-text ag-small">{t("pii.presets")}</span>
                {PRESETS.map((p) => <button key={p.key} type="button" className="btn btn-sm" onClick={() => preset(p)}>{p.name}</button>)}
              </div>
            </div>
          )}

          {form && (
            <div className="panel-body">
              <form onSubmit={saveRule} className="ag-stack" style={{ gap: 10 }}>
                <div className="form-row">
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="pr-name">{t("pii.name")}</label>
                    <input id="pr-name" required maxLength={100} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                  </div>
                  <div className="field" style={{ margin: 0 }}>
                    <label htmlFor="pr-label">{t("pii.label")}</label>
                    <input id="pr-label" className="mono" required maxLength={32} value={form.label} placeholder="PINFL"
                      onChange={(e) => setForm({ ...form, label: e.target.value.toUpperCase() })} />
                    <p className="hint-text">{t("pii.label_hint", { label: form.label || "LABEL" })}</p>
                  </div>
                </div>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="pr-pattern">{t("pii.pattern")}</label>
                  <input id="pr-pattern" className="mono" required maxLength={data?.limits.max_pattern_length ?? 500}
                    value={form.pattern} placeholder="\b[3-6]\d{13}\b" spellCheck={false}
                    onChange={(e) => setForm({ ...form, pattern: e.target.value })} />
                  {ruleErr ? <p className="error-text ag-small">{ruleErr}</p> : <p className="hint-text">{t("pii.pattern_hint")}</p>}
                </div>
                <div className="ag-actions" style={{ alignItems: "center", gap: 16 }}>
                  <label style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400 }}>
                    <input type="checkbox" style={{ width: "auto" }} checked={form.ignore_case}
                      onChange={(e) => setForm({ ...form, ignore_case: e.target.checked })} />{t("pii.ignore_case")}
                  </label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400 }}>
                    {t("pii.action")}
                    <select value={form.action} style={{ width: "auto" }} onChange={(e) => setForm({ ...form, action: e.target.value as PiiAction })}>
                      <option value="mask">{t("pii.mask")}</option>
                      <option value="block">{t("pii.block")}</option>
                    </select>
                  </label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center", fontWeight: 400 }}>
                    <input type="checkbox" style={{ width: "auto" }} checked={form.enabled}
                      onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />{t("pii.enabled")}
                  </label>
                </div>
                <div className="field" style={{ margin: 0 }}>
                  <label htmlFor="pr-desc">{t("pii.description")}</label>
                  <input id="pr-desc" maxLength={2000} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                </div>
                <div className="ag-actions">
                  <button className="btn btn-primary" type="submit" disabled={busy || !!ruleErr}>{t("pii.save_rule")}</button>
                  <button className="btn" type="button" onClick={() => setForm(null)}>{t("pii.cancel")}</button>
                </div>
              </form>
            </div>
          )}

          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("pii.rule")}</th>
                  <th>{t("pii.pattern")}</th>
                  <th>{t("pii.action")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data && data.rules.length === 0 && (
                  <tr className="empty-row"><td colSpan={4} className="hint-text" style={{ padding: 20 }}>{t("pii.no_rules")}</td></tr>
                )}
                {(data?.rules ?? []).map((r) => (
                  <tr key={r.id}>
                    <td data-label={t("pii.rule")}>
                      <strong>{r.name}</strong> <span className="pill pill-neutral mono" style={{ fontSize: 10 }}>{r.label}</span>
                      {!r.enabled && <span className="pill pill-neutral" style={{ fontSize: 10, marginLeft: 4 }}>{t("pii.off")}</span>}
                      {r.description && <div className="hint-text" style={{ fontSize: 12 }}>{r.description}</div>}
                      {r.timeouts > 0 && <div className="error-text" style={{ fontSize: 12 }}>{t("pii.timeouts", { count: r.timeouts })}</div>}
                    </td>
                    <td data-label={t("pii.pattern")}><code className="mono ag-wrap" style={{ fontSize: 12 }}>{r.pattern}</code>
                      {r.ignore_case && <div className="hint-text" style={{ fontSize: 11 }}>{t("pii.ignore_case")}</div>}</td>
                    <td data-label={t("pii.action")}>
                      <span className={`pill ${r.action === "block" ? "pill-critical" : "pill-medium"}`}>{t(`pii.${r.action}`)}</span>
                    </td>
                    <td>
                      {isAdmin && (
                        <div className="ag-row-actions">
                          <button className="btn btn-sm" disabled={busy} onClick={() => edit(r)}>{t("pii.edit")}</button>
                          <button className="btn btn-sm" disabled={busy} onClick={() => toggle(r)}>{r.enabled ? t("pii.disable") : t("pii.enable")}</button>
                          <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => remove(r)}>{t("pii.delete")}</button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* ---------------- tester ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{form ? t("pii.test_with_draft") : t("pii.test")}</h2></div>
          <div className="panel-body ag-stack" style={{ gap: 10 }}>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="pii-sample">{t("pii.sample")}</label>
              <textarea id="pii-sample" rows={3} maxLength={20000} value={sample} placeholder={t("pii.sample_ph")}
                onChange={(e) => setSample(e.target.value)} />
              <p className="hint-text">{t("pii.sample_hint")}</p>
            </div>
            {testing && <p className="hint-text ag-small">{t("pii.testing")}</p>}
            {testError && <p className="error-text ag-small">{testError}</p>}
            {result && sample.trim() && (
              <>
                {ruleTest?.ok && (
                  <div>
                    <div className="ag-label">{t("pii.rule_finds", { count: ruleTest.count ?? 0, ms: ruleTest.elapsed_ms ?? 0 })}</div>
                    <Highlighted text={sample} spans={ruleTest.matches} />
                  </div>
                )}
                <div>
                  <div className="ag-label">{t("pii.firewall_result")}</div>
                  {result.firewall.blocked ? (
                    <p className="ag-small"><span className="pill pill-critical">{t("pii.blocked")}</span> {result.firewall.reason}</p>
                  ) : (
                    <div className="ag-code ag-wrap">{result.firewall.masked_text}</div>
                  )}
                  {result.firewall.flags.length > 0 && (
                    <div className="ag-chips" style={{ marginTop: 6 }}>
                      {result.firewall.flags.map((f) => <span key={f} className="pill pill-neutral mono" style={{ fontSize: 10 }}>{f}</span>)}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </section>
      </div>
    </>
  );
}
