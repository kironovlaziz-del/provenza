"use client";

// Workload attestation: policies saying where agents must prove they run
// (Kubernetes ServiceAccount tokens of a cluster, from allowed namespaces /
// service accounts), a token tester, and every attestation attempt.

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { PageHeader } from "@/components/PageHeader";
import { useAuth } from "@/lib/auth";
import { translateApiError } from "@/lib/errors";
import {
  attestCommand, createPolicy, deletePolicy, listAttestations, listPolicies, podSpecSnippet, testPolicy,
  updatePolicy, type AttestationPolicyT, type AttestationT, type PolicyInput,
} from "@/lib/attestation_api";

type JwksMode = "paste" | "url" | "discovery";
type PolicyForm = {
  id: number | null; name: string; description: string; issuer: string; audience: string; jwksMode: JwksMode;
  jwks: string; jwksUrl: string; namespaces: string; serviceAccounts: string; requirePod: boolean; validity: number;
};
const EMPTY: PolicyForm = {
  id: null, name: "", description: "", issuer: "", audience: "provenza", jwksMode: "paste", jwks: "", jwksUrl: "",
  namespaces: "", serviceAccounts: "", requirePod: true, validity: 60,
};

const split = (s: string) => Array.from(new Set(s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean)));

function apiError(err: unknown, t: ReturnType<typeof useTranslation>["t"], fallback: string) {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  const msg = Array.isArray(detail) && detail[0]?.msg ? String(detail[0].msg).replace(/^Value error, /, "") : null;
  return msg ?? translateApiError(detail, t, fallback);
}

export default function AttestationPage() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [policies, setPolicies] = useState<AttestationPolicyT[]>([]);
  const [records, setRecords] = useState<AttestationT[]>([]);
  const [form, setForm] = useState<PolicyForm | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [setupFor, setSetupFor] = useState<number | null>(null);
  const [testFor, setTestFor] = useState<number | null>(null);
  const [testToken, setTestToken] = useState("");
  const [testResult, setTestResult] = useState<Awaited<ReturnType<typeof testPolicy>> | null>(null);

  const load = useCallback(() => {
    Promise.all([listPolicies(), listAttestations(undefined, 50)])
      .then(([p, r]) => { setPolicies(p); setRecords(r); })
      .catch((err) => setError(apiError(err, t, t("attest.load_failed"))));
  }, [t]);
  useEffect(load, [load]);

  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");

  function edit(p: AttestationPolicyT) {
    setForm({
      id: p.id, name: p.name, description: p.description ?? "", issuer: p.issuer, audience: p.audience,
      jwksMode: p.jwks_keys.length ? "paste" : p.jwks_url ? "url" : "discovery", jwks: "", jwksUrl: p.jwks_url ?? "",
      namespaces: p.namespaces.join(", "), serviceAccounts: p.service_accounts.join(", "),
      requirePod: p.require_pod_bound, validity: p.validity_minutes,
    });
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!form) return;
    let jwks: unknown = undefined;
    if (form.jwksMode === "paste" && form.jwks.trim()) {
      try {
        jwks = JSON.parse(form.jwks);
      } catch {
        setError(t("attest.jwks_not_json"));
        return;
      }
    }
    if (form.jwksMode === "url" && !form.jwksUrl.trim()) {
      setError(t("attest.jwks_url_required"));
      return;
    }
    const body: PolicyInput = {
      name: form.name.trim(), description: form.description.trim() || null, issuer: form.issuer.trim(),
      audience: form.audience.trim(), namespaces: split(form.namespaces), service_accounts: split(form.serviceAccounts),
      require_pod_bound: form.requirePod, validity_minutes: form.validity,
      jwks_url: form.jwksMode === "url" ? form.jwksUrl.trim() || null : null,
    };
    // pasted keys: new ones replace; editing without pasting keeps the stored ones
    if (form.jwksMode === "paste") {
      const hasKeys = !!policies.find((p) => p.id === form.id)?.jwks_keys.length;
      if (jwks !== undefined) body.jwks = jwks;
      else if (!form.id || !hasKeys) { setError(t("attest.jwks_required")); return; }
    } else {
      body.jwks = null;
    }
    if (form.id) {
      const current = policies.find((p) => p.id === form.id);
      if (current && current.roles > 0 && !window.confirm(t("attest.confirm_update"))) return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (form.id) await updatePolicy(form.id, body);
      else await createPolicy(body);
      setForm(null);
      setNotice(t("attest.saved"));
      load();
    } catch (err) {
      setError(apiError(err, t, t("attest.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function remove(p: AttestationPolicyT) {
    if (!window.confirm(t("attest.confirm_delete", { name: p.name }))) return;
    setBusy(true);
    setError(null);
    try {
      await deletePolicy(p.id);
      setNotice(t("attest.deleted"));
      load();
    } catch (err) {
      setError(apiError(err, t, t("attest.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function runTest(id: number) {
    setTestResult(null);
    try {
      setTestResult(await testPolicy(id, testToken.trim()));
    } catch (err) {
      setError(apiError(err, t, t("attest.failed")));
    }
  }

  const reasonText = (code: string | null, detail?: string | null) =>
    code ? `${t(`errors.${code}`, code)}${detail ? ` — ${detail}` : ""}` : "";

  return (
    <>
      <PageHeader title={t("attest.title")} />
      <div className="content agent-page">
        <p className="hint-text u-mb-16">{t("attest.intro")}</p>
        {error && <p className="error-text u-mb-16">{error}</p>}
        {notice && <p className="hint-text u-mb-16">{notice}</p>}

        {/* ---------------- policies ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header">
            <h2>{t("attest.policies")}</h2>
            {isAdmin && !form && <button className="btn btn-sm btn-primary" onClick={() => setForm(EMPTY)}>{t("attest.new_policy")}</button>}
          </div>

          {form && (
            <div className="panel-body">
              <Form onSubmit={save}>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="ap-name">{t("attest.name")}</label>
                    <input id="ap-name" required maxLength={100} value={form.name} placeholder="prod-cluster"
                      onChange={(e) => setForm({ ...form, name: e.target.value })} />
                  </div>
                  <div className="field">
                    <label htmlFor="ap-validity">{t("attest.validity")}</label>
                    <input id="ap-validity" type="number" min={5} max={1440} value={form.validity}
                      onChange={(e) => setForm({ ...form, validity: Number(e.target.value) })} />
                    <p className="hint-text">{t("attest.validity_hint")}</p>
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="ap-desc">{t("attest.description")}</label>
                  <input id="ap-desc" maxLength={2000} value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })} />
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="ap-iss">{t("attest.issuer")}</label>
                    <input id="ap-iss" className="mono" required value={form.issuer}
                      placeholder="https://kubernetes.default.svc.cluster.local"
                      onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
                    <p className="hint-text">{t("attest.issuer_hint")} <code className="mono">kubectl get --raw /.well-known/openid-configuration</code></p>
                  </div>
                  <div className="field">
                    <label htmlFor="ap-aud">{t("attest.audience")}</label>
                    <input id="ap-aud" className="mono" required value={form.audience}
                      onChange={(e) => setForm({ ...form, audience: e.target.value })} />
                    <p className="hint-text">{t("attest.audience_hint")}</p>
                  </div>
                </div>
                <div className="field">
                  <label>{t("attest.jwks")}</label>
                  {(["paste", "url", "discovery"] as JwksMode[]).map((m) => (
                    <label key={m} style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 400 }}>
                      <input type="radio" name="jwks-mode" style={{ width: "auto" }} checked={form.jwksMode === m}
                        onChange={() => setForm({ ...form, jwksMode: m })} />
                      {t(`attest.jwks_${m}`)}
                    </label>
                  ))}
                  {form.jwksMode === "paste" && (
                    <>
                      <textarea className="mono" rows={5} value={form.jwks} style={{ fontSize: 11 }}
                        placeholder={form.id ? t("attest.jwks_keep") : '{"keys": [...]}'}
                        onChange={(e) => setForm({ ...form, jwks: e.target.value })} />
                      <p className="hint-text">{t("attest.jwks_paste_hint")} <code className="mono">kubectl get --raw /openid/v1/jwks</code></p>
                    </>
                  )}
                  {form.jwksMode === "url" && (
                    <input className="mono" value={form.jwksUrl} placeholder="https://…/openid/v1/jwks"
                      onChange={(e) => setForm({ ...form, jwksUrl: e.target.value })} />
                  )}
                  {form.jwksMode === "discovery" && <p className="hint-text">{t("attest.jwks_discovery_hint")}</p>}
                </div>
                <div className="form-row">
                  <div className="field">
                    <label htmlFor="ap-ns">{t("attest.namespaces")}</label>
                    <input id="ap-ns" className="mono" value={form.namespaces} placeholder="agents, team-*"
                      onChange={(e) => setForm({ ...form, namespaces: e.target.value })} />
                  </div>
                  <div className="field">
                    <label htmlFor="ap-sa">{t("attest.service_accounts")}</label>
                    <input id="ap-sa" className="mono" value={form.serviceAccounts} placeholder="payments/billing-agent"
                      onChange={(e) => setForm({ ...form, serviceAccounts: e.target.value })} />
                  </div>
                </div>
                <p className="hint-text" style={{ marginTop: -6 }}>{t("attest.rules_hint")}</p>
                <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
                  <input type="checkbox" style={{ width: "auto", marginTop: 3 }} checked={form.requirePod}
                    onChange={(e) => setForm({ ...form, requirePod: e.target.checked })} />
                  <span>{t("attest.require_pod")}<span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("attest.require_pod_hint")}</span></span>
                </label>
                <div className="ag-actions" style={{ marginTop: 12 }}>
                  <button className="btn btn-primary" type="submit" disabled={busy}>{t("attest.save")}</button>
                  <button className="btn" type="button" onClick={() => setForm(null)}>{t("attest.cancel")}</button>
                </div>
              </Form>
            </div>
          )}

          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("attest.policy")}</th>
                  <th>{t("attest.workloads")}</th>
                  <th>{t("attest.validity_short")}</th>
                  <th>{t("attest.roles")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {policies.length === 0 && (
                  <tr className="empty-row"><td colSpan={5} className="hint-text" style={{ padding: 20 }}>{t("attest.no_policies")}</td></tr>
                )}
                {policies.map((p) => (
                  <React.Fragment key={p.id}>
                    <tr>
                      <td data-label={t("attest.policy")}>
                        <strong>{p.name}</strong>
                        <div className="hint-text mono" style={{ fontSize: 11 }}>{p.issuer}</div>
                        <div className="hint-text" style={{ fontSize: 11 }}>
                          aud <code className="mono">{p.audience}</code> ·{" "}
                          {p.jwks_keys.length ? t("attest.keys_pasted", { count: p.jwks_keys.length }) : p.jwks_url ? t("attest.keys_url") : t("attest.keys_discovery")}
                        </div>
                      </td>
                      <td data-label={t("attest.workloads")} className="mono" style={{ fontSize: 12 }}>
                        {p.namespaces.map((n) => <div key={`n${n}`}>ns: {n}</div>)}
                        {p.service_accounts.map((s) => <div key={`s${s}`}>sa: {s}</div>)}
                        {!p.require_pod_bound && <div className="hint-text">{t("attest.pod_not_required")}</div>}
                      </td>
                      <td data-label={t("attest.validity_short")}>{p.validity_minutes} min</td>
                      <td data-label={t("attest.roles")}>{p.roles}</td>
                      <td>
                        <div className="ag-row-actions">
                          <button className="btn btn-sm" onClick={() => setSetupFor(setupFor === p.id ? null : p.id)}>{t("attest.setup")}</button>
                          {isAdmin && (
                            <>
                              <button className="btn btn-sm" onClick={() => { setTestFor(testFor === p.id ? null : p.id); setTestResult(null); }}>{t("attest.test")}</button>
                              <button className="btn btn-sm" disabled={busy} onClick={() => edit(p)}>{t("attest.edit")}</button>
                              <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => remove(p)}>{t("attest.delete")}</button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                    {setupFor === p.id && (
                      <tr className="ag-form-row">
                        <td colSpan={5}>
                          <div className="ag-stack">
                            <div>
                              <div className="ag-label">{t("attest.setup_pod")}</div>
                              <pre className="ag-code" style={{ whiteSpace: "pre", overflowX: "auto" }}>{podSpecSnippet(p.audience)}</pre>
                            </div>
                            <div>
                              <div className="ag-label">{t("attest.setup_agent")}</div>
                              <code className="ag-code">{attestCommand(p.validity_minutes)}</code>
                              <p className="hint-text ag-small">{t("attest.setup_agent_hint")}</p>
                            </div>
                            <p className="hint-text ag-small">{t("attest.setup_roles")} <Link href="/teams">{t("teams.title")}</Link></p>
                          </div>
                        </td>
                      </tr>
                    )}
                    {testFor === p.id && (
                      <tr className="ag-form-row">
                        <td colSpan={5}>
                          <div className="ag-stack">
                            <div className="field">
                              <label htmlFor={`tok-${p.id}`}>{t("attest.test_token")}</label>
                              <textarea id={`tok-${p.id}`} className="mono ag-wrap" rows={4} style={{ fontSize: 11 }} value={testToken}
                                onChange={(e) => setTestToken(e.target.value)} placeholder="eyJhbGciOi…" />
                              <p className="hint-text">{t("attest.test_hint")}</p>
                            </div>
                            <div><button className="btn btn-sm btn-primary" disabled={!testToken.trim()} onClick={() => runTest(p.id)}>{t("attest.test_run")}</button></div>
                            {testResult && (testResult.ok ? (
                              <p className="ag-small"><span className="pill pill-low">{t("attest.passes")}</span>{" "}
                                {testResult.identity?.namespace}/{testResult.identity?.service_account}
                                {testResult.identity?.pod ? ` · pod ${testResult.identity.pod}` : ""}
                                {testResult.identity?.node ? ` · node ${testResult.identity.node}` : ""}</p>
                            ) : (
                              <p className="ag-small"><span className="pill pill-critical">{t("attest.fails")}</span>{" "}
                                {reasonText(testResult.reason ?? null, testResult.detail)}
                                {testResult.issuer_in_token && testResult.issuer_in_token !== p.issuer
                                  ? ` · ${t("attest.issuer_in_token", { iss: testResult.issuer_in_token })}` : ""}</p>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* ---------------- attempts ---------------- */}
        <section className="panel ag-section">
          <div className="panel-header"><h2>{t("attest.attempts")}</h2></div>
          <div className="ag-table-wrap">
            <table className="table-cards">
              <thead>
                <tr>
                  <th>{t("attest.when")}</th>
                  <th>{t("attest.agent")}</th>
                  <th>{t("attest.result")}</th>
                  <th>{t("attest.workload")}</th>
                  <th>{t("attest.valid_until")}</th>
                </tr>
              </thead>
              <tbody>
                {records.length === 0 && (
                  <tr className="empty-row"><td colSpan={5} className="hint-text" style={{ padding: 20 }}>{t("attest.no_attempts")}</td></tr>
                )}
                {records.map((r) => (
                  <tr key={r.id}>
                    <td data-label={t("attest.when")} className="ag-period">{fmt(r.created_at)}</td>
                    <td data-label={t("attest.agent")}>
                      <Link href={`/agents/${r.agent_id}`}>{r.agent_name ?? `#${r.agent_id}`}</Link>
                      {r.policy && <div className="hint-text" style={{ fontSize: 11 }}>{r.policy}</div>}
                    </td>
                    <td data-label={t("attest.result")}>
                      <span className={`pill ${r.ok ? "pill-low" : "pill-critical"}`}>{r.ok ? t("attest.passed") : t("attest.failed_pill")}</span>
                      {!r.ok && <div className="hint-text" style={{ fontSize: 12 }}>{reasonText(r.reason, r.detail)}</div>}
                    </td>
                    <td data-label={t("attest.workload")} className="mono" style={{ fontSize: 12 }}>
                      {r.identity?.namespace ? `${r.identity.namespace}/${r.identity.service_account}` : r.identity?.workload ?? "—"}
                      {r.identity?.pod && <div className="hint-text">pod {r.identity.pod}</div>}
                    </td>
                    <td data-label={t("attest.valid_until")} className="ag-period">{r.ok ? fmt(r.valid_until) : "—"}</td>
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
