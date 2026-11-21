"use client";

// AI agents -> Connect an agent: the short way to a governed agent, in two
// steps. 1. What it may use: tick the gateways' tools (an approved tool can be
// given; one awaiting approval is shown, not offered). 2. Connect: an
// enrollment token for exactly those rights, and the one command that enrolls
// the agent on the client's machine and connects the client (EnrollPanel ->
// ConnectPanel). Teams, roles, models and a key registered by hand stay on the
// full form (/agents/new).

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { EnrollPanel } from "@/components/EnrollPanel";
import { LoadError } from "@/components/LoadError";
import { PageHeader } from "@/components/PageHeader";
import { listGatewayTools, type GatewayTool } from "@/lib/agent_api";
import { attestCommand, podSpecSnippet } from "@/lib/attestation_api";
import { issueEnrollment, listEnrollments, revokeEnrollment, type EnrollmentT } from "@/lib/enrollment_api";
import { translateApiError } from "@/lib/errors";
import { apiErrorMessage } from "@/lib/inventory_api";

const TTLS = [1, 24, 72, 168];

export default function ConnectAgentPage() {
  const { t } = useTranslation();
  const [tools, setTools] = useState<GatewayTool[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [hybrid, setHybrid] = useState(true);
  const [ttl, setTtl] = useState(24);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<EnrollmentT | null>(null);

  function load() {
    setLoadError(null);
    listGatewayTools()
      .then((list) => setTools([...list].sort((a, b) => a.name.localeCompare(b.name))))
      .catch((e) => setLoadError(apiErrorMessage(e, t("common.load_failed"))));
  }
  useEffect(load, []); // eslint-disable-line react-hooks/exhaustive-deps

  const usable = (tools ?? []).filter((x) => x.usable);
  const waiting = (tools ?? []).filter((x) => !x.usable);

  function toggle(tool: string, on: boolean) {
    setPicked((list) => (on ? [...list, tool] : list.filter((x) => x !== tool)));
  }

  async function next() {
    setBusy(true);
    setError(null);
    try {
      // the rights of the full form's defaults, with only the ticked tools
      setIssued(await issueEnrollment({
        name: name.trim() || undefined,
        agent_type: "custom",
        capabilities: [],
        allowed_tools: picked,
        allowed_models: [],
        max_delegation_depth: 3,
        require_hybrid: hybrid,
        ttl_hours: ttl,
      }));
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      setError(translateApiError(detail, t, t("agents.register_failed")));
    } finally {
      setBusy(false);
    }
  }

  async function startOver() {
    // a token still unused is revoked: it should not stay valid on a page nobody
    // looks at. One the machine already used is left alone (the agent exists).
    if (issued) {
      const now = await listEnrollments().then((l) => l.find((x) => x.id === issued.id), () => undefined);
      if (now?.state === "open") await revokeEnrollment(issued.id).catch(() => undefined);
    }
    setIssued(null);
  }

  const step = issued?.token ? 2 : 1;

  return (
    <>
      <PageHeader title={t("wizard.title")} />
      <div className="content">
        <ol className="wizard-steps" aria-label={t("wizard.steps")}>
          {[1, 2].map((n) => (
            <li key={n} className={n === step ? "on" : n < step ? "done" : ""} aria-current={n === step ? "step" : undefined}>
              <span className="wizard-step-n">{n < step ? "✓" : n}</span>
              {t(`wizard.step${n}`)}
            </li>
          ))}
        </ol>

        {step === 1 && (
          <section className="panel" aria-labelledby="wizard-tools">
            <div className="panel-header"><h2 id="wizard-tools">{t("wizard.tools_title")}</h2></div>
            <div className="panel-body" style={{ display: "grid", gap: 16 }}>
              <p className="hint-text" style={{ margin: 0 }}>{t("wizard.tools_hint")}</p>
              <LoadError message={loadError} onRetry={load} />
              {tools === null && !loadError && <p className="hint-text">{t("common.loading")}</p>}
              {tools !== null && usable.length === 0 && (
                <p className="hint-text" style={{ margin: 0 }}>
                  {t("wizard.no_tools")} <Link href="/gateway?tab=mcp">{t("wizard.add_tools")} →</Link>
                </p>
              )}
              {usable.length > 0 && (
                <fieldset className="wizard-tools">
                  <legend className="sr-only">{t("wizard.tools_title")}</legend>
                  {usable.map((x) => (
                    <label key={x.name} className="wizard-tool">
                      <input type="checkbox" checked={picked.includes(x.name)} onChange={(e) => toggle(x.name, e.target.checked)} />
                      <span className="mono">{x.name}</span>
                      <span className="pill pill-neutral">{x.kind.toUpperCase()}</span>
                    </label>
                  ))}
                </fieldset>
              )}
              {waiting.length > 0 && (
                <p className="hint-text" style={{ margin: 0 }}>
                  {t("wizard.awaiting", { count: waiting.length, names: waiting.map((x) => x.name).join(", ") })}{" "}
                  <Link href="/gateway?tab=mcp">{t("wizard.review_tools")} →</Link>
                </p>
              )}

              <div className="field" style={{ margin: 0, maxWidth: 420 }}>
                <label htmlFor="wizard-name">{t("wizard.name")}</label>
                <input id="wizard-name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)}
                  placeholder="claude-code@laptop" />
                <p className="hint-text">{t("wizard.name_hint")}</p>
              </div>

              <details className="wizard-more">
                <summary>{t("wizard.more")}</summary>
                <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
                  <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontWeight: 400 }}>
                    <input type="checkbox" checked={hybrid} onChange={(e) => setHybrid(e.target.checked)} style={{ width: "auto", marginTop: 3 }} />
                    <span>
                      {t("agents.hybrid")}
                      <span className="hint-text" style={{ display: "block", fontSize: 12 }}>{t("agents.hybrid_hint")}</span>
                    </span>
                  </label>
                  <div className="field" style={{ margin: 0, maxWidth: 240 }}>
                    <label htmlFor="wizard-ttl">{t("enroll.ttl")}</label>
                    <select id="wizard-ttl" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} style={{ width: "auto" }}>
                      {TTLS.map((h) => <option key={h} value={h}>{t("enroll.ttl_hours", { count: h })}</option>)}
                    </select>
                  </div>
                  <p className="hint-text" style={{ margin: 0 }}>
                    {t("wizard.full_form")} <Link href="/agents/new">{t("wizard.full_form_link")} →</Link>
                  </p>
                </div>
              </details>

              {error && <p className="error-text" style={{ margin: 0 }}>{error}</p>}
              <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                <button type="button" className="btn btn-primary" disabled={busy || tools === null} onClick={next}>
                  {busy ? t("wizard.working") : t("wizard.next")}
                </button>
                {tools !== null && picked.length === 0 && (
                  <span className="hint-text">{t("wizard.none_picked")}</span>
                )}
              </div>
            </div>
          </section>
        )}

        {step === 2 && issued?.token && (
          <section className="panel" aria-labelledby="wizard-connect">
            <div className="panel-header">
              <h2 id="wizard-connect">{t("wizard.step2")}</h2>
              <button type="button" className="btn btn-sm" onClick={startOver}>{t("wizard.start_over")}</button>
            </div>
            <div className="panel-body" style={{ display: "grid", gap: 14 }}>
              <p className="hint-text" style={{ margin: 0 }}>
                {issued.allowed_tools.length > 0
                  ? t("wizard.rights", { tools: issued.allowed_tools.join(", ") })
                  : t("wizard.rights_none")}{" "}
                {t("wizard.expires", { time: new Date(issued.expires_at).toLocaleString() })}
              </p>
              <EnrollPanel token={issued.token} hybrid={issued.require_hybrid} enrollmentId={issued.id} />
              {issued.attestation?.required && (
                <div className="field" style={{ margin: 0 }}>
                  <label>{t("attest.enroll_title")}</label>
                  <p className="hint-text">{t("attest.enroll_hint", { policy: issued.attestation.policy ?? "—", audience: issued.attestation.audience ?? "—" })}</p>
                  {issued.attestation.audience && (
                    <pre className="mono" style={{ fontSize: 11, whiteSpace: "pre", overflowX: "auto" }}>{podSpecSnippet(issued.attestation.audience)}</pre>
                  )}
                  <code className="mono" style={{ fontSize: 12 }}>{attestCommand(issued.attestation.validity_minutes ?? 60)}</code>
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </>
  );
}
