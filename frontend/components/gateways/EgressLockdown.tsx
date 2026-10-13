"use client";

// Lock agents down: network rules that leave an agent one way out - the
// egress proxy, which also relays its calls to Provenza. Without them every
// control is cooperative. Rendered by the server (app/services/egress_lockdown.py);
// verified by the agents' egress self-check.

import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { errorMessage } from "@/lib/errors";
import { renderLockdown, type LockdownKind, type LockdownT } from "@/lib/agent_identity_api";

const DEFAULTS = {
  proxy_host: "provenza-proxy", proxy_port: 8443, namespace: "agents", proxy_namespace: "provenza-egress",
  agent_label: "provenza/egress=proxied", agent_user: "agent", agent_service: "agent",
};

export function EgressLockdown() {
  const { t } = useTranslation();
  const [kind, setKind] = useState<LockdownKind>("kubernetes");
  const [p, setP] = useState(DEFAULTS);
  const [out, setOut] = useState<LockdownT | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  async function render(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      setOut(await renderLockdown({ kind, ...p }));
    } catch (err) {
      setOut(null);
      setError(errorMessage(err, t, t("gw.failed")));
    }
  }

  async function copy(name: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(name);
    } catch {
      /* the text stays visible to copy by hand */
    }
  }

  const field = (key: keyof typeof DEFAULTS, label: string, type = "text") => (
    <div className="field">
      <label htmlFor={`ld-${key}`}>{label}</label>
      <input id={`ld-${key}`} type={type} value={p[key]}
             onChange={(e) => setP({ ...p, [key]: type === "number" ? Number(e.target.value) : e.target.value })} />
    </div>
  );

  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("gw.lockdown.title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text u-mb-12">{t("gw.lockdown.hint")}</p>
        <Form onSubmit={render}>
          <div className="u-row-tight u-mb-12">
            {(["kubernetes", "docker", "nftables"] as LockdownKind[]).map((k) => (
              <label key={k} className="u-flex u-items-center u-gap-6">
                <input type="radio" name="lockdown-kind" style={{ width: "auto" }} checked={kind === k}
                       onChange={() => { setKind(k); setOut(null); if (k === "nftables" && p.proxy_host === DEFAULTS.proxy_host) setP({ ...p, proxy_host: "127.0.0.1" }); }} />
                {t(`gw.lockdown.kind_${k}`)}
              </label>
            ))}
          </div>
          <div className="form-row">
            {kind === "kubernetes" && (
              <>
                {field("namespace", t("gw.lockdown.namespace"))}
                {field("agent_label", t("gw.lockdown.agent_label"))}
                {field("proxy_namespace", t("gw.lockdown.proxy_namespace"))}
              </>
            )}
            {kind === "docker" && field("agent_service", t("gw.lockdown.agent_service"))}
            {kind === "nftables" && (
              <>
                {field("agent_user", t("gw.lockdown.agent_user"))}
                {field("proxy_host", t("gw.lockdown.proxy_ip"))}
              </>
            )}
            {field("proxy_port", t("gw.lockdown.proxy_port"), "number")}
          </div>
          <button className="btn btn-primary btn-sm" type="submit">{t("gw.lockdown.render")}</button>
        </Form>
        {error && <p className="error-text">{error}</p>}
        {out && (
          <div className="u-mt-16">
            {out.files.map((f) => (
              <div key={f.name} className="field">
                <div className="u-flex u-justify-between u-items-center">
                  <label className="u-mono">{f.name}</label>
                  <button type="button" className="btn btn-sm" onClick={() => copy(f.name, f.content)}>
                    {copied === f.name ? t("agents.copied") : t("agents.copy")}
                  </button>
                </div>
                <pre className="u-mono" style={{ fontSize: 11, whiteSpace: "pre", overflowX: "auto", maxHeight: 360 }}>{f.content}</pre>
              </div>
            ))}
            <div className="field">
              <label>{t("gw.lockdown.agent_env")}</label>
              <pre className="u-mono" style={{ fontSize: 12, whiteSpace: "pre-wrap" }}>
                {Object.entries(out.agent_env).map(([k, v]) => `${k}=${v}`).join("\n")}
              </pre>
            </div>
            <ul className="hint-text">
              {out.notes.map((n) => <li key={n}>{n}</li>)}
            </ul>
            <p className="hint-text"><strong>{t("gw.lockdown.verify")}</strong> {t("gw.lockdown.verify_hint")}</p>
          </div>
        )}
      </div>
    </div>
  );
}
