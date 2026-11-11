"use client";

// Agents -> Connect: one command for the machine where an AI client runs.
// It downloads provenza-proxy from this server, enrolls the agent with the
// one-time token (its keys are made there and never leave it) and connects
// the client through agent mode (backend app/api/connect_script.py).
import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { listEnrollments, type EnrollmentT } from "@/lib/enrollment_api";

const CLIENTS = ["gemini-cli", "claude-code", "cursor", "openai"] as const;
const SYSTEMS = ["linux", "windows"] as const;
export type ConnectSystem = (typeof SYSTEMS)[number];
const POLL_MS = 3000;
const POLL_FOR_MS = 60 * 60 * 1000;

/** The control plane's origin: the configured one, else the page's. */
function origin(): string {
  const envURL = process.env.NEXT_PUBLIC_API_URL || "";
  return envURL.replace(/\/api\/v1\/?$/, "") || (typeof window !== "undefined" ? window.location.origin : "");
}

export function connectCommand(token: string, client: string, system: ConnectSystem = "linux"): string {
  if (system === "windows") {
    // PowerShell as the client's user; a script block, so no execution-policy change
    const script = `${origin()}/api/v1/agent-enrollment/connect.ps1`;
    return `& ([scriptblock]::Create((irm "${script}"))) -Client ${client} -Token ${token}`;
  }
  const script = `${origin()}/api/v1/agent-enrollment/connect.sh`;
  return `f=$(mktemp) && curl -fsSL ${script} -o "$f" && sh "$f" ${client} ${token}`;
}

export function ConnectPanel({ token, enrollmentId, onConnected }:
  { token: string; enrollmentId: number; onConnected?: () => void }) {
  const { t } = useTranslation();
  const [client, setClient] = useState<string>("gemini-cli");
  const [system, setSystem] = useState<ConnectSystem>("linux");
  const [copied, setCopied] = useState(false);
  const [used, setUsed] = useState<EnrollmentT | null>(null);
  const cmd = connectCommand(token, client, system);

  // the token is spent when the machine enrolls: then the agent is connected
  useEffect(() => {
    if (used) return;
    const until = Date.now() + POLL_FOR_MS;
    const timer = setInterval(async () => {
      if (Date.now() > until) return clearInterval(timer);
      try {
        const e = (await listEnrollments()).find((x) => x.id === enrollmentId);
        if (e?.state === "used") {
          setUsed(e);
          onConnected?.();   // the token is spent: the other ways to use it are gone
          clearInterval(timer);
        }
      } catch {
        /* keep polling: a passing network error is not a failure */
      }
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [enrollmentId, used]);

  return (
    <div className="field" style={{ margin: 0 }}>
      <label>{t("connect.title")}</label>
      {used ? (
        <span>
          <span className="pill pill-low">✓ {t("connect.done", { id: used.agent_id ?? "?" })}</span>
          {used.agent_id != null && <> <Link href={`/agents/${used.agent_id}`}>{t("connect.open_agent")} →</Link></>}
        </span>
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          <p className="hint-text" style={{ margin: 0 }}>{t("connect.hint")}</p>
          <div className="form-row" style={{ alignItems: "flex-end" }}>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="connect-client">{t("connect.client")}</label>
              <select id="connect-client" value={client} onChange={(e) => { setClient(e.target.value); setCopied(false); }}>
                {CLIENTS.map((c) => <option key={c} value={c}>{t(`connect.clients.${c}`)}</option>)}
              </select>
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label htmlFor="connect-system">{t("connect.system")}</label>
              <select id="connect-system" value={system} onChange={(e) => { setSystem(e.target.value as ConnectSystem); setCopied(false); }}>
                {SYSTEMS.map((x) => <option key={x} value={x}>{t(`connect.systems.${x}`)}</option>)}
              </select>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <code className="mono u-break" style={{ flex: 1, fontSize: 12 }}>{cmd}</code>
            <button type="button" className="btn btn-sm btn-primary"
                    onClick={() => navigator.clipboard?.writeText(cmd).then(() => setCopied(true), () => undefined)}>
              {copied ? t("agents.copied") : t("agents.copy")}
            </button>
          </div>
          <p className="hint-text" style={{ margin: 0 }}>{t("connect.waiting")}</p>
          <p className="hint-text" style={{ margin: 0 }}>{t(system === "windows" ? "connect.where_windows" : "connect.where")}</p>
        </div>
      )}
    </div>
  );
}
