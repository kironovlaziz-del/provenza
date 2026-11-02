"use client";

// How to install the endpoint agent on a workstation: one command per
// system, copied into a terminal. The command asks for the key itself.

import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { AGENT_OSES, agentInstallCommand, controlPlaneOrigin, type AgentOS } from "@/lib/agent_install";

export function AgentInstall() {
  const { t } = useTranslation();
  const [os, setOS] = useState<AgentOS>("windows");
  const [copied, setCopied] = useState(false);
  const cmd = agentInstallCommand(os, controlPlaneOrigin());

  async function copy() {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
    } catch {
      // no clipboard (insecure context): the command is selectable
    }
  }

  return (
    <div>
      <div className="tabs" role="tablist">
        {AGENT_OSES.map((o) => (
          <button
            key={o}
            type="button"
            role="tab"
            aria-selected={o === os}
            className={`tab${o === os ? " tab-active" : ""}`}
            onClick={() => { setOS(o); setCopied(false); }}
          >
            {t(`ingestion_sources.agent_os_${o}`)}
          </button>
        ))}
      </div>
      <p className="hint-text" style={{ marginTop: 0 }}>{t(`ingestion_sources.agent_where_${os}`)}</p>
      <div className="form-row" style={{ alignItems: "flex-start" }}>
        <pre className="mono" style={{ flex: 1, margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{cmd}</pre>
        <button type="button" className="btn btn-sm" onClick={copy}>
          {copied ? t("ingestion_sources.copied") : t("ingestion_sources.copy")}
        </button>
      </div>
      <p className="hint-text">{t("ingestion_sources.agent_after")}</p>
    </div>
  );
}
