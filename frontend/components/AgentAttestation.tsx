"use client";

// Where the agent proved it runs (workload attestation): what its role
// requires, the attestation that counts now, or why the agent is refused.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { agentAttestation, attestCommand, type AgentAttestationStatus } from "@/lib/attestation_api";

export function AgentAttestation({ agentId, rev }: { agentId: number; rev?: unknown }) {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<AgentAttestationStatus | null>(null);

  useEffect(() => {
    agentAttestation(agentId).then(setSt).catch(() => setSt(null));
  }, [agentId, rev]);

  if (!st || (!st.required && !st.last)) return null;
  const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString(i18n.language) : "—");
  const cur = st.current;
  const last = st.last;

  return (
    <div>
      <div className="ag-label">{t("attest.agent_title")}</div>
      {st.required && st.policy && (
        <div className="hint-text ag-small" style={{ marginBottom: 6 }}>
          {t("attest.required_by_role")} <Link href="/attestation">{st.policy.name}</Link> · aud{" "}
          <code className="mono">{st.policy.audience}</code>
        </div>
      )}
      {cur ? (
        <div className="ag-small">
          <span className="pill pill-low">{t("attest.passed")}</span>{" "}
          <span className="mono">{cur.identity?.namespace}/{cur.identity?.service_account}</span>
          {cur.identity?.pod && <span className="hint-text"> · pod {cur.identity.pod}</span>}
          {cur.identity?.node && <span className="hint-text"> · node {cur.identity.node}</span>}
          <div className="hint-text">{t("attest.valid_until")}: {fmt(cur.valid_until)}</div>
        </div>
      ) : st.refusal ? (
        <div className="ag-revoked">
          <span className="pill pill-critical">{t("attest.blocked")}</span> {t(`errors.${st.refusal}`, st.refusal)}
          {last && !last.ok && (
            <div className="hint-text">
              {t("attest.last_attempt", { time: fmt(last.created_at) })}: {t(`errors.${last.reason}`, last.reason ?? "")}
              {last.detail ? ` — ${last.detail}` : ""}
            </div>
          )}
          {st.policy && <div className="hint-text" style={{ marginTop: 4 }}><code className="mono">{attestCommand(st.policy.validity_minutes)}</code></div>}
        </div>
      ) : last ? (
        <div className="hint-text ag-small">
          {t("attest.last_attempt", { time: fmt(last.created_at) })}: {last.ok ? t("attest.passed") : t(`errors.${last.reason}`, last.reason ?? "")}
        </div>
      ) : null}
    </div>
  );
}
