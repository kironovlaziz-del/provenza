"use client";

import React from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { DelegationGraph } from "../agent-chains/DelegationGraph";

export default function AgentMapPage() {
  const { t } = useTranslation();
  return (
    <>
      <PageHeader title={t("agent_map.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("agent_map.hint")}</p>
        <div className="panel">
          <div className="panel-body" style={{ padding: 0 }}>
            <DelegationGraph height={560} />
          </div>
        </div>
        <div style={{ display: "flex", gap: 18, marginTop: 14, flexWrap: "wrap", fontSize: 12 }}>
          <span><span style={{ color: "#2451d9" }}>●</span> {t("agent_map.legend_active")}</span>
          <span><span style={{ color: "#dc2626" }}>●</span> {t("agent_map.legend_violation")}</span>
          <span><span style={{ color: "#94a3b8" }}>●</span> {t("agent_map.legend_suspended")}</span>
          <span><span style={{ color: "#2f9e63" }}>—</span> {t("agent_map.legend_verified")}</span>
          <span><span style={{ color: "#dc2626" }}>┈</span> {t("agent_map.legend_violated_edge")}</span>
          <span><span style={{ color: "#d97706" }}>┈</span> ⚡ {t("agent_map.legend_tripped")}</span>
        </div>
      </div>
    </>
  );
}
