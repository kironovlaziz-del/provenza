"use client";

// Gateways: every way agents reach the outside world through Provenza -
// AI providers (LLM), tools (MCP), other agents (A2A) and external APIs
// (egress proxy). Each enforces the agent's rights and records its actions.

import React, { Suspense } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Tabs, useTab } from "@/components/Tabs";
import { A2aPeers } from "@/components/gateways/A2aPeers";
import { EgressProxy } from "@/components/gateways/EgressProxy";
import { LlmGateway } from "@/components/gateways/LlmGateway";
import { McpServers } from "@/components/gateways/McpServers";

function GatewaysInner() {
  const { t } = useTranslation();
  const [tab, setTab] = useTab(["llm", "mcp", "a2a", "egress"]);
  return (
    <>
      <PageHeader title={t("gw.title")} />
      <div className="content">
        <Tabs
          current={tab}
          onChange={setTab}
          tabs={[
            { key: "llm", label: t("gw.tab_llm") },
            { key: "mcp", label: t("gw.tab_mcp") },
            { key: "a2a", label: t("gw.tab_a2a") },
            { key: "egress", label: t("gw.tab_egress") },
          ]}
        />
        {tab === "llm" && <LlmGateway />}
        {tab === "mcp" && <McpServers />}
        {tab === "a2a" && <A2aPeers />}
        {tab === "egress" && <EgressProxy />}
      </div>
    </>
  );
}

export default function GatewaysPage() {
  return (
    <Suspense>
      <GatewaysInner />
    </Suspense>
  );
}
