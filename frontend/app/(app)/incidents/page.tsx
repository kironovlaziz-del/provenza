"use client";

// One place for incidents: the platform's (reported or raised by Shadow AI
// and the Prompt Firewall) and every kind the agent layer raises.
// /agent-incidents redirects to the second tab (next.config.ts).

import React, { Suspense, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Tabs, useTab } from "@/components/Tabs";
import { AgentIncidents } from "@/components/incidents/AgentIncidents";
import { PlatformIncidents } from "@/components/incidents/PlatformIncidents";
import { getAgentIncidentTypes } from "@/lib/agent_api";

function IncidentsInner() {
  const { t } = useTranslation();
  const [tab, setTab] = useTab(["platform", "agents"]);
  const [agentOpen, setAgentOpen] = useState(0);

  useEffect(() => {
    getAgentIncidentTypes()
      .then((types) => setAgentOpen(types.reduce((n, x) => n + x.unresolved, 0)))
      .catch(() => setAgentOpen(0));
  }, [tab]);

  return (
    <>
      <PageHeader title={t("incidents.title_all")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("incidents.subtitle")}</p>
        <Tabs
          current={tab}
          onChange={setTab}
          tabs={[
            { key: "platform", label: t("incidents.tab_platform") },
            { key: "agents", label: t("incidents.tab_agents"), badge: agentOpen },
          ]}
        />
        {tab === "platform" ? <PlatformIncidents /> : <AgentIncidents />}
      </div>
    </>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense>
      <IncidentsInner />
    </Suspense>
  );
}
