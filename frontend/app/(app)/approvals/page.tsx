"use client";

// One approvals inbox: agent actions held for a human (reviewers) and usage
// requests. /agent-approvals redirects to the first tab (next.config.ts).

import React, { Suspense, useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Tabs, useTab } from "@/components/Tabs";
import { AgentActionApprovals } from "@/components/approvals/AgentActionApprovals";
import { RequestApprovals } from "@/components/approvals/RequestApprovals";
import { useAuth } from "@/lib/auth";

function ApprovalsInner() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const reviewer = user?.role === "admin" || user?.role === "approver";
  const keys = reviewer ? ["agents", "requests"] : ["requests"];
  const [tab, setTab] = useTab(keys);
  const [agentPending, setAgentPending] = useState(0);
  const onCount = useCallback((n: number) => setAgentPending(n), []);

  return (
    <>
      <PageHeader title={t("approvals.title_all")} />
      <div className="content">
        {reviewer && (
          <Tabs
            current={tab}
            onChange={setTab}
            tabs={[
              { key: "agents", label: t("approvals.tab_agents"), badge: agentPending },
              { key: "requests", label: t("approvals.tab_requests") },
            ]}
          />
        )}
        {tab === "agents" && reviewer ? <AgentActionApprovals onCount={onCount} /> : <RequestApprovals />}
      </div>
    </>
  );
}

export default function ApprovalsPage() {
  return (
    <Suspense>
      <ApprovalsInner />
    </Suspense>
  );
}
