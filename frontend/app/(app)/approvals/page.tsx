"use client";

// The approvals inbox: agent actions held for a human (reviewers: admins and
// approvers). /agent-approvals redirects here (next.config.ts).

import React from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { AgentActionApprovals } from "@/components/approvals/AgentActionApprovals";
import { useAuth } from "@/lib/auth";

export default function ApprovalsPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const reviewer = user?.role === "admin" || user?.role === "approver";

  return (
    <>
      <PageHeader title={t("approvals.title_all")} />
      <div className="content">
        {reviewer ? (
          <AgentActionApprovals />
        ) : (
          <p className="hint-text">{t("approvals.reviewers_only", "Agent actions are approved by admins and approvers.")}</p>
        )}
      </div>
    </>
  );
}
