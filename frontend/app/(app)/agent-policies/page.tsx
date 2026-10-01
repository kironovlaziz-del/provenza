"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { listAgentPolicies, listAgents } from "@/lib/agent_api";
import type { AgentPolicyT, Agent } from "@/lib/agent_types";

export default function AgentPoliciesPage() {
  const { t } = useTranslation();
  const [policies, setPolicies] = useState<AgentPolicyT[]>([]);
  const [agentNames, setAgentNames] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([listAgentPolicies(), listAgents()])
      .then(([pols, agents]) => {
        setPolicies(pols);
        const names: Record<number, string> = {};
        (agents as Agent[]).forEach((a) => (names[a.id] = a.name));
        setAgentNames(names);
      })
      .finally(() => setLoading(false));
  }, []);

  function summarize(rules: Record<string, unknown> | null | undefined): string {
    if (!rules) return "—";
    const parts: string[] = [];
    if (Array.isArray(rules.deny_tools)) parts.push(`deny ${(rules.deny_tools as string[]).length}`);
    if (Array.isArray(rules.allow_only_tools)) parts.push(`allowlist ${(rules.allow_only_tools as string[]).length}`);
    if (Array.isArray(rules.require_approval_tools)) parts.push(`approval ${(rules.require_approval_tools as string[]).length}`);
    if (Array.isArray(rules.argument_rules)) parts.push(`args ${(rules.argument_rules as unknown[]).length}`);
    if (Array.isArray(rules.deny_action_types)) parts.push(`deny-types ${(rules.deny_action_types as string[]).length}`);
    return parts.join(" · ") || "—";
  }

  return (
    <>
      <PageHeader
        title={t("agent_policies.title")}
        actions={
          <Link href="/agent-policies/new" className="btn btn-primary btn-sm">{t("agent_policies.new")}</Link>
        }
      />
      <div className="content">
        <p className="hint-text u-mb-16">{t("agent_policies.hint")}</p>
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>{t("agent_policies.col_name")}</th>
                <th>{t("agent_policies.col_scope")}</th>
                <th>{t("agent_policies.col_rules")}</th>
                <th>{t("agent_policies.col_priority")}</th>
                <th>{t("agent_policies.col_enabled")}</th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr className="empty-row"><td colSpan={5}>{t("common.loading")}</td></tr>}
              {!loading && policies.length === 0 && (
                <tr className="empty-row"><td colSpan={5}>{t("agent_policies.empty")}</td></tr>
              )}
              {policies.map((p) => (
                <tr key={p.id}>
                  <td style={{ fontWeight: 600 }}>{p.name}</td>
                  <td>{p.agent_id ? (agentNames[p.agent_id] || `agent#${p.agent_id}`) : t("agent_policies.all_agents")}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{summarize(p.rules)}</td>
                  <td>{p.priority}</td>
                  <td>{p.enabled ? "✅" : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
