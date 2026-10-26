"use client";

import React, { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { getChain, listAgentActions, listAgents } from "@/lib/agent_api";
import type { DelegationChainDetail, DelegationHopT, AgentActionT, Agent } from "@/lib/agent_types";

type TreeNode = { key: string; agentId: number; hop?: DelegationHopT; task?: string | null; children: TreeNode[] };

// The chain as a tree: an agent can hand work to several agents (siblings),
// and each of them on. A hop hangs under the latest earlier hop that brought
// work to its delegating agent - the root agent's own task when there is none.
function buildTree(chain: DelegationChainDetail): TreeNode {
  const root: TreeNode = { key: "root", agentId: chain.root_agent_id, task: chain.root_task, children: [] };
  const hops = [...chain.hops].sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id - b.id);
  const latestInto: Record<number, TreeNode> = { [chain.root_agent_id]: root };
  for (const hop of hops) {
    const node: TreeNode = { key: `hop-${hop.id}`, agentId: hop.to_agent_id, hop, task: hop.task_description, children: [] };
    (latestInto[hop.from_agent_id] || root).children.push(node);
    latestInto[hop.to_agent_id] = node;
  }
  return root;
}

const VERDICT_ICON: Record<string, string> = { denied: "❌", pending_approval: "⏳" };

function expiryBadge(iso: string | null | undefined, expiredLabel: string, expiringLabel: string) {
  if (!iso) return null;
  const exp = new Date(iso).getTime();
  const mins = (exp - Date.now()) / 60000;
  let color = "#64748b";
  let prefix = "";
  if (mins < 0) { color = "#ef4444"; prefix = expiredLabel + " · "; }
  else if (mins < 5) { color = "#f59e0b"; prefix = expiringLabel + " · "; }
  return (
    <div style={{ fontSize: 11, color, marginTop: 3 }}>
      ⏱ {prefix}{new Date(iso).toLocaleString()}
    </div>
  );
}

export default function ChainDetailPage() {
  const params = useParams<{ id: string }>();
  const chainId = Number(params.id);
  const { t, i18n } = useTranslation();

  const [chain, setChain] = useState<DelegationChainDetail | null>(null);
  const [actions, setActions] = useState<AgentActionT[]>([]);
  const [agentNames, setAgentNames] = useState<Record<number, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getChain(chainId), listAgentActions({ chain_id: chainId }), listAgents()])
      .then(([c, acts, agents]) => {
        setChain(c);
        setActions(acts);
        const names: Record<number, string> = {};
        (agents as Agent[]).forEach((a) => (names[a.id] = a.name));
        setAgentNames(names);
      })
      .finally(() => setLoading(false));
  }, [chainId]);

  const nameOf = (id: number) => agentNames[id] || `agent#${id}`;

  if (loading) return <div className="content"><p className="hint-text">{t("common.loading")}</p></div>;
  if (!chain) return <div className="content"><p className="hint-text">{t("chains.not_found")}</p></div>;

  // actions grouped by agent, to annotate each node with what it did
  const actionsByAgent: Record<number, AgentActionT[]> = {};
  for (const a of actions) {
    (actionsByAgent[a.agent_id] = actionsByAgent[a.agent_id] || []).push(a);
  }

  const tree = buildTree(chain);
  const shownActions = new Set<number>();   // an agent reached twice lists its actions once

  const renderNode = (node: TreeNode): React.ReactNode => {
    const acts = shownActions.has(node.agentId) ? [] : actionsByAgent[node.agentId] || [];
    shownActions.add(node.agentId);
    const denied = acts.filter((a) => a.policy_check_result === "denied");
    return (
      <div key={node.key}>
        {node.hop && (
          <div style={{ color: "var(--text-muted,#64748b)", fontSize: 12, margin: "8px 0 4px" }}>
            ↳ <span className="mono">delegate: {(node.hop.delegated_capabilities || []).join(", ") || "—"}</span>
            {node.hop.delegated_tools && (
              <span className="mono"> · tools: {node.hop.delegated_tools.join(", ") || "—"}</span>
            )}
            {!node.hop.verified && <span style={{ color: "var(--risk-critical,#c1352f)" }}> · {t("chains.unverified")}</span>}
          </div>
        )}
        <div
          style={{
            border: "1px solid var(--border,#e5e7eb)",
            borderRadius: 8,
            padding: "10px 14px",
            background: "var(--bg-panel,#fff)",
            display: "inline-block",
            minWidth: 240,
            maxWidth: "100%",
          }}
        >
          <div style={{ fontWeight: 600 }}>🤖 {nameOf(node.agentId)}</div>
          {node.task && <div className="hint-text" style={{ fontSize: 12 }}>{node.task}</div>}
          {expiryBadge(node.hop?.expires_at, t("chains.expired", "expired") as string, t("chains.expiring", "expiring") as string)}
          {acts.map((a) => (
            <div key={a.id} style={{ fontSize: 12, marginTop: 4 }}>
              {VERDICT_ICON[a.policy_check_result || ""] || "✅"}{" "}
              <span className="mono">{a.tool_name}</span>
              {a.policy_check_result === "denied" && a.reason && (
                <span style={{ color: "var(--risk-critical,#c1352f)" }}> — {a.reason}</span>
              )}
            </div>
          ))}
          {denied.length > 0 && (
            <div style={{ fontSize: 11, color: "var(--risk-critical,#c1352f)", marginTop: 4 }}>
              {t("chains.blocked_note")}
            </div>
          )}
        </div>
        {node.children.length > 0 && (
          <div style={{ marginLeft: 18, paddingLeft: 16, borderLeft: "1px dashed var(--border,#cbd5e1)" }}>
            {node.children.map(renderNode)}
          </div>
        )}
      </div>
    );
  };

  return (
    <>
      <PageHeader title={`${t("chains.chain")} #${chain.id}`} />
      <div className="content">
        <Link href="/agent-chains" className="btn btn-sm" style={{ marginBottom: 16 }}>
          ← {t("chains.back")}
        </Link>

        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body" style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
            <div><div className="hint-text">{t("chains.col_status")}</div><strong>{t(`chains.status_${chain.status}`, chain.status)}</strong></div>
            <div><div className="hint-text">{t("chains.col_hops")}</div><strong>{chain.total_hops}</strong></div>
            <div><div className="hint-text">{t("chains.col_depth")}</div><strong>{chain.max_depth_reached}</strong></div>
            <div><div className="hint-text">{t("chains.col_task")}</div><strong>{chain.root_task || "—"}</strong></div>
          </div>
        </div>

        {chain.status === "tripped" && (
          <div className="panel" style={{ marginBottom: 20, borderColor: "#f59e0b" }}>
            <div className="panel-body" style={{ color: "#d97706" }}>
              ⚡ {t("chains.tripped_banner")}{" "}
              <Link href="/agent-breaker">{t("chains.open_breaker")}</Link>
            </div>
          </div>
        )}

        {/* Delegation graph: a tree - one agent may delegate to several */}
        <h2 style={{ fontSize: 15, marginBottom: 12 }}>{t("chains.graph_title")}</h2>
        <div className="panel" style={{ marginBottom: 20 }}>
          <div className="panel-body">
            <div style={{ overflowX: "auto" }}>{renderNode(tree)}</div>
          </div>
        </div>

        {/* Action timeline */}
        <h2 style={{ fontSize: 15, marginBottom: 12 }}>{t("chains.timeline_title")}</h2>
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>{t("chains.tl_time")}</th>
                <th>{t("chains.tl_agent")}</th>
                <th>{t("chains.tl_tool")}</th>
                <th>{t("chains.tl_result")}</th>
                <th>{t("chains.tl_reason")}</th>
              </tr>
            </thead>
            <tbody>
              {actions.length === 0 && (
                <tr className="empty-row"><td colSpan={5}>{t("chains.no_actions")}</td></tr>
              )}
              {actions.map((a) => (
                <tr key={a.id}>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(a.created_at).toLocaleTimeString(i18n.language)}</td>
                  <td>{nameOf(a.agent_id)}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{a.tool_name}</td>
                  <td>
                    <span className={`pill ${a.policy_check_result === "denied" ? "pill-critical" : a.policy_check_result === "pending_approval" ? "pill-medium" : "pill-low"}`}>
                      {a.policy_check_result}
                    </span>
                  </td>
                  <td className="hint-text" style={{ fontSize: 12 }}>{a.reason || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
