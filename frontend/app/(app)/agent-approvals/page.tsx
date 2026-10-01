"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import {
  approvalError,
  approveReviewed,
  denyReviewed,
  getReviewPacket,
  listPendingApprovals,
  type PendingApproval,
  type ReviewPacket,
} from "@/lib/approvals_api";

function ExpiresIn({ iso }: { iso: string }) {
  const { t } = useTranslation();
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return <>{t("agent_approvals.expired", "expired")}</>;
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  return <>{t("agent_approvals.expires_in", { h, m, defaultValue: `expires in ${h}h ${m}m` })}</>;
}

function Fact({ label, children, bad }: { label: string; children: React.ReactNode; bad?: boolean }) {
  return (
    <div style={{ display: "flex", gap: 8, fontSize: 13, marginBottom: 4 }}>
      <span className="hint-text" style={{ minWidth: 150 }}>{label}</span>
      <span style={{ color: bad ? "#ef4444" : undefined, fontWeight: bad ? 600 : undefined }}>{children}</span>
    </div>
  );
}

function Review({ id, onDone }: { id: number; onDone: () => void }) {
  const { t } = useTranslation();
  const [p, setP] = useState<ReviewPacket | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getReviewPacket(id)
      .then(setP)
      .catch((e) => setError(approvalError(e, t("agent_approvals.load_failed", "Could not load the review."))));
  }, [id, t]);

  async function decide(kind: "approve" | "deny") {
    if (!p) return;
    setBusy(true);
    setError(null);
    try {
      if (kind === "approve") {
        await approveReviewed(id, p.verified.input_sha256, confirmation);
      } else {
        const reason = window.prompt(t("agent_approvals.deny_prompt") as string);
        if (reason === null) {
          setBusy(false);
          return;
        }
        await denyReviewed(id, reason);
      }
      onDone();
    } catch (e) {
      setError(approvalError(e, t("agent_approvals.failed", "Could not save the decision.")));
      setBusy(false);
    }
  }

  if (!p) return <div className="hint-text" style={{ padding: 12 }}>{error ?? t("common.loading", "Loading…")}</div>;

  const v = p.verified;
  const rv = p.reviewer;
  const sig = v.signature;
  const sigOk = sig.present && sig.valid && sig.covers_these_arguments;

  return (
    <div style={{ padding: "12px 4px" }}>
      {/* ---- verified by the server ---- */}
      <div style={{ border: "1px solid #22c55e55", borderRadius: 8, padding: 12, marginBottom: 12 }}>
        <div style={{ fontWeight: 700, fontSize: 13, color: "#16a34a", marginBottom: 8 }}>
          ✓ {t("agent_approvals.verified_title", "Verified by Provenza")}
        </div>
        <div className="hint-text" style={{ fontSize: 12, marginBottom: 6 }}>
          {t("agent_approvals.exact_args", "Exact arguments that will be approved")}
        </div>
        <pre
          className="mono"
          style={{ fontSize: 12, background: "rgba(100,116,139,0.1)", padding: 10, borderRadius: 6, overflowX: "auto", margin: "0 0 8px" }}
        >
          {JSON.stringify(p.action.input, null, 2)}
        </pre>
        <Fact label={t("agent_approvals.tool", "Tool")}><span className="mono">{p.action.tool_name}</span></Fact>
        <Fact label="SHA-256"><span className="mono" style={{ fontSize: 11 }}>{v.input_sha256}</span></Fact>
        <Fact label={t("agent_approvals.signature", "Agent signature")} bad={!sigOk}>
          {!sig.present
            ? t("agent_approvals.sig_missing", "not signed")
            : sigOk
              ? t("agent_approvals.sig_ok", "valid, covers exactly these arguments")
              : t("agent_approvals.sig_bad", "does NOT match these arguments")}
        </Fact>
        <Fact label={t("agent_approvals.agent", "Agent")}>
          {v.agent.name} ({v.agent.status}){v.agent.owner_team ? ` · ${v.agent.owner_team}` : ""}
        </Fact>
        <Fact label={t("agent_approvals.policy", "Why approval is needed")}>
          {v.policy.name ?? "—"}
          {p.action.reason ? <span className="hint-text"> — {p.action.reason}</span> : null}
        </Fact>
        {v.chain && (
          <Fact label={t("agent_approvals.chain", "Delegation chain")}>
            <Link href={`/agent-chains/${v.chain.id}`}>#{v.chain.id}</Link> · {t("agent_approvals.depth", "depth")} {v.chain.depth}
            {v.chain.delegated_by_agent_id ? ` · ${t("agent_approvals.delegated_by", "delegated by agent")} #${v.chain.delegated_by_agent_id}` : ""}
          </Fact>
        )}
        <Fact
          label={t("agent_approvals.risk_tier", "System risk tier")}
          bad={v.inventory.risk_tier === "high" || v.inventory.risk_tier === "unacceptable"}
        >
          {v.inventory.risk_tier ?? "—"}
          {v.inventory.risk_tier && !v.inventory.risk_confirmed ? ` (${t("agent_approvals.unconfirmed", "not confirmed")})` : ""}
        </Fact>
        <Fact label={t("agent_approvals.recent", "Last 7 days")} bad={(v.recent_7d.denial_rate ?? 0) > 0.1}>
          {v.recent_7d.actions} {t("agent_approvals.actions", "actions")}, {v.recent_7d.denied} {t("agent_approvals.denied", "denied")}
        </Fact>
      </div>

      {/* ---- what agents claimed ---- */}
      {p.unverified_statements.length > 0 && (
        <div style={{ border: "1px dashed #f59e0b88", borderRadius: 8, padding: 12, marginBottom: 12 }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: "#d97706", marginBottom: 4 }}>
            ⚠ {t("agent_approvals.unverified_title", "Written by agents — not verified")}
          </div>
          <div className="hint-text" style={{ fontSize: 12, marginBottom: 8 }}>
            {t(
              "agent_approvals.unverified_hint",
              "Judge the action by the arguments above, not by this description. Text like this is how an agent (or a prompt injected into it) tries to make a harmful action look routine.",
            )}
          </div>
          {p.unverified_statements.map((s, i) => (
            <div key={i} style={{ fontSize: 13, marginBottom: 4 }}>
              <span className="hint-text">{s.source}:</span> <em>“{s.text}”</em>
            </div>
          ))}
        </div>
      )}

      {/* ---- decision ---- */}
      {error && <div style={{ color: "#ef4444", fontSize: 13, marginBottom: 8 }}>{error}</div>}
      {rv.blocked_reason && <div style={{ color: "#d97706", fontSize: 13, marginBottom: 8 }}>{rv.blocked_reason}</div>}
      {rv.self_approval && (
        <div style={{ color: "#d97706", fontSize: 13, marginBottom: 8 }}>
          {t("agent_approvals.self_approval", "You own this agent and no other reviewer exists — your decision will be recorded as self-approval.")}
        </div>
      )}
      {rv.requires_typed_confirmation && rv.can_decide && (
        <div className="field" style={{ maxWidth: 420 }}>
          <label htmlFor={`confirm-${id}`}>
            {t("agent_approvals.type_to_confirm", { tool: rv.confirmation_text, defaultValue: `Type "${rv.confirmation_text}" to approve` })}
            <span className="hint-text"> ({rv.flags.map((f) => t(`agent_approvals.flag_${f}`, f)).join(", ")})</span>
          </label>
          <input id={`confirm-${id}`} className="mono" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} />
        </div>
      )}
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <button
          className="btn btn-primary btn-sm"
          disabled={busy || !rv.can_decide || (rv.requires_typed_confirmation && confirmation.trim() !== rv.confirmation_text)}
          onClick={() => decide("approve")}
        >
          {t("agent_approvals.approve", "Approve these arguments")}
        </button>
        <button className="btn btn-sm" disabled={busy || p.action.status !== "pending_approval"} onClick={() => decide("deny")}>
          {t("agent_approvals.deny", "Deny")}
        </button>
        <span className="hint-text" style={{ fontSize: 12 }}><ExpiresIn iso={rv.expires_at} /></span>
      </div>
    </div>
  );
}

export default function AgentApprovalsPage() {
  const { t } = useTranslation();
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    listPendingApprovals()
      .then((rows) => {
        setPending(rows);
        setError(null);
      })
      .catch((e) => setError(approvalError(e, t("agent_approvals.load_failed", "Could not load the review."))))
      .finally(() => setLoading(false));
  }, [t]);

  useEffect(refresh, [refresh]);

  return (
    <>
      <PageHeader title={t("agent_approvals.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("agent_approvals.hint")}</p>
        {error && <div style={{ color: "#ef4444", marginBottom: 12 }}>{error}</div>}
        <div className="panel">
          <div className="panel-header"><h2>{t("agent_approvals.pending")} ({pending.length})</h2></div>
          <div className="panel-body">
            {loading && <div className="hint-text">{t("common.loading", "Loading…")}</div>}
            {!loading && pending.length === 0 && (
              <div className="hint-text">{t("agent_approvals.none", "Nothing is waiting for approval.")}</div>
            )}
            {pending.map((a) => (
              <div key={a.id} style={{ borderBottom: "1px solid var(--border,#e5e7eb)", padding: "10px 0" }}>
                <button
                  type="button"
                  onClick={() => setOpen(open === a.id ? null : a.id)}
                  style={{ background: "none", border: "none", padding: 0, cursor: "pointer", color: "inherit", width: "100%", textAlign: "left" }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                    <span>
                      <strong>{a.agent_name}</strong> → <span className="mono">{a.tool_name}</span>
                      {a.chain_id ? <span className="hint-text"> · chain #{a.chain_id}</span> : null}
                    </span>
                    <span className="hint-text" style={{ fontSize: 12 }}>
                      <ExpiresIn iso={a.expires_at} /> {open === a.id ? "▲" : "▼"}
                    </span>
                  </div>
                </button>
                {open === a.id && (
                  <Review
                    id={a.id}
                    onDone={() => {
                      setOpen(null);
                      refresh();
                    }}
                  />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
