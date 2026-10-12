"use client";

// Approvals of usage requests (Usage Registry): anyone sees them, admins and
// approvers decide.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { StatusPill } from "@/components/Pill";
import { decideApproval, listApprovals } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Approval } from "@/lib/types";

export function RequestApprovals() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const canDecide = user?.role === "admin" || user?.role === "approver"; // the API refuses others
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [reasonDraft, setReasonDraft] = useState<Record<number, string>>({});

  function refresh() {
    setLoading(true);
    listApprovals()
      .then(setApprovals)
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function decide(id: number, decision: "approved" | "rejected") {
    setBusyId(id);
    try {
      await decideApproval(id, { decision, reason: reasonDraft[id] || undefined });
      refresh();
    } finally {
      setBusyId(null);
    }
  }

  const pending = approvals.filter((a) => !a.decision);
  const decided = approvals.filter((a) => a.decision);

  return (
    <>
        <div className="panel u-mb-16">
          <div className="panel-header">
            <h2>{t("approvals.pending_title")}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t("approvals.col_id")}</th>
                <th>{t("approvals.col_request")}</th>
                <th>{t("approvals.col_comment")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr className="empty-row">
                  <td colSpan={4}>{t("approvals.loading")}</td>
                </tr>
              )}
              {!loading && pending.length === 0 && (
                <tr className="empty-row">
                  <td colSpan={4}>{t("approvals.empty_pending")}</td>
                </tr>
              )}
              {pending.map((a) => (
                <tr key={a.id}>
                  <td className="mono">#{a.id}</td>
                  <td>
                    <Link href={`/requests/${a.request_id}`}>
                      {t("approvals.request_link", { id: a.request_id })}
                    </Link>
                  </td>
                  <td>
                    {canDecide && <input
                      placeholder={t("approvals.comment_placeholder")}
                      value={reasonDraft[a.id] || ""}
                      onChange={(e) =>
                        setReasonDraft((d) => ({ ...d, [a.id]: e.target.value }))
                      }
                      style={{
                        border: "1px solid var(--border-strong)",
                        borderRadius: 4,
                        padding: "6px 8px",
                        width: "100%",
                      }}
                    />}
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    {canDecide && <><button
                      className="btn btn-sm btn-primary"
                      style={{ marginRight: 6 }}
                      disabled={busyId === a.id}
                      onClick={() => decide(a.id, "approved")}
                    >
                      {t("approvals.approve")}
                    </button>
                    <button
                      className="btn btn-sm btn-danger"
                      disabled={busyId === a.id}
                      onClick={() => decide(a.id, "rejected")}
                    >
                      {t("approvals.reject")}
                    </button></>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>{t("approvals.decided_title")}</h2>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t("approvals.col_id")}</th>
                <th>{t("approvals.col_request")}</th>
                <th>{t("approvals.col_decision")}</th>
                <th>{t("approvals.col_reason")}</th>
                <th>{t("approvals.col_date")}</th>
              </tr>
            </thead>
            <tbody>
              {!loading && decided.length === 0 && (
                <tr className="empty-row">
                  <td colSpan={5}>{t("approvals.empty_decided")}</td>
                </tr>
              )}
              {decided.map((a) => (
                <tr key={a.id}>
                  <td className="mono">#{a.id}</td>
                  <td>
                    <Link href={`/requests/${a.request_id}`}>
                      {t("approvals.request_link", { id: a.request_id })}
                    </Link>
                  </td>
                  <td>
                    <StatusPill status={a.decision || ""} />
                  </td>
                  <td>{a.reason || "—"}</td>
                  <td className="mono">
                    {new Date(a.created_at).toLocaleString(i18n.language)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
                </div>
    </>
  );
}
