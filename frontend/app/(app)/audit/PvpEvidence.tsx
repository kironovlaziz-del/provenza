"use client";

// Evidence for auditors: the receipt of one agent action (signed record, the
// check it was decided by, its place in a sealed Merkle batch, the audit
// checkpoint) and TRACE exports, verifiable offline with tools/provenza_audit.py.

import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { errorMessage } from "@/lib/errors";
import { downloadJson, getActionTrace, getChainTrace, getReceipt } from "@/lib/gateways_api";

type Receipt = {
  action?: {
    action_id?: number; agent_id?: number; tool_name?: string; action_type?: string; decision?: string;
    recorded_at?: number; executed_by?: string | null; signed_by?: unknown;
  };
  seal?: { seal_id?: number; leaf_index?: number; size?: number; root?: string } | null;
  checkpoint?: unknown;
  current_decision?: string | null;
};

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr>
      <td className="hint-text" style={{ width: 220 }}>{label}</td>
      <td>{children}</td>
    </tr>
  );
}

export function PvpEvidence() {
  const { t, i18n } = useTranslation();
  const [actionId, setActionId] = useState("");
  const [chainId, setChainId] = useState("");
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorMessage(e, t, t("evidence.failed")));
    } finally {
      setBusy(false);
    }
  }

  const a = receipt?.action;
  return (
    <>
      <p className="hint-text u-mb-16">{t("evidence.hint")}</p>

      <div className="panel u-mb-16">
        <div className="panel-header"><h2>{t("evidence.receipt_title")}</h2></div>
        <div className="panel-body">
          <Form onSubmit={(e) => {
            e.preventDefault();
            run(async () => setReceipt((await getReceipt(Number(actionId))) as Receipt));
          }}>
            <div className="form-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 220 }}>
                <label htmlFor="ev-action">{t("evidence.action_id")}</label>
                <input id="ev-action" required type="number" min={1} value={actionId} onChange={(e) => setActionId(e.target.value)} />
              </div>
              <button className="btn btn-primary" type="submit" disabled={busy}>{t("evidence.show")}</button>
            </div>
          </Form>
          {error && <p className="error-text">{error}</p>}
          {receipt && a && (
            <>
              <table className="u-mt-12">
                <tbody>
                  <Row label={t("evidence.action")}>#{a.action_id} · <span className="u-mono">{a.tool_name}</span> ({a.action_type})</Row>
                  <Row label={t("evidence.agent")}>#{a.agent_id}</Row>
                  <Row label={t("evidence.decision")}>
                    {a.decision}
                    {receipt.current_decision && receipt.current_decision !== a.decision && (
                      <span className="hint-text"> · {t("evidence.now")}: {receipt.current_decision}</span>
                    )}
                  </Row>
                  <Row label={t("evidence.recorded")}>
                    {a.recorded_at ? new Date(a.recorded_at * 1000).toLocaleString(i18n.language) : "—"}
                  </Row>
                  <Row label={t("evidence.witness")}>
                    {a.signed_by ? t("evidence.signed_by_agent") : a.executed_by ? t("evidence.executed_by", { by: a.executed_by }) : "—"}
                  </Row>
                  <Row label={t("evidence.seal")}>
                    {receipt.seal
                      ? <>{t("evidence.sealed", { leaf: (receipt.seal.leaf_index ?? 0) + 1, size: receipt.seal.size })}{" "}
                          <span className="u-mono hint-text" title={receipt.seal.root}>{receipt.seal.root?.slice(0, 16)}…</span></>
                      : t("evidence.not_sealed")}
                  </Row>
                  <Row label={t("evidence.checkpoint")}>{receipt.checkpoint ? t("evidence.signed_checkpoint") : t("evidence.no_checkpoint")}</Row>
                </tbody>
              </table>
              <div className="u-btn-row u-mt-12">
                <button className="btn btn-sm" onClick={() => downloadJson(`receipt-${a.action_id}.json`, receipt)}>
                  {t("evidence.download_receipt")}
                </button>
                <button className="btn btn-sm" disabled={busy}
                        onClick={() => run(async () => downloadJson(`trace-action-${a.action_id}.json`, await getActionTrace(a.action_id!)))}>
                  {t("evidence.download_trace")}
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="panel u-mb-16">
        <div className="panel-header"><h2>{t("evidence.chain_title")}</h2></div>
        <div className="panel-body">
          <p className="hint-text">{t("evidence.chain_hint")}</p>
          <Form onSubmit={(e) => {
            e.preventDefault();
            run(async () => downloadJson(`trace-chain-${chainId}.json`, await getChainTrace(Number(chainId))));
          }}>
            <div className="form-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 220 }}>
                <label htmlFor="ev-chain">{t("evidence.chain_id")}</label>
                <input id="ev-chain" required type="number" min={1} value={chainId} onChange={(e) => setChainId(e.target.value)} />
              </div>
              <button className="btn btn-primary" type="submit" disabled={busy}>{t("evidence.download_trace")}</button>
            </div>
          </Form>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header"><h2>{t("evidence.verify_title")}</h2></div>
        <div className="panel-body">
          <p className="hint-text">{t("evidence.verify_hint")}</p>
          <pre className="u-mono">{"python tools/provenza_audit.py receipt receipt-123.json\npython tools/provenza_audit.py trace trace-chain-7.json"}</pre>
        </div>
      </div>
    </>
  );
}
