"use client";

// The organization's audit key: current fingerprint, verified handovers,
// a pending change with its quorum, and a fingerprint pinned in this browser.
// A new key is trusted only when the old key handed over to it AND its
// fingerprint matches what was published outside Provenza.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { translateApiError } from "@/lib/errors";
import {
  approveRotation,
  cancelRotation,
  checkHandover,
  completeRotation,
  getKeyStatus,
  pinStatus,
  proposeRotation,
  type KeyStatusT,
} from "@/lib/audit_api";

const PIN_KEY = "provenza.audit.pinned_fingerprint";

function readPin(): string {
  try {
    return localStorage.getItem(PIN_KEY) ?? "";
  } catch {
    return "";
  }
}

function writePin(fp: string) {
  try {
    if (fp) localStorage.setItem(PIN_KEY, fp);
    else localStorage.removeItem(PIN_KEY);
  } catch {
    /* storage unavailable: the pin lasts for this page only */
  }
}

export function KeyPanel({ isAdmin, onChange }: { isAdmin: boolean; onChange?: () => void }) {
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<KeyStatusT | null>(null);
  const [verified, setVerified] = useState<Record<number, boolean>>({});
  const [pin, setPin] = useState("");
  const [pinState, setPinState] = useState<"" | "match" | "changed" | "unknown">("");
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const when = (s: string) => new Date(s).toLocaleString(i18n.language);

  function load() {
    getKeyStatus()
      .then(async (d) => {
        setData(d);
        const v: Record<number, boolean> = {};
        for (const h of d.handovers) v[h.rotation_id] = await checkHandover(h);
        setVerified(v);
      })
      .catch((e) => setError(translateApiError(e?.response?.data?.detail, t, t("audit.load_failed"))));
  }

  useEffect(() => {
    setPin(readPin());
    load();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!pin || !data?.current) {
      setPinState("");
      return;
    }
    let live = true; // a slower check for an older pin must not overwrite a newer one
    pinStatus(pin, data.current.fingerprint, data.handovers).then((s) => { if (live) setPinState(s); });
    return () => { live = false; };
  }, [pin, data]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError("");
    try {
      await fn();
      setTyped("");
      setReason("");
      load();
      onChange?.();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: unknown } } };
      setError(translateApiError(err?.response?.data?.detail, t, t("audit.action_failed")));
    } finally {
      setBusy(false);
    }
  }

  if (!data) return error ? <div className="error-text">{error}</div> : null;
  const cur = data.current;
  const p = data.pending;
  const counted = p ? p.approvals.filter((a) => a.counts).length : 0;

  return (
    <div style={{ borderTop: "1px solid var(--border)", marginTop: 8, paddingTop: 10, display: "grid", gap: 6 }}>
      <strong>{t("audit.key_title")}</strong>
      {error && <div className="error-text">{error}</div>}
      {!cur && <div className="hint-text">{t("audit.key_none")}</div>}
      {cur && (
        <>
          <div className="mono" style={{ overflowWrap: "anywhere" }}>
            {cur.fingerprint} ({cur.algorithm}{cur.organization_key ? "" : `, ${t("audit.key_shared")}`})
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            {pinState === "match" && <span className="pill pill-low">✓ {t("audit.pin_match")}</span>}
            {pinState === "changed" && <span className="pill pill-medium">{t("audit.pin_changed")}</span>}
            {pinState === "unknown" && <span className="pill pill-critical">✗ {t("audit.pin_unknown")}</span>}
            {!pin && <span className="hint-text">{t("audit.pin_none")}</span>}
            <button type="button" className="btn btn-sm" onClick={() => { writePin(cur.fingerprint); setPin(cur.fingerprint); }}>
              {t("audit.pin_this")}
            </button>
            {pin && (
              <button type="button" className="btn btn-sm" onClick={() => { writePin(""); setPin(""); }}>
                {t("audit.pin_clear")}
              </button>
            )}
          </div>
          {pin && pinState !== "match" && (
            <div className="hint-text mono" style={{ overflowWrap: "anywhere" }}>
              {t("audit.pin_yours", { fp: pin })}
            </div>
          )}
        </>
      )}

      {data.handovers.length > 0 && (
        <div>
          <div className="hint-text">{t("audit.handovers")}</div>
          <ul style={{ margin: "4px 0 0 18px" }}>
            {data.handovers.map((h) => (
              <li key={h.rotation_id} className="mono" style={{ overflowWrap: "anywhere" }}>
                {verified[h.rotation_id] === undefined ? "…" : verified[h.rotation_id] ? "✓" : "✗"}{" "}
                {h.old_key_fingerprint} → {h.new_key_fingerprint} · {t("audit.handover_at", { size: h.tree_size, time: when(h.issued_at) })}
              </li>
            ))}
          </ul>
        </div>
      )}

      {p && (
        <div className="panel" style={{ padding: 10, display: "grid", gap: 6 }}>
          <div><strong>{t("audit.rotation_pending")}</strong>{p.reason ? ` — ${p.reason}` : ""}</div>
          <div className="mono" style={{ fontSize: 14, overflowWrap: "anywhere" }}>{p.new_key.fingerprint}</div>
          <div className="hint-text">{t("audit.rotation_publish")}</div>
          <div>
            {t("audit.rotation_progress", { have: counted, need: p.quorum })} ·{" "}
            {t("audit.rotation_after", { time: when(p.activate_after) })}
          </div>
          <div className="hint-text">
            {p.approvals.map((a) => `${a.email}${a.counts ? "" : ` (${t("audit.rotation_not_counted")})`}`).join(", ")}
          </div>
          {isAdmin && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                placeholder={t("audit.rotation_type_fp")}
                aria-label={t("audit.rotation_type_fp")}
                className="mono"
                style={{ flex: "1 1 280px", minWidth: 0 }}
              />
              <button type="button" className="btn btn-sm" disabled={busy || !typed.trim()} onClick={() => act(() => approveRotation(p.id, typed.trim()))}>
                {t("audit.rotation_approve")}
              </button>
              <button type="button" className="btn btn-sm btn-primary" disabled={busy || !p.ready} onClick={() => act(() => completeRotation(p.id))}>
                {t("audit.rotation_complete")}
              </button>
              <button type="button" className="btn btn-sm" disabled={busy} onClick={() => act(() => cancelRotation(p.id))}>
                {t("audit.rotation_cancel")}
              </button>
            </div>
          )}
        </div>
      )}

      {isAdmin && !p && cur && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={500}
            placeholder={t("audit.rotation_reason")}
            aria-label={t("audit.rotation_reason")}
            style={{ flex: "1 1 240px", minWidth: 0 }}
          />
          <button type="button" className="btn btn-sm" disabled={busy} onClick={() => act(() => proposeRotation(reason.trim()))}>
            {t("audit.rotation_propose")}
          </button>
        </div>
      )}
      {isAdmin && !p && cur && (
        <div className="hint-text">{t("audit.rotation_rules", { quorum: data.quorum, hours: data.notice_hours })}</div>
      )}
    </div>
  );
}
