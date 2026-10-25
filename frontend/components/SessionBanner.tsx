"use client";

// For people who sign (administrators, approvers): at the top of every page,
//  - a new sign-in to their account waiting for this session to let it in
//    (with the passkey, or the password while they have no passkey) or to
//    refuse it;
//  - this session not confirmed with the passkey yet (one PIN prompt);
//  - no passkey at all yet: where to add one.
// Polls the session every 15 seconds; hidden when there is nothing to say.

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";
import { admitSession, certifySession, passkeysSupported, refuseSession, type SessionPeer } from "@/lib/signing";
import { confirmDialog, promptDialog } from "./Dialog";

const POLL_MS = 15000;

function describe(p: SessionPeer, t: (k: string, d?: string) => string): string {
  const when = new Date(p.created_at).toLocaleString();
  return `${when} · ${p.ip ?? t("session.unknown_address", "unknown address")} · ${p.user_agent ?? t("session.unknown_browser", "unknown browser")}`;
}

export function SessionBanner() {
  const { t } = useTranslation();
  const { session, refreshSession } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!session?.signing) return;
    const id = setInterval(() => void refreshSession(), POLL_MS);
    return () => clearInterval(id);
  }, [session?.signing, refreshSession]);

  if (!session?.signing || session.status !== "active") return null;

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refreshSession();
    } catch (err) {
      setError(errorMessage(err, t, t("session.failed", "That did not work - try again.")));
    } finally {
      setBusy(false);
    }
  }

  async function admit(p: SessionPeer) {
    if (session?.has_passkey) return run(() => admitSession(p.session_id, true));
    const password = await promptDialog(t("session.admit_password", "Let this sign-in in? Type your password to confirm:"));
    if (password) await run(() => admitSession(p.session_id, false, password));
  }

  async function refuse(p: SessionPeer) {
    if (await confirmDialog(t("session.refuse_confirm", "End this sign-in? If it was not you, change your password."), { danger: true }))
      await run(() => refuseSession(p.session_id));
  }

  const waiting = session.waiting ?? [];
  const style: React.CSSProperties = {
    display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", padding: "10px 16px", fontSize: 13,
    borderBottom: "1px solid var(--border)", color: "var(--text-primary)",
  };

  if (waiting.length) {
    return (
      <div role="alert" style={{ ...style, background: "var(--risk-critical-bg)", borderBottomColor: "var(--risk-critical)" }}>
        <span style={{ fontWeight: 700, color: "var(--risk-critical)" }}>
          {t("session.waiting_title", "Someone signed in to your account and is waiting for you")}
        </span>
        {waiting.map((p) => (
          <span key={p.session_id} style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
            <span>{describe(p, t)}</span>
            <button className="btn btn-sm" disabled={busy} onClick={() => admit(p)}>
              {session.has_passkey ? t("session.admit_passkey", "Let in (passkey)") : t("session.admit", "Let in")}
            </button>
            <button className="btn btn-sm btn-danger" disabled={busy} onClick={() => refuse(p)}>{t("session.refuse", "Refuse")}</button>
          </span>
        ))}
        {error && <span className="error-text">{error}</span>}
      </div>
    );
  }

  if (!session.has_passkey) {
    return (
      <div role="note" style={{ ...style, background: "var(--risk-medium-bg)" }}>
        <span>{t("session.no_passkey", "Add a passkey: it confirms your sign-ins and what you sign, with your device's PIN.")}</span>
        <Link href="/profile">{t("session.add_passkey", "Add in My profile")} →</Link>
      </div>
    );
  }

  if (!session.certified && passkeysSupported()) {
    return (
      <div role="note" style={{ ...style, background: "var(--risk-medium-bg)" }}>
        <span>{t("session.certify_hint", "Confirm this sign-in with your passkey: until then you cannot sign.")}</span>
        <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => run(() => certifySession(session))}>
          {t("session.certify", "Confirm with passkey")}
        </button>
        {error && <span className="error-text">{error}</span>}
      </div>
    );
  }
  return null;
}
