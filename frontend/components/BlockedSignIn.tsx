"use client";

// A second sign-in of an administrator or approver while a session of theirs
// is open: it waits here until that session lets it in (with the passkey), or
// ends the other session itself - with the passkey only.

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";
import { passkeysSupported, takeOver } from "@/lib/signing";

const POLL_MS = 5000;

export function BlockedSignIn() {
  const { t } = useTranslation();
  const router = useRouter();
  const { session, refreshSession, logout } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const id = setInterval(async () => {
      const s = await refreshSession();
      if (s?.status === "active") router.push("/dashboard");
    }, POLL_MS);
    return () => clearInterval(id);
  }, [refreshSession, router]);

  async function takeover() {
    setBusy(true);
    setError(null);
    try {
      await takeOver();
      const s = await refreshSession();
      if (s?.status === "active") router.push("/dashboard");
    } catch (err) {
      setError(errorMessage(err, t, t("session.failed", "That did not work - try again.")));
    } finally {
      setBusy(false);
    }
  }

  const open = session?.active_elsewhere ?? [];
  return (
    <div>
      <p className="hint-text">
        {t("session.blocked_text", "You are already signed in elsewhere. This sign-in waits until that session lets it in with your passkey.")}
      </p>
      {open.map((p) => (
        <p key={p.session_id} className="hint-text" style={{ fontSize: 12 }}>
          {new Date(p.created_at).toLocaleString()} · {p.ip ?? "?"} · {p.user_agent ?? "?"}
        </p>
      ))}
      <p className="hint-text">{t("session.blocked_waiting", "Waiting…")}</p>
      {session?.has_passkey && passkeysSupported() && (
        <button type="button" className="btn btn-primary" style={{ width: "100%", justifyContent: "center", marginTop: 4 }}
          disabled={busy} onClick={takeover}>
          {t("session.takeover", "End the other session (passkey)")}
        </button>
      )}
      {error && <p className="error-text">{error}</p>}
      <button type="button" className="btn" style={{ width: "100%", justifyContent: "center", marginTop: 8 }}
        onClick={logout}>
        {t("session.cancel", "Cancel this sign-in")}
      </button>
    </div>
  );
}
