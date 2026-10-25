"use client";

// For administrators, at the top of every page, what needs their passkey in
// the signed policy (components/SignedPolicyPanel.tsx): a release that no
// longer verifies or has expired (nothing is allowed), a draft waiting for
// their signature, a release about to expire, changes not signed yet.
// Polls every minute; hidden when there is nothing to say.

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import { getReleaseState, type ReleaseState } from "@/lib/policy_release_api";

const POLL_MS = 60000;
const SOON_S = 7 * 86400;

export function ReleaseBanner() {
  const { t } = useTranslation();
  const { user, session } = useAuth();
  const admin = user?.role === "admin" && session?.status === "active";
  const [st, setSt] = useState<ReleaseState | null>(null);

  useEffect(() => {
    if (!admin) return;
    const load = () => getReleaseState().then(setSt).catch(() => setSt(null));
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [admin]);

  if (!admin || !st) return null;
  const f = st.in_force;
  const style: React.CSSProperties = {
    display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", padding: "8px 16px", fontSize: 13,
    borderBottom: "1px solid var(--border)", color: "var(--text-primary)",
  };
  const link = <Link href="/policy-hierarchy">{t("release.open", "Signed policy")} →</Link>;

  if (f && (f.problem || f.expired)) {
    return (
      <div role="alert" style={{ ...style, background: "var(--risk-critical-bg)" }}>
        <strong style={{ color: "var(--risk-critical)" }}>
          {f.problem ? t("release.banner_invalid", "The signed policy does not verify: no agent action is allowed.")
            : t("release.banner_expired", "The signed policy has expired: no agent action is allowed.")}
        </strong>
        {link}
      </div>
    );
  }
  const notes: string[] = [];
  if (st.draft?.can_sign) notes.push(t("release.banner_sign", { n: st.draft.number, defaultValue: `Release #${st.draft.number} waits for your signature.` }));
  if (f && f.not_after - Date.now() / 1000 < SOON_S) notes.push(t("release.banner_soon", { date: new Date(f.not_after * 1000).toLocaleDateString(), defaultValue: "The signed policy expires soon." }));
  if (st.unsigned_count) notes.push(t("release.banner_unsigned", { n: st.unsigned_count, defaultValue: `${st.unsigned_count} policy changes take effect only after signing.` }));
  if (!notes.length) return null;
  return (
    <div role="note" style={{ ...style, background: "var(--risk-medium-bg)" }}>
      <span>{notes.join(" ")}</span>
      {link}
    </div>
  );
}
