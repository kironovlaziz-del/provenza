"use client";

// The signed-in user's own account: who they are here, two-factor sign-in,
// passkeys (for people who sign), and their password. Changing the password
// ends every other session (a stolen session ends with it).

import React, { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { PageHeader } from "@/components/PageHeader";
import { MfaPanel } from "@/components/profile/MfaPanel";
import { PasskeysPanel } from "@/components/profile/PasskeysPanel";
import { changeMyPassword } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";

function Profile() {
  const { t } = useTranslation();
  const { user, refreshSession } = useAuth();
  const mfaRequired = useSearchParams().get("mfa") === "required";
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setDone(false);
    if (next !== again) {
      setError(t("profile.mismatch"));
      return;
    }
    setBusy(true);
    try {
      await changeMyPassword(current, next);
      await refreshSession();     // a new session: confirm it with the passkey again
      setCurrent("");
      setNext("");
      setAgain("");
      setDone(true);
    } catch (err) {
      setError(errorMessage(err, t, t("profile.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title={t("profile.title")} />
      <div className="content">
        <div className="panel u-mb-16">
          <div className="panel-header"><h2>{t("profile.account")}</h2></div>
          <div className="panel-body">
            <table>
              <tbody>
                <tr><td className="hint-text" style={{ width: 200 }}>{t("profile.name")}</td><td>{user?.name}</td></tr>
                <tr><td className="hint-text">{t("profile.email")}</td><td>{user?.email}</td></tr>
                <tr><td className="hint-text">{t("profile.role")}</td><td>{t(`sidebar.role_${user?.role ?? "user"}`)}</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <MfaPanel required={mfaRequired} />

        <PasskeysPanel />

        <div className="panel">
          <div className="panel-header"><h2>{t("profile.password_title")}</h2></div>
          <div className="panel-body">
            <p className="hint-text">{t("profile.password_hint")}</p>
            <Form onSubmit={submit}>
              <div className="field" style={{ maxWidth: 360 }}>
                <label htmlFor="pw-current">{t("profile.current")}</label>
                <input id="pw-current" type="password" required autoComplete="current-password" value={current}
                       onChange={(e) => setCurrent(e.target.value)} />
              </div>
              <div className="field" style={{ maxWidth: 360 }}>
                <label htmlFor="pw-new">{t("profile.new")}</label>
                <input id="pw-new" type="password" required minLength={8} autoComplete="new-password" value={next}
                       onChange={(e) => setNext(e.target.value)} />
              </div>
              <div className="field" style={{ maxWidth: 360 }}>
                <label htmlFor="pw-again">{t("profile.again")}</label>
                <input id="pw-again" type="password" required minLength={8} autoComplete="new-password" value={again}
                       onChange={(e) => setAgain(e.target.value)} />
              </div>
              {error && <p className="error-text">{error}</p>}
              {done && <p className="hint-text">{t("profile.changed")}</p>}
              <button className="btn btn-primary" type="submit" disabled={busy}>
                {busy ? t("common.loading") : t("profile.change")}
              </button>
            </Form>
          </div>
        </div>
      </div>
    </>
  );
}

export default function ProfilePage() {
  return (
    <Suspense>
      <Profile />
    </Suspense>
  );
}
