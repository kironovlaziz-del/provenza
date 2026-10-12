"use client";

// Two-factor sign-in for the signed-in user: set up with an authenticator app
// (the key or the otpauth link), confirm with a code, keep the recovery codes;
// switch off with password and code, or renew the recovery codes.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { disableMfa, enableMfa, getMyMfa, MyMfa, renewRecoveryCodes, setupMfa } from "@/lib/api";
import { errorMessage } from "@/lib/errors";

function group(secret: string) {
  return secret.match(/.{1,4}/g)?.join(" ") ?? secret;
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useTranslation();
  const text = codes.join("\n");
  return (
    <div className="panel u-mt-12" style={{ borderColor: "var(--risk-critical)" }}>
      <div className="panel-body">
        <p className="error-text">{t("mfa.codes_once")}</p>
        <pre className="u-mono" style={{ columns: 2, margin: "8px 0" }}>{text}</pre>
        <div className="u-btn-row">
          <button className="btn btn-sm" onClick={() => navigator.clipboard?.writeText(text).catch(() => undefined)}>{t("mfa.copy")}</button>
          <button className="btn btn-sm" onClick={() => {
            const url = URL.createObjectURL(new Blob([text + "\n"], { type: "text/plain" }));
            const a = document.createElement("a");
            a.href = url;
            a.download = "provenza-recovery-codes.txt";
            a.click();
            URL.revokeObjectURL(url);
          }}>{t("mfa.download")}</button>
          <button className="btn btn-sm btn-primary" onClick={onDone}>{t("mfa.saved_codes")}</button>
        </div>
      </div>
    </div>
  );
}

export function MfaPanel({ required }: { required?: boolean }) {
  const { t, i18n } = useTranslation();
  const [state, setState] = useState<MyMfa | null>(null);
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [mode, setMode] = useState<"idle" | "disable" | "renew">("idle");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => getMyMfa().then(setState).catch(() => setState(null));
  useEffect(() => { refresh(); }, []);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorMessage(e, t, t("mfa.failed")));
    } finally {
      setBusy(false);
    }
  }

  if (!state) return null;
  return (
    <div className="panel u-mb-16">
      <div className="panel-header u-flex u-justify-between u-items-center">
        <h2>{t("mfa.title")}</h2>
        <span className={`pill ${state.enabled ? "pill-low" : state.required ? "pill-critical" : "pill-neutral"}`}>
          {state.enabled ? t("mfa.on") : t("mfa.off")}
        </span>
      </div>
      <div className="panel-body">
        {(required || state.required) && !state.enabled && <p className="error-text">{t("mfa.required_notice")}</p>}
        <p className="hint-text">{t("mfa.hint")}</p>

        {!state.enabled && !setup && (
          <button className="btn btn-primary" disabled={busy} onClick={() => run(async () => setSetup(await setupMfa()))}>
            {t("mfa.start")}
          </button>
        )}

        {!state.enabled && setup && (
          <Form onSubmit={(e) => {
            e.preventDefault();
            run(async () => {
              const r = await enableMfa(code);
              setCodes(r.recovery_codes);
              setSetup(null);
              setCode("");
              await refresh();
            });
          }}>
            <ol className="hint-text" style={{ paddingLeft: 18 }}>
              <li>{t("mfa.step_app")}</li>
              <li>
                {t("mfa.step_key")}{" "}
                <code className="u-mono" style={{ fontSize: 15, userSelect: "all" }}>{group(setup.secret)}</code>
                <div><a href={setup.otpauth_uri}>{t("mfa.open_in_app")}</a></div>
              </li>
              <li>{t("mfa.step_code")}</li>
            </ol>
            <div className="form-row" style={{ alignItems: "flex-end" }}>
              <div className="field" style={{ maxWidth: 200 }}>
                <label htmlFor="mfa-code">{t("mfa.code")}</label>
                <input id="mfa-code" required autoComplete="one-time-code" inputMode="numeric" pattern="[0-9 ]{6,8}"
                       value={code} onChange={(e) => setCode(e.target.value)} />
              </div>
              <button className="btn btn-primary" type="submit" disabled={busy}>{t("mfa.confirm")}</button>
            </div>
          </Form>
        )}

        {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}

        {state.enabled && !codes && (
          <>
            <p>
              {t("mfa.since", { when: state.enabled_at ? new Date(state.enabled_at).toLocaleDateString(i18n.language) : "—" })}
              {" · "}
              {t("mfa.codes_left", { count: state.recovery_codes_left })}
            </p>
            {mode === "idle" && (
              <div className="u-btn-row">
                <button className="btn btn-sm" onClick={() => setMode("renew")}>{t("mfa.renew")}</button>
                {!state.required && (
                  <button className="btn btn-sm btn-danger" onClick={() => setMode("disable")}>{t("mfa.disable")}</button>
                )}
              </div>
            )}
            {mode !== "idle" && (
              <Form onSubmit={(e) => {
                e.preventDefault();
                run(async () => {
                  if (mode === "disable") await disableMfa(password, code);
                  else setCodes((await renewRecoveryCodes(code)).recovery_codes);
                  setMode("idle");
                  setCode("");
                  setPassword("");
                  await refresh();
                });
              }}>
                <div className="form-row" style={{ alignItems: "flex-end" }}>
                  {mode === "disable" && (
                    <div className="field" style={{ maxWidth: 240 }}>
                      <label htmlFor="mfa-pw">{t("profile.current")}</label>
                      <input id="mfa-pw" type="password" required autoComplete="current-password" value={password}
                             onChange={(e) => setPassword(e.target.value)} />
                    </div>
                  )}
                  <div className="field" style={{ maxWidth: 200 }}>
                    <label htmlFor="mfa-code2">{t("mfa.code")}</label>
                    <input id="mfa-code2" required autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
                  </div>
                  <button className={`btn ${mode === "disable" ? "btn-danger" : "btn-primary"}`} type="submit" disabled={busy}>
                    {mode === "disable" ? t("mfa.disable") : t("mfa.renew")}
                  </button>
                  <button className="btn" type="button" onClick={() => setMode("idle")}>{t("common.cancel")}</button>
                </div>
              </Form>
            )}
          </>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
