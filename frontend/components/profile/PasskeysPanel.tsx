"use client";

// Passkeys of a person who signs (administrator, approver): the device-held
// key, unlocked by the device's PIN, that confirms each sign-in and what is
// signed. Adding one asks for the password and - once there is a passkey -
// for an existing passkey too; removing one asks for both.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Form } from "@/components/Form";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";
import { listPasskeys, passkeysSupported, registerPasskey, removePasskey, type Passkey } from "@/lib/signing";

export function PasskeysPanel() {
  const { t } = useTranslation();
  const { session, refreshSession } = useAuth();
  const [keys, setKeys] = useState<Passkey[] | null>(null);
  const [label, setLabel] = useState("");
  const [password, setPassword] = useState("");
  const [removing, setRemoving] = useState<Passkey | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => listPasskeys().then(setKeys).catch(() => setKeys([]));
  useEffect(() => { refresh(); }, []);

  if (!session?.signing) return null;

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setPassword("");
      setLabel("");
      setRemoving(null);
      await refresh();
      await refreshSession();
    } catch (err) {
      setError(errorMessage(err, t, t("passkeys.failed", "That did not work - try again.")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("passkeys.title", "Passkeys")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">
          {t("passkeys.hint", "A passkey stays on your phone or computer and is unlocked with its PIN. It confirms each sign-in and everything you sign; Provenza keeps only its public key. Add a second one on another device so you are not locked out.")}
        </p>
        {!passkeysSupported() && <p className="error-text">{t("passkeys.unsupported", "This browser cannot use passkeys.")}</p>}
        {keys && keys.length > 0 && (
          <table className="u-mb-12">
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td>{k.label}</td>
                  <td className="hint-text">{k.algorithm} <code title={t("passkeys.fingerprint_hint", "Fingerprint: pins this passkey when receipts of approved actions are checked offline")}>{k.fingerprint}</code></td>
                  <td className="hint-text">{t("passkeys.added", "added")} {new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="hint-text">
                    {k.last_used_at ? `${t("passkeys.used", "used")} ${new Date(k.last_used_at).toLocaleString()}` : ""}
                  </td>
                  <td><button className="btn btn-sm btn-danger" disabled={busy} onClick={() => setRemoving(k)}>{t("passkeys.remove", "Remove")}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {keys && keys.length === 0 && <p className="hint-text">{t("passkeys.none", "No passkey yet.")}</p>}
        <Form onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            if (removing) await removePasskey(removing.id, password);
            else await registerPasskey(label.trim() || t("passkeys.default_label", "passkey"), password);
          });
        }}>
          {removing ? (
            <p className="hint-text">{t("passkeys.remove_confirm", { label: removing.label, defaultValue: "Remove “{{label}}”? Confirm with your password and a passkey." })}</p>
          ) : (
            <div className="field" style={{ maxWidth: 360 }}>
              <label htmlFor="pk-label">{t("passkeys.label", "Name (e.g. work laptop)")}</label>
              <input id="pk-label" maxLength={100} value={label} onChange={(e) => setLabel(e.target.value)} />
            </div>
          )}
          <div className="field" style={{ maxWidth: 360 }}>
            <label htmlFor="pk-password">{t("passkeys.password", "Your Provenza password (the one you sign in with, not the device PIN)")}</label>
            <input id="pk-password" type="password" required autoComplete="current-password" value={password}
                   onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && <p className="error-text">{error}</p>}
          <div className="u-btn-row">
            <button className={`btn ${removing ? "btn-danger" : "btn-primary"}`} type="submit" disabled={busy || !passkeysSupported()}>
              {removing ? t("passkeys.remove", "Remove") : t("passkeys.add", "Add a passkey")}
            </button>
            {removing && <button className="btn" type="button" onClick={() => setRemoving(null)}>{t("common.cancel")}</button>}
          </div>
        </Form>
      </div>
    </div>
  );
}
