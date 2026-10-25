"use client";

// Where an upstream's credential lives (lib/sealing.ts): sealed here, in the
// browser, to the egress proxies - the server stores envelopes it cannot
// open - or kept in the proxies' own configuration. Shown on a route,
// connection, MCP server, A2A peer or HTTP tool; nothing is ever displayed
// or sent in clear text.

import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage } from "@/lib/errors";
import {
  countersignCredential, getCredential, getProxyKeys, proxyKeyHolds, sealCredential, setCredentialSource,
  type CredentialObject, type CredentialState, type ProxyKey,
} from "@/lib/sealing";

/** After creating an object with a credential typed in its form: seal it. */
export async function sealNew(obj: CredentialObject, id: number, credential: string): Promise<void> {
  if (credential) await sealCredential(obj, id, credential);
}

function Keys({ keys }: { keys: (ProxyKey & { holds: boolean })[] }) {
  const { t } = useTranslation();
  if (!keys.length) return <p className="error-text">{t("sealed.no_keys", "No egress proxy has registered its key yet: start one first.")}</p>;
  return (
    <div className="hint-text" style={{ fontSize: 12 }}>
      {t("sealed.keys_hint", "Sealed to these proxies' keys - compare the fingerprints with what each proxy logs on its host:")}
      {keys.map((k) => (
        <div key={k.proxy_id} className="u-mono">
          {k.holds ? "✓" : "✗"} {k.name} · {k.encryption_key_fingerprint}
          {!k.holds && ` (${t("sealed.bad_key", "not signed by the proxy's own key - not used")})`}
        </div>
      ))}
    </div>
  );
}

export function SealedCredential({ obj, id, allowLocal = true, onChange }: {
  obj: CredentialObject; id: number; allowLocal?: boolean; onChange?: () => void;
}) {
  const { t } = useTranslation();
  const [st, setSt] = useState<CredentialState | null>(null);
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const [keys, setKeys] = useState<(ProxyKey & { holds: boolean })[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getCredential(obj, id).then(setSt).catch(() => setSt(null));
  }, [obj, id]);

  async function open() {
    setEditing(true);
    setError(null);
    try {
      const list = await getProxyKeys();
      setKeys(await Promise.all(list.map(async (k) => ({ ...k, holds: await proxyKeyHolds(k) }))));
    } catch (e) {
      setError(errorMessage(e, t, t("sealed.failed", "That did not work.")));
    }
  }

  async function run(fn: () => Promise<CredentialState>) {
    setBusy(true);
    setError(null);
    try {
      setSt(await fn());
      setEditing(false);
      setValue("");
      onChange?.();
    } catch (e) {
      setError(errorMessage(e, t, t("sealed.failed", "That did not work.")));
    } finally {
      setBusy(false);
    }
  }

  if (!st) return null;
  const status = st.source === "sealed"
    ? (!st.sealed_for.length ? t("sealed.not_yet", "not sealed yet")
      : st.missing.length
      ? t("sealed.missing", { n: st.missing.length, defaultValue: `sealed - ${st.missing.length} proxies cannot open it yet` })
      : t("sealed.sealed", { n: st.sealed_for.length, defaultValue: `sealed to ${st.sealed_for.length} proxies` }))
    : st.source === "local" ? t("sealed.local", "in the proxies' configuration")
    : t("sealed.none", "no credential");

  return (
    <div style={{ fontSize: 12 }}>
      <span className={`pill ${st.source === "none" ? "pill-neutral"
        : st.missing.length || st.awaiting_sealing || (st.source === "sealed" && !st.sealed_for.length) ? "pill-medium" : "pill-low"}`}>
        {status}
      </span>
      {st.upstream && st.source === "sealed" && <span className="hint-text u-mono"> → {st.upstream}</span>}
      {st.stale.length > 0 && (
        <span className="hint-text"> · {t("sealed.stale", "sealed for an earlier address: seal it again")}</span>
      )}
      {st.source === "sealed" && (st.unsigned ?? []).length > 0 && (
        <span className="hint-text"> · {t("sealed.unsigned", "sealed by the server: proxies that follow the signed policy use it only once an administrator vouches for it")}
          <button type="button" className="btn btn-sm" style={{ marginLeft: 6 }} disabled={busy}
                  onClick={() => run(() => countersignCredential(obj, id))}>
            {t("sealed.countersign", "Vouch for it")}
          </button>
        </span>
      )}
      {st.awaiting_sealing && (
        <span className="hint-text"> · {t("sealed.awaiting", "the server still holds the old one: seal it under Egress → Proxies")}</span>
      )}
      {!editing && (
        <button type="button" className="btn btn-sm" style={{ marginLeft: 8 }} onClick={open}>
          {st.source === "sealed" && st.sealed_for.length ? t("sealed.replace", "Replace") : t("sealed.set", "Set credential")}
        </button>
      )}
      {editing && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 6 }}>
          {keys && <Keys keys={keys} />}
          {st.upstream && (
            <div className="hint-text" style={{ fontSize: 12 }}>
              {t("sealed.only_to", "The proxies send it only to")} <span className="u-mono">{st.upstream}</span>
            </div>
          )}
          <input type="password" autoComplete="new-password" maxLength={8000} value={value}
                 aria-label={t("gw.secret", "Secret")}
                 placeholder={t("sealed.placeholder", "Sealed in this browser; the server never sees it")}
                 onChange={(e) => setValue(e.target.value)} />
          <div className="u-btn-row">
            <button type="button" className="btn btn-primary btn-sm" disabled={busy || !value}
                    onClick={() => run(() => sealCredential(obj, id, value))}>
              {t("sealed.seal", "Seal to the proxies")}
            </button>
            {allowLocal && st.source !== "local" && (
              <button type="button" className="btn btn-sm" disabled={busy}
                      onClick={() => run(() => setCredentialSource(obj, id, "local"))}>
                {t("sealed.use_local", "In the proxies' configuration")}
              </button>
            )}
            {st.source !== "none" && (
              <button type="button" className="btn btn-sm" disabled={busy}
                      onClick={() => run(() => setCredentialSource(obj, id, "none"))}>
                {t("sealed.remove", "Remove")}
              </button>
            )}
            <button type="button" className="btn btn-sm" onClick={() => { setEditing(false); setValue(""); }}>
              {t("common.cancel", "Cancel")}
            </button>
          </div>
        </div>
      )}
      {error && <p className="error-text">{error}</p>}
    </div>
  );
}
