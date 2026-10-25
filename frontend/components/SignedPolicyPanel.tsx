"use client";

// The signed policy (docs/pvp/edge.md, section 3): which release is in force,
// what the working copy changes that is not signed yet, the draft waiting for
// the administrators' passkeys, and the quorum / validity / offline time the
// next release states. Shown on the policy page; administrators act here.

import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { confirmDialog } from "@/components/Dialog";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/errors";
import {
  getReleaseState, prepareRelease, saveReleaseSettings, signRelease, withdrawRelease,
  type Change, type ReleaseSettings, type ReleaseState,
} from "@/lib/policy_release_api";

const when = (s: number | string | null | undefined) =>
  s == null ? "—" : new Date(typeof s === "number" ? s * 1000 : s).toLocaleString();

function short(v: unknown): string {
  if (v === null || v === undefined) return "—";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > 120 ? s.slice(0, 117) + "…" : s;
}

function Changes({ items, total }: { items: Change[]; total?: number }) {
  const { t } = useTranslation();
  if (!items.length) return <p className="hint-text">{t("release.no_changes", "Nothing differs.")}</p>;
  return (
    <div style={{ maxHeight: 320, overflowY: "auto", fontSize: 13 }}>
      {items.map((c, i) => (
        <div key={i} style={{ padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
          <span className={`pill ${c.change === "removed" ? "pill-neutral" : c.change === "added" ? "pill-medium" : "pill-accent"}`}>
            {t(`release.change_${c.change}`, c.change)}
          </span>{" "}
          <span className="hint-text">{t(`release.sections.${c.section.replace(/\./g, "__")}`, c.section)}</span>{" "}
          <span className="mono">{c.label}</span>
          {c.fields.map((f, j) => (
            <div key={j} className="mono" style={{ fontSize: 12, paddingLeft: 16 }}>
              {f.field ? `${f.field}: ` : ""}<span style={{ color: "var(--risk-critical)" }}>{short(f.before)}</span>
              {" → "}<span style={{ color: "var(--risk-low)" }}>{short(f.after)}</span>
            </div>
          ))}
        </div>
      ))}
      {total !== undefined && total > items.length && (
        <p className="hint-text">{t("release.more", { n: total - items.length, defaultValue: `and ${total - items.length} more` })}</p>
      )}
    </div>
  );
}

export function SignedPolicyPanel() {
  const { t } = useTranslation();
  const { user, session } = useAuth();
  const isAdmin = user?.role === "admin";
  const [st, setSt] = useState<ReleaseState | null>(null);
  const [cfg, setCfg] = useState<ReleaseSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showUnsigned, setShowUnsigned] = useState(false);

  const load = useCallback(() => {
    getReleaseState().then((s) => { setSt(s); setCfg(s.settings); }).catch((e) => setError(errorMessage(e, t, t("release.failed", "That did not work."))));
  }, [t]);
  useEffect(load, [load]);

  async function run(fn: () => Promise<ReleaseState | unknown>) {
    setBusy(true);
    setError(null);
    try {
      const out = await fn();
      if (out && typeof out === "object" && "settings" in (out as object)) setSt(out as ReleaseState);
      else load();
    } catch (e) {
      setError(errorMessage(e, t, t("release.failed", "That did not work.")));
    } finally {
      setBusy(false);
    }
  }

  if (!st) return error ? <p className="error-text">{error}</p> : null;
  const f = st.in_force;
  const d = st.draft;

  return (
    <div className="panel u-mb-16">
      <div className="panel-header"><h2>{t("release.title", "Signed policy")}</h2></div>
      <div className="panel-body">
        <p className="hint-text">
          {t("release.hint", "What decides allow or deny - agents' rights, policies, the Tool Registry, gateways and their routes - and the keys are frozen into a release that administrators sign with their passkeys. Once a release is in force, a change that loosens anything takes effect only when the quorum has signed the next release; a change that tightens takes effect at once.")}
        </p>

        {!f && <p className="u-mb-12"><strong>{t("release.none", "No release is signed yet: the working copy alone decides, as before.")}</strong></p>}
        {f && (
          <div className="u-mb-12" style={{ fontSize: 13 }}>
            <div>
              <strong>{t("release.in_force", { n: f.number, defaultValue: `Release #${f.number} is in force` })}</strong>{" "}
              <span className="hint-text">{t("release.since", "since")} {when(f.in_force_at)} · {t("release.valid_until", "valid until")} {when(f.not_after)}</span>
            </div>
            <div className="hint-text">
              {t("release.signed_by", "Signed by")} {f.signers.map((s) => s.email).join(", ")} · {t("release.quorum", "quorum")} {f.quorum}
              {" · "}<span className="mono" title={f.bundle.sha256}>bundle v{f.bundle.version} {f.bundle.sha256.slice(0, 12)}</span>
              {" · "}<span className="mono" title={f.manifest.sha256}>manifest v{f.manifest.version} {f.manifest.sha256.slice(0, 12)}</span>
            </div>
            <div className="hint-text" style={{ fontSize: 12 }}>
              {t("release.pin_hint", "To pin it on an egress proxy or sensor (policy.pin):")}{" "}
              <code style={{ userSelect: "all", wordBreak: "break-all" }}>{f.manifest.sha256}</code>
            </div>
            {(f.problem || f.expired) && (
              <p className="error-text">{f.problem
                ? t("release.problem", { problem: f.problem, defaultValue: `It does not verify (${f.problem}): no agent action is allowed until a quorum signs a new release.` })
                : t("release.expired", "It has expired: no agent action is allowed until a quorum signs a new release.")}</p>
            )}
            {st.unsigned_count !== null && (
              <div style={{ marginTop: 8 }}>
                {st.unsigned_count === 0
                  ? <span className="hint-text">{t("release.all_signed", "The working copy is exactly what is signed.")}</span>
                  : (
                    <button type="button" className="btn btn-sm" onClick={() => setShowUnsigned(!showUnsigned)}>
                      {t("release.unsigned", { n: st.unsigned_count, defaultValue: `${st.unsigned_count} changes are not signed` })} {showUnsigned ? "▲" : "▼"}
                    </button>
                  )}
                {showUnsigned && st.unsigned_changes && <Changes items={st.unsigned_changes} total={st.unsigned_count ?? undefined} />}
              </div>
            )}
          </div>
        )}

        {d && (
          <div className="u-mb-12" style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12 }}>
            <div style={{ fontSize: 13, marginBottom: 6 }}>
              <strong>{t("release.draft", { n: d.number, defaultValue: `Release #${d.number} waits for signatures` })}</strong>{" "}
              <span className="hint-text">
                {d.signers.length} / {d.quorum} · {t("release.valid_until", "valid until")} {when(d.not_after)}
                {d.signers.length ? ` · ${d.signers.map((s) => s.email).join(", ")}` : ""}
              </span>
            </div>
            <p className="hint-text" style={{ fontSize: 12 }}>
              {t("release.check_hash", "Your passkey signs this exact release:")}{" "}
              <span className="mono">bundle {d.bundle.sha256.slice(0, 16)} · manifest {d.manifest.sha256.slice(0, 16)}</span>
            </p>
            <Changes items={d.changes} />
            {isAdmin && (
              <div className="u-btn-row" style={{ marginTop: 8 }}>
                {d.can_sign && (
                  <button className="btn btn-primary btn-sm" disabled={busy} onClick={() => run(() => signRelease(d.id))}>
                    {t("release.sign", "Sign with passkey")}
                  </button>
                )}
                <button className="btn btn-sm" disabled={busy} onClick={async () => {
                  if (await confirmDialog(t("release.withdraw_confirm", "Withdraw this draft? Its signatures are dropped."))) await run(() => withdrawRelease(d.id));
                }}>{t("release.withdraw", "Withdraw")}</button>
                {!d.can_sign && !d.signers.some((s) => s.user_id === user?.id) && (
                  <span className="hint-text" style={{ fontSize: 12 }}>
                    {session?.has_passkey
                      ? t("release.not_signer", "Your passkey is not in the release that governs this one: you can sign from the next release on.")
                      : t("release.add_passkey", "Add a passkey in My profile to sign.")}
                  </span>
                )}
              </div>
            )}
          </div>
        )}

        {isAdmin && (
          <div className="u-btn-row u-mb-12">
            <button className="btn btn-sm" disabled={busy} onClick={async () => {
              if (!d || await confirmDialog(t("release.replace_confirm", "Prepare a new release from the working copy? The current draft and its signatures are withdrawn."))) await run(prepareRelease);
            }}>
              {f ? t("release.prepare", "Prepare a release of the changes") : t("release.prepare_first", "Prepare the first release")}
            </button>
          </div>
        )}

        {isAdmin && cfg && (
          <details>
            <summary className="hint-text" style={{ cursor: "pointer" }}>{t("release.settings", "Quorum, validity, offline time, mode, egress proxy binaries and configurations")}</summary>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end", marginTop: 8 }}>
              {([["quorum", 1, 10], ["validity_days", 1, 365], ["offline_seconds", 60, 86400]] as const).map(([k, lo, hi]) => (
                <div className="field" key={k} style={{ maxWidth: 200 }}>
                  <label htmlFor={`rel-${k}`}>{t(k === "quorum" ? "release.quorum_input" : `release.${k}`, k)}</label>
                  <input id={`rel-${k}`} type="number" min={lo} max={hi} value={cfg[k]}
                         onChange={(e) => setCfg({ ...cfg, [k]: Number(e.target.value) })} />
                </div>
              ))}
              <div className="field" style={{ maxWidth: 420 }}>
                <label htmlFor="rel-enforcement">{t("release.enforcement", "Mode")}</label>
                <select id="rel-enforcement" value={cfg.enforcement ?? "observe"}
                        onChange={(e) => setCfg({ ...cfg, enforcement: e.target.value as "observe" | "enforce" })}>
                  <option value="observe">{t("release.enforcement_observe", "Observe: agents may act after a check")}</option>
                  <option value="enforce">{t("release.enforcement_enforce", "Enforce: agent-signed, through a proxy only")}</option>
                </select>
              </div>
              <div className="field" style={{ flexBasis: "100%" }}>
                <label htmlFor="rel-proxy-binaries">{t("release.proxy_binaries", "Egress proxy binaries (SHA-256, one per line)")}</label>
                <textarea id="rel-proxy-binaries" rows={2} className="u-mono" spellCheck={false}
                          value={(cfg.proxy_binaries ?? []).join("\n")}
                          onChange={(e) => setCfg({ ...cfg, proxy_binaries: e.target.value.split(/\s+/).filter(Boolean) })} />
              </div>
              <div className="field" style={{ flexBasis: "100%" }}>
                <label htmlFor="rel-proxy-configs">{t("release.proxy_configs", "Egress proxy configurations (SHA-256 of proxy.json, one per line)")}</label>
                <textarea id="rel-proxy-configs" rows={2} className="u-mono" spellCheck={false}
                          value={(cfg.proxy_configs ?? []).join("\n")}
                          onChange={(e) => setCfg({ ...cfg, proxy_configs: e.target.value.split(/\s+/).filter(Boolean) })} />
              </div>
              <button className="btn btn-sm" disabled={busy} onClick={() => run(() => saveReleaseSettings(cfg))}>{t("common.save", "Save")}</button>
            </div>
            <p className="hint-text" style={{ fontSize: 12 }}>
              {t("release.settings_hint", "These take effect with the next signed release. The quorum is how many administrators must sign (2 or more: one stolen device or one rogue administrator cannot loosen anything); validity: after it, nothing is allowed until a new release is signed; offline time: how long an enforcement point keeps working without this server; egress proxy binaries: a sensor on a proxy host lets the proxy out only while it runs one of these (sha256sum provenza-proxy), with one of the configurations (sha256sum proxy.json). Enforce mode: this server's gateways execute nothing and a check by the agent only observes - every action goes through an egress proxy in enforce mode, signed by the agent (the proxy's agent mode signs for clients that cannot); switching it on takes effect at once, switching it off only with a signed release.")}
            </p>
          </details>
        )}
        {error && <p className="error-text">{error}</p>}
      </div>
    </div>
  );
}
