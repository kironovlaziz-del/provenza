"use client";

// Rule packs, a tab of the Policy hierarchy page (backend services/rule_packs.py).
// A profile replaces a level's policy; a guard adds its restrictions to it.
// Every application is listed and can be undone; both are shown as "before ->
// after" first and saved like an edit of the level (revision, audit log, and
// under a signed policy a loosening waits for the next signed release).

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { argRuleText } from "@/components/ArgumentRulesEditor";
import { confirmDialog } from "@/components/Dialog";
import { useAuth } from "@/lib/auth";
import { errorMessage as apiError } from "@/lib/errors";
import type { Agent } from "@/lib/agent_types";
import type { OverviewT, Scope } from "@/lib/policy_layers_api";
import {
  applyPack, createPack, deletePack, listApplications, listPacks, packFileName, previewApply, previewUndo,
  undoApplication, updatePack,
  type ApplicationT, type ApplyPreviewT, type PackChange, type PackIn, type PackKind, type PackLevel, type PackT,
  type UndoPreviewT,
} from "@/lib/policy_packs_api";

type Target = { scope: Scope; id: number | null };
type Editing = { id: number | null; body: PackIn };

const EMPTY: PackIn = { name: "", description: "", kind: "guard", level: "any", yaml: "version: 1\ntools:\n  deny: []\n" };
const targetKey = (x: Target) => `${x.scope}:${x.id ?? ""}`;

function Changes({ changes }: { changes: PackChange[] }) {
  const { t } = useTranslation();
  if (changes.length === 0) return <p className="hint-text ag-small">{t("packs.no_changes")}</p>;
  const show = (v: unknown) => (v === null || v === undefined ? "—" : Array.isArray(v) ? (v.length ? v.join(", ") : "[ ]") : String(v));
  const item = (p: unknown) => (typeof p === "object" && p !== null ? argRuleText(p, t) : String(p));
  return (
    <div className="ag-stack" style={{ gap: 6 }}>
      {changes.map((c) => (
        <div key={c.field} className="ag-small">
          <strong>{t(`ph.field.${c.field}`, c.field)}</strong>{" "}
          {c.added || c.removed ? (
            <>
              {(c.added ?? []).map((p) => <span key={`+${item(p)}`} className="pill pill-accent mono" style={{ marginRight: 4 }}>+ {item(p)}</span>)}
              {(c.removed ?? []).map((p) => <span key={`-${item(p)}`} className="pill pill-neutral mono" style={{ marginRight: 4, textDecoration: "line-through" }}>{item(p)}</span>)}
              {Array.isArray(c.after) && c.after.length === 0 && <span className="hint-text"> {t("packs.allow_nothing")}</span>}
            </>
          ) : (
            <span className="mono">{show(c.before)} → {show(c.after)}</span>
          )}
        </div>
      ))}
    </div>
  );
}

export function RulePacks({ overview, agents, onChanged }: {
  overview: OverviewT | null; agents: Agent[]; onChanged: () => void;
}) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [packs, setPacks] = useState<{ builtin: PackT[]; own: PackT[] } | null>(null);
  const [apps, setApps] = useState<ApplicationT[]>([]);
  const [open, setOpen] = useState<string | null>(null);              // a pack whose YAML is shown
  const [applying, setApplying] = useState<PackT | null>(null);
  const [target, setTarget] = useState<Target>({ scope: "org", id: null });
  const [preview, setPreview] = useState<ApplyPreviewT | null>(null);
  const [undoing, setUndoing] = useState<UndoPreviewT | null>(null);
  const [confirmEdited, setConfirmEdited] = useState(false);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const load = useCallback(() => {
    listPacks().then(setPacks).catch((err) => setError(apiError(err, t, t("packs.load_failed"))));
    listApplications().then(setApps).catch(() => setApps([]));
  }, [t]);
  useEffect(() => { load(); }, [load]);

  const targets = useMemo(() => {
    const out: { key: string; target: Target; label: string }[] = [{ key: "org:", target: { scope: "org", id: null }, label: t("packs.level_org") }];
    for (const x of overview?.teams ?? []) out.push({ key: `team:${x.id}`, target: { scope: "team", id: x.id }, label: `${t("packs.level_team")}: ${x.name}` });
    for (const a of agents.filter((y) => y.status !== "retired")) out.push({ key: `agent:${a.id}`, target: { scope: "agent", id: a.id }, label: `${t("packs.level_agent")}: ${a.name}` });
    return out;
  }, [overview, agents, t]);
  const labelOf = (scope: Scope, id: number | null) =>
    targets.find((x) => x.key === targetKey({ scope, id }))?.label ?? `${scope} ${id ?? ""}`;

  function say(msg: string) { setError(null); setNotice(msg); }
  function fail(err: unknown, fallback: string) { setNotice(null); setError(apiError(err, t, fallback)); }

  // ------------------------------------------------------------------ apply
  function startApply(p: PackT) {
    setEditing(null);
    setUndoing(null);
    setApplying(p);
    setPreview(null);
    const first = p.level === "team" ? targets.find((x) => x.target.scope === "team")
      : p.level === "agent" ? targets.find((x) => x.target.scope === "agent") : targets[0];
    setTarget(first?.target ?? { scope: "org", id: null });
  }

  useEffect(() => {
    if (!applying) return;
    setPreview(null);
    previewApply(applying.ref, target.scope, target.id).then(setPreview).catch((err) => fail(err, t("packs.preview_failed")));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applying, target]);

  async function apply() {
    if (!applying || !preview) return;
    setBusy(true);
    try {
      const res = await applyPack(applying.ref, target.scope, target.id, preview.revision);
      say(res.skipped.length ? t("packs.applied_skipped", { name: applying.name, fields: res.skipped.join(", ") })
        : t("packs.applied", { name: applying.name }));
      setApplying(null);
      load();
      onChanged();
    } catch (err) {
      fail(err, t("packs.apply_failed"));
    } finally {
      setBusy(false);
    }
  }

  // ------------------------------------------------------------------ undo
  async function startUndo(a: ApplicationT) {
    setApplying(null);
    setEditing(null);
    setConfirmEdited(false);
    try {
      setUndoing(await previewUndo(a.id));
    } catch (err) {
      fail(err, t("packs.preview_failed"));
    }
  }

  async function undo() {
    if (!undoing) return;
    setBusy(true);
    try {
      await undoApplication(undoing.application.id, undoing.revision, confirmEdited);
      say(t("packs.undone", { name: undoing.application.pack_name }));
      setUndoing(null);
      load();
      onChanged();
    } catch (err) {
      fail(err, t("packs.undo_failed"));
    } finally {
      setBusy(false);
    }
  }

  // ------------------------------------------------------------------ own packs
  function startEdit(p: PackT | null, copy = false) {
    setApplying(null);
    setUndoing(null);
    if (!p) { setEditing({ id: null, body: { ...EMPTY } }); return; }
    setEditing({ id: copy ? null : p.id ?? null,
      body: { name: copy ? t("packs.copy_of", { name: p.name }) : p.name, description: p.description ?? "",
        kind: p.kind, level: p.level, yaml: p.yaml } });
  }

  async function saveEdit() {
    if (!editing) return;
    setBusy(true);
    try {
      if (editing.id) await updatePack(editing.id, editing.body);
      else await createPack(editing.body);
      say(t("packs.saved", { name: editing.body.name }));
      setEditing(null);
      load();
    } catch (err) {
      fail(err, t("packs.save_failed"));
    } finally {
      setBusy(false);
    }
  }

  async function remove(p: PackT) {
    if (!p.id || !await confirmDialog(t("packs.confirm_delete", { name: p.name }))) return;
    try {
      await deletePack(p.id);
      say(t("packs.deleted", { name: p.name }));
      load();
    } catch (err) {
      fail(err, t("packs.save_failed"));
    }
  }

  function download(p: PackT) {
    const url = URL.createObjectURL(new Blob([p.yaml], { type: "application/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = packFileName(p.name);
    a.click();
    URL.revokeObjectURL(url);
  }

  async function upload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 32 * 1024) { setError(t("packs.too_large")); return; }
    const text = await file.text();
    const allows = /^\s*allow\s*:/m.test(text) && /^\s*tools\s*:/m.test(text);
    setApplying(null);
    setUndoing(null);
    setEditing({ id: null, body: { name: file.name.replace(/\.ya?ml$/i, ""), description: "",
      kind: allows ? "profile" : "guard", level: "any", yaml: text } });
  }

  const active = apps.filter((a) => !a.undone_at);
  const groups: { kind: PackKind; title: string; hint: string }[] = [
    { kind: "profile", title: t("packs.profiles"), hint: t("packs.profiles_hint") },
    { kind: "guard", title: t("packs.guards"), hint: t("packs.guards_hint") },
  ];
  const all = [...(packs?.builtin ?? []), ...(packs?.own ?? [])];

  return (
    <div className="ag-stack">
      <p className="hint-text">{t("packs.intro")}</p>
      {error && <p className="error-text ag-banner">{error}</p>}
      {notice && <p className="hint-text ag-banner">{notice}</p>}

      {isAdmin && (
        <div className="ag-actions">
          <button className="btn btn-primary" onClick={() => startEdit(null)}>{t("packs.new")}</button>
          <button className="btn" onClick={() => fileInput.current?.click()}>{t("packs.upload")}</button>
          <input ref={fileInput} type="file" accept=".yaml,.yml,text/yaml" hidden onChange={upload} />
        </div>
      )}

      {/* ---------------- editor ---------------- */}
      {editing && (
        <section className="panel" style={{ borderColor: "var(--accent)" }}>
          <div className="panel-header"><h2>{editing.id ? t("packs.edit") : t("packs.new")}</h2></div>
          <div className="panel-body ag-stack">
            <div className="ph-fields">
              <div className="field"><label>{t("packs.name")}</label>
                <input value={editing.body.name} maxLength={100} onChange={(e) => setEditing({ ...editing, body: { ...editing.body, name: e.target.value } })} /></div>
              <div className="field"><label>{t("packs.kind")}</label>
                <select value={editing.body.kind} onChange={(e) => setEditing({ ...editing, body: { ...editing.body, kind: e.target.value as PackKind } })}>
                  <option value="guard">{t("packs.kind_guard")}</option>
                  <option value="profile">{t("packs.kind_profile")}</option>
                </select></div>
              <div className="field"><label>{t("packs.level")}</label>
                <select value={editing.body.level} onChange={(e) => setEditing({ ...editing, body: { ...editing.body, level: e.target.value as PackLevel } })}>
                  {(["any", "org", "team", "agent"] as PackLevel[]).map((l) => <option key={l} value={l}>{t(`packs.level_${l}`)}</option>)}
                </select></div>
            </div>
            <div className="field"><label>{t("packs.description")}</label>
              <input value={editing.body.description ?? ""} maxLength={2000} onChange={(e) => setEditing({ ...editing, body: { ...editing.body, description: e.target.value } })} /></div>
            <p className="hint-text ag-small">{t(editing.body.kind === "guard" ? "packs.guard_rule" : "packs.profile_rule")}</p>
            <textarea className="mono ag-wrap" rows={16} style={{ fontSize: 12 }} spellCheck={false} value={editing.body.yaml}
              onChange={(e) => setEditing({ ...editing, body: { ...editing.body, yaml: e.target.value } })} />
            <div className="ag-actions">
              <button className="btn btn-primary" disabled={busy || !editing.body.name.trim()} onClick={saveEdit}>{t("ph.save")}</button>
              <button className="btn" onClick={() => setEditing(null)}>{t("common.cancel")}</button>
            </div>
          </div>
        </section>
      )}

      {/* ---------------- apply ---------------- */}
      {applying && (
        <section className="panel" style={{ borderColor: "var(--accent)" }}>
          <div className="panel-header"><h2>{t("packs.apply_title", { name: applying.name })}</h2></div>
          <div className="panel-body ag-stack">
            <p className="hint-text ag-small">{t(applying.kind === "profile" ? "packs.apply_profile_hint" : "packs.apply_guard_hint")}</p>
            <div className="field" style={{ maxWidth: 420 }}><label>{t("packs.apply_to")}</label>
              <select value={targetKey(target)} onChange={(e) => {
                const x = targets.find((y) => y.key === e.target.value);
                if (x) setTarget(x.target);
              }}>
                {targets.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
              </select></div>
            {preview ? (
              <>
                <div className="ag-label">{t("packs.what_changes")}</div>
                <Changes changes={preview.changes} />
                {preview.skipped.length > 0 && (
                  <p className="hint-text ag-small">{t("packs.skipped", { fields: preview.skipped.map((f) => t(`ph.field.${f}`, f)).join(", ") })}</p>
                )}
                <p className="hint-text ag-small">{t("packs.signed_note")}</p>
              </>
            ) : <p className="hint-text ag-small">{t("common.loading")}</p>}
            <div className="ag-actions">
              <button className="btn btn-primary" disabled={busy || !preview || preview.changes.length === 0} onClick={apply}>{t("packs.apply")}</button>
              <button className="btn" onClick={() => setApplying(null)}>{t("common.cancel")}</button>
            </div>
          </div>
        </section>
      )}

      {/* ---------------- undo ---------------- */}
      {undoing && (
        <section className="panel" style={{ borderColor: "var(--risk-medium)" }}>
          <div className="panel-header"><h2>{t("packs.undo_title", { name: undoing.application.pack_name })}</h2></div>
          <div className="panel-body ag-stack">
            <p className="hint-text ag-small">{t(undoing.application.kind === "profile" ? "packs.undo_profile_hint" : "packs.undo_guard_hint",
              { level: labelOf(undoing.application.scope, undoing.application.target_id) })}</p>
            <div className="ag-label">{t("packs.what_changes")}</div>
            <Changes changes={undoing.changes} />
            {undoing.edited_since && (
              undoing.application.kind === "profile" ? (
                <label className="ag-small" style={{ color: "var(--risk-medium)" }}>
                  <input type="checkbox" checked={confirmEdited} onChange={(e) => setConfirmEdited(e.target.checked)} /> {t("packs.edited_since_profile")}
                </label>
              ) : <p className="hint-text ag-small">{t("packs.edited_since_guard")}</p>
            )}
            <p className="hint-text ag-small">{t("packs.undo_signed_note")}</p>
            <div className="ag-actions">
              <button className="btn btn-primary" disabled={busy || (undoing.edited_since && undoing.application.kind === "profile" && !confirmEdited)}
                onClick={undo}>{t("packs.undo")}</button>
              <button className="btn" onClick={() => setUndoing(null)}>{t("common.cancel")}</button>
            </div>
          </div>
        </section>
      )}

      {/* ---------------- applied ---------------- */}
      <section className="panel">
        <div className="panel-header"><h2>{t("packs.applied_title")} <span className="tab-badge">{active.length}</span></h2></div>
        <div className="ag-table-wrap">
          {apps.length === 0 ? <p className="hint-text panel-body">{t("packs.nothing_applied")}</p> : (
            <table className="table-cards">
              <tbody>
                {apps.slice(0, 50).map((a) => (
                  <tr key={a.id} style={a.undone_at ? { opacity: 0.55 } : undefined}>
                    <td data-label={t("packs.pack")}><strong>{a.pack_name}</strong> <span className="pill pill-neutral">{t(`packs.kind_${a.kind}`)}</span></td>
                    <td data-label={t("packs.level")}>{labelOf(a.scope, a.target_id)}</td>
                    <td data-label={t("packs.when")} className="hint-text ag-small">
                      {a.applied_at ? new Date(a.applied_at).toLocaleString() : ""}
                      {a.undone_at && <> · {t("packs.undone_at", { when: new Date(a.undone_at).toLocaleString() })}</>}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      {isAdmin && !a.undone_at && <button className="btn btn-sm" onClick={() => startUndo(a)}>{t("packs.undo")}</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      {/* ---------------- the packs ---------------- */}
      {groups.map((g) => (
        <section className="panel" key={g.kind}>
          <div className="panel-header"><h2>{g.title}</h2></div>
          <div className="panel-body ag-stack">
            <p className="hint-text ag-small">{g.hint}</p>
            {all.filter((p) => p.kind === g.kind).map((p) => (
              <div key={p.ref} style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                <div className="u-flex u-justify-between u-items-center" style={{ gap: 12, flexWrap: "wrap" }}>
                  <div>
                    <strong>{p.name}</strong>{" "}
                    <span className={`pill ${p.builtin ? "pill-neutral" : "pill-accent"}`}>{p.builtin ? t("packs.builtin") : t("packs.own")}</span>{" "}
                    <span className="pill pill-neutral">{t(`packs.level_${p.level}`)}</span>
                    {p.description && <div className="hint-text ag-small">{p.description}</div>}
                  </div>
                  <div className="ag-actions">
                    <button className="btn btn-sm" onClick={() => setOpen(open === p.ref ? null : p.ref)}>{open === p.ref ? t("packs.hide") : t("packs.view")}</button>
                    <button className="btn btn-sm" onClick={() => download(p)}>{t("packs.download")}</button>
                    {isAdmin && <button className="btn btn-sm" onClick={() => startEdit(p, true)}>{t("packs.copy")}</button>}
                    {isAdmin && !p.builtin && <button className="btn btn-sm" onClick={() => startEdit(p)}>{t("packs.edit")}</button>}
                    {isAdmin && !p.builtin && <button className="btn btn-sm" onClick={() => remove(p)}>{t("packs.delete")}</button>}
                    {isAdmin && <button className="btn btn-sm btn-primary" onClick={() => startApply(p)}>{t("packs.apply")}</button>}
                  </div>
                </div>
                {open === p.ref && <pre className="mono ag-wrap ag-small" style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>{p.yaml}</pre>}
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
