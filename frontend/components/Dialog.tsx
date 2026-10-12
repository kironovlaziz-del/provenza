"use client";

// Confirmation and input dialogs in the app's own style, instead of the
// browser's window.confirm / window.prompt:
//
//   const { dialog, confirm, prompt } = useDialog();
//   if (await confirm(t("x.confirm_delete", { name }), { danger: true })) ...
//   const reason = await prompt(t("x.reason")); // null when cancelled
//   ... return <>{dialog}...</>
//
// Or, anywhere (DialogHost is mounted once in app/(app)/layout.tsx):
//   if (!(await confirmDialog(message))) return;
//   const reason = await promptDialog(message);

import React, { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

interface Pending {
  kind: "confirm" | "prompt";
  message: string;
  danger?: boolean;
  confirmLabel?: string;
  resolve: (value: string | boolean | null) => void;
}

export function useDialog() {
  const { t } = useTranslation();
  const [pending, setPending] = useState<Pending | null>(null);
  const [text, setText] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);
  const okRef = useRef<HTMLButtonElement | null>(null);

  const confirm = useCallback(
    (message: string, opts: { danger?: boolean; confirmLabel?: string } = {}) =>
      new Promise<boolean>((resolve) =>
        setPending({ kind: "confirm", message, ...opts, resolve: (v) => resolve(v === true) })),
    [],
  );
  const prompt = useCallback(
    (message: string, opts: { confirmLabel?: string; defaultValue?: string } = {}) =>
      new Promise<string | null>((resolve) => {
        setText(opts.defaultValue ?? "");
        setPending({ kind: "prompt", message, ...opts, resolve: (v) => resolve(typeof v === "string" ? v : null) });
      }),
    [],
  );

  const close = useCallback((value: string | boolean | null) => {
    setPending((p) => {
      p?.resolve(value);
      return null;
    });
  }, []);

  useEffect(() => {
    if (!pending) return;
    (pending.kind === "prompt" ? inputRef.current : okRef.current)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close(pending.kind === "prompt" ? null : false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pending, close]);

  const dialog = pending ? (
    <div className="dialog-backdrop" onMouseDown={() => close(pending.kind === "prompt" ? null : false)}>
      <div className="dialog" role="dialog" aria-modal="true" onMouseDown={(e) => e.stopPropagation()}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            close(pending.kind === "prompt" ? text : true);
          }}
        >
          <p className="dialog-message">{pending.message}</p>
          {pending.kind === "prompt" && (
            <input ref={inputRef} value={text} onChange={(e) => setText(e.target.value)} maxLength={2000} />
          )}
          <div className="u-btn-row dialog-actions">
            <button type="button" className="btn btn-sm" onClick={() => close(pending.kind === "prompt" ? null : false)}>
              {t("common.cancel")}
            </button>
            <button ref={okRef} type="submit" className={`btn btn-sm ${pending.danger ? "btn-danger" : "btn-primary"}`}>
              {pending.confirmLabel ?? t("common.confirm")}
            </button>
          </div>
        </form>
      </div>
    </div>
  ) : null;

  return { dialog, confirm, prompt };
}

// ---------------------------------------------------------------- global

type HostRequest =
  | { kind: "confirm"; message: string; opts: { danger?: boolean; confirmLabel?: string }; resolve: (v: boolean) => void }
  | { kind: "prompt"; message: string; opts: { confirmLabel?: string; defaultValue?: string }; resolve: (v: string | null) => void };

let host: ((r: HostRequest) => void) | null = null;

/** A confirmation in the app's style; falls back to the browser's if no host is mounted. */
export function confirmDialog(message: string, opts: { danger?: boolean; confirmLabel?: string } = {}): Promise<boolean> {
  return new Promise((resolve) => (host ? host({ kind: "confirm", message, opts, resolve }) : resolve(window.confirm(message))));
}

/** Asks for a line of text; null when cancelled. */
export function promptDialog(message: string, defaultValue = ""): Promise<string | null> {
  return new Promise((resolve) =>
    host ? host({ kind: "prompt", message, opts: { defaultValue }, resolve }) : resolve(window.prompt(message, defaultValue)));
}

export function DialogHost() {
  const { dialog, confirm, prompt } = useDialog();
  useEffect(() => {
    host = (r) => {
      if (r.kind === "confirm") confirm(r.message, r.opts).then(r.resolve);
      else prompt(r.message, r.opts).then(r.resolve);
    };
    return () => {
      host = null;
    };
  }, [confirm, prompt]);
  return dialog;
}
