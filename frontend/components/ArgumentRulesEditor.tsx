"use client";

// Argument rules - WHAT a tool may be called with (OWASP Agentic ASI02;
// backend/app/services/argument_rules.py). Used by the Agent Policies rule
// builder and by the policy hierarchy's form (tools.arguments).

import React from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";

export type ArgOp =
  | "equals" | "in" | "not_in" | "max" | "min" | "max_length"
  | "starts_with" | "domain_in" | "matches" | "not_matches";
export type ArgEffect = "deny" | "require_approval";

export interface ArgRule {
  tool: string;
  arg: string;
  op: ArgOp;
  value: unknown;
  effect?: ArgEffect;
}

export interface ArgRow {
  tool: string;
  arg: string;
  op: ArgOp;
  value: string; // edited as text, converted on emit
  effect: ArgEffect;
}

export const ARG_OPS: ArgOp[] = [
  "not_matches", "matches", "domain_in", "starts_with", "max", "min", "max_length", "in", "not_in", "equals",
];
const LIST_OPS = new Set<ArgOp>(["in", "not_in", "starts_with", "domain_in"]);
const NUMERIC_OPS = new Set<ArgOp>(["max", "min", "max_length"]);

const ARG_PRESETS: { key: string; row: ArgRow }[] = [
  {
    key: "read_only_sql",
    row: { tool: "db.query", arg: "sql", op: "not_matches",
           value: "(?i)\\b(drop|delete|truncate|alter|update|insert|grant)\\b", effect: "deny" },
  },
  { key: "corp_email", row: { tool: "email.send", arg: "to", op: "domain_in", value: "corp.example", effect: "deny" } },
  { key: "sandbox_files", row: { tool: "file.*", arg: "path", op: "starts_with", value: "/sandbox/", effect: "deny" } },
  { key: "payment_limit", row: { tool: "payments.*", arg: "amount", op: "max", value: "100", effect: "require_approval" } },
];

export const EMPTY_ARG_ROW: ArgRow = { tool: "", arg: "", op: "not_matches", value: "", effect: "deny" };

function toList(s: string): string[] {
  return s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
}

function argValue(row: ArgRow): unknown | undefined {
  const text = row.value.trim();
  if (!text) return undefined;
  if (LIST_OPS.has(row.op)) {
    const list = toList(text);
    return list.length ? list : undefined;
  }
  if (NUMERIC_OPS.has(row.op)) {
    const n = Number(text);
    return Number.isFinite(n) ? n : undefined;
  }
  if (row.op === "equals" && /^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  return text;
}

/** A row as the rule the server stores, or null while it is incomplete. */
export function argRuleFromRow(r: ArgRow): ArgRule | null {
  const v = argValue(r);
  if (!r.tool.trim() || !r.arg.trim() || v === undefined) return null;
  return { tool: r.tool.trim(), arg: r.arg.trim(), op: r.op, value: v, effect: r.effect };
}

export function argRowFromRule(rule: unknown): ArgRow | null {
  if (!rule || typeof rule !== "object") return null;
  const r = rule as Record<string, unknown>;
  return {
    tool: String(r.tool ?? ""),
    arg: String(r.arg ?? ""),
    op: (ARG_OPS.includes(r.op as ArgOp) ? r.op : "equals") as ArgOp,
    value: Array.isArray(r.value) ? r.value.join(", ") : String(r.value ?? ""),
    effect: r.effect === "require_approval" ? "require_approval" : "deny",
  };
}

/** Whether the form can show these rules without changing them (a value such
 *  as `in: [1, 2]` or `equals: true` would come back as text). */
export function rowsRoundTrip(rules: unknown[]): boolean {
  return rules.every((rule) => {
    const row = argRowFromRule(rule);
    const back = row && argRuleFromRow(row);
    const r = rule as Record<string, unknown>;
    return !!back && JSON.stringify(back) === JSON.stringify({ ...r, effect: r.effect ?? "deny" });
  });
}

/** One rule in a line: "payments.* · amount ≤ 100 → approval". */
export function argRuleText(rule: unknown, t: TFunction): string {
  const r = (rule ?? {}) as Record<string, unknown>;
  const value = Array.isArray(r.value) ? r.value.join(", ") : String(r.value);
  const effect = r.effect === "require_approval" ? t("rulebuilder.effect_require_approval") : t("rulebuilder.effect_deny");
  return `${String(r.tool)} · ${String(r.arg)} ${t(`rulebuilder.op_${String(r.op)}`, String(r.op))} ${value} → ${effect}`;
}

export function ArgumentRulesEditor({ rows, onChange, disabled = false }: {
  rows: ArgRow[]; onChange: (rows: ArgRow[]) => void; disabled?: boolean;
}) {
  const { t } = useTranslation();
  const update = (i: number, patch: Partial<ArgRow>) => onChange(rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));

  return (
    <div>
      <strong style={{ fontSize: 14 }}>🎯 {t("rulebuilder.args_title", "Argument constraints")}</strong>
      <p className="hint-text" style={{ fontSize: 12, margin: "4px 0 10px" }}>
        {t("rulebuilder.args_hint",
          "Limit WHAT a tool may be called with. A missing argument counts as a violation; for lists every element must comply.")}
      </p>

      {rows.map((row, i) => (
        <div key={i} style={{ border: "1px solid var(--border,#e5e7eb)", borderRadius: 8, padding: 12, marginBottom: 10 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 8 }}>
            <div className="field" style={{ margin: 0 }}>
              <label>{t("rulebuilder.args_tool", "Tool")}</label>
              <input value={row.tool} disabled={disabled} placeholder="db.query, payments.*"
                onChange={(e) => update(i, { tool: e.target.value })} />
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label>{t("rulebuilder.args_arg", "Argument")}</label>
              <input value={row.arg} disabled={disabled} placeholder="sql, to, options.cc"
                onChange={(e) => update(i, { arg: e.target.value })} />
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label>{t("rulebuilder.args_op", "Must")}</label>
              <select value={row.op} disabled={disabled} onChange={(e) => update(i, { op: e.target.value as ArgOp })}>
                {ARG_OPS.map((op) => <option key={op} value={op}>{t(`rulebuilder.op_${op}`, op)}</option>)}
              </select>
            </div>
            <div className="field" style={{ margin: 0, gridColumn: "span 2" }}>
              <label>{t("rulebuilder.args_value", "Value")}</label>
              <input value={row.value} disabled={disabled} placeholder={t(`rulebuilder.ph_op_${row.op}`, "")}
                onChange={(e) => update(i, { value: e.target.value })}
                className={row.op === "matches" || row.op === "not_matches" ? "mono" : undefined} />
            </div>
            <div className="field" style={{ margin: 0 }}>
              <label>{t("rulebuilder.args_effect", "Otherwise")}</label>
              <select value={row.effect} disabled={disabled} onChange={(e) => update(i, { effect: e.target.value as ArgEffect })}>
                <option value="deny">{t("rulebuilder.effect_deny", "Deny")}</option>
                <option value="require_approval">{t("rulebuilder.effect_require_approval", "Require approval")}</option>
              </select>
            </div>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 6, gap: 8 }}>
            {argRuleFromRow(row) === null
              ? <span className="error-text" style={{ fontSize: 12 }}>{t("rulebuilder.args_incomplete")}</span>
              : <span className="hint-text" style={{ fontSize: 12 }}>{t(`rulebuilder.hint_op_${row.op}`, "")}</span>}
            {!disabled && (
              <button type="button" className="btn btn-sm" style={{ padding: "2px 8px" }}
                aria-label={t("rulebuilder.args_remove")} onClick={() => onChange(rows.filter((_, idx) => idx !== i))}>
                ✕
              </button>
            )}
          </div>
        </div>
      ))}

      {!disabled && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          <button type="button" className="btn btn-sm" onClick={() => onChange([...rows, { ...EMPTY_ARG_ROW }])}>
            + 🎯 {t("rulebuilder.args_add", "Add constraint")}
          </button>
          {ARG_PRESETS.map((p) => (
            <button key={p.key} type="button" className="btn btn-sm" onClick={() => onChange([...rows, { ...p.row }])}>
              + {t(`rulebuilder.preset_${p.key}`, p.key)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
