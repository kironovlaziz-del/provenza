"use client";

import React, { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";

// The agent policy engine understands these rule keys (see
// agent_policy_engine.evaluate_custom_rule). Each builder row maps to one
// of them. The builder is the friendly face; the JSON it produces is
// exactly what the backend already consumes.
type RuleKind = "deny_tools" | "allow_only_tools" | "require_approval_tools" | "deny_action_types";

interface Row {
  kind: RuleKind;
  values: string; // comma-separated, edited as text
}

// what each rule does, in plain words (translated)
const RULE_META: { kind: RuleKind; icon: string }[] = [
  { kind: "deny_tools", icon: "🚫" },
  { kind: "require_approval_tools", icon: "⏸️" },
  { kind: "allow_only_tools", icon: "✅" },
  { kind: "deny_action_types", icon: "⛔" },
];

// ---- ASI02: argument rules (see backend/app/services/argument_rules.py) ----
type ArgOp =
  | "equals" | "in" | "not_in" | "max" | "min" | "max_length"
  | "starts_with" | "domain_in" | "matches" | "not_matches";
type ArgEffect = "deny" | "require_approval";

const ARG_OPS: ArgOp[] = [
  "not_matches", "matches", "domain_in", "starts_with", "max", "min", "max_length", "in", "not_in", "equals",
];
const LIST_OPS = new Set<ArgOp>(["in", "not_in", "starts_with", "domain_in"]);
const NUMERIC_OPS = new Set<ArgOp>(["max", "min", "max_length"]);

interface ArgRow {
  tool: string;
  arg: string;
  op: ArgOp;
  value: string; // edited as text, converted on emit
  effect: ArgEffect;
}

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

function argRowFromRule(rule: any): ArgRow | null {
  if (!rule || typeof rule !== "object") return null;
  return {
    tool: String(rule.tool ?? ""),
    arg: String(rule.arg ?? ""),
    op: (ARG_OPS.includes(rule.op) ? rule.op : "equals") as ArgOp,
    value: Array.isArray(rule.value) ? rule.value.join(", ") : String(rule.value ?? ""),
    effect: rule.effect === "require_approval" ? "require_approval" : "deny",
  };
}

/**
 * Emits a rules object like
 * { deny_tools: [...], require_approval_tools: [...], argument_rules: [...] }.
 * Value is controlled by the parent so it can also show/round-trip raw JSON.
 */
export function AgentRuleBuilder({
  value,
  onChange,
}: {
  value: Record<string, unknown>;
  onChange: (rules: Record<string, unknown>) => void;
}) {
  const { t } = useTranslation();

  // hydrate rows from the incoming value once
  const [rows, setRows] = useState<Row[]>(() => {
    const initial: Row[] = [];
    for (const { kind } of RULE_META) {
      const v = value?.[kind];
      if (Array.isArray(v) && v.length) initial.push({ kind, values: v.join(", ") });
    }
    return initial;
  });

  const [argRows, setArgRows] = useState<ArgRow[]>(() => {
    const v = value?.argument_rules;
    return Array.isArray(v) ? (v.map(argRowFromRule).filter(Boolean) as ArgRow[]) : [];
  });

  useEffect(() => {
    const rules: Record<string, unknown> = {};
    for (const r of rows) {
      const list = toList(r.values);
      if (list.length) rules[r.kind] = list;
    }
    const argumentRules = argRows
      .map((r) => {
        const v = argValue(r);
        if (!r.tool.trim() || !r.arg.trim() || v === undefined) return null;
        return { tool: r.tool.trim(), arg: r.arg.trim(), op: r.op, value: v, effect: r.effect };
      })
      .filter(Boolean);
    if (argumentRules.length) rules.argument_rules = argumentRules;
    onChange(rules);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, argRows]);

  function addRow(kind: RuleKind) {
    setRows((rs) => [...rs, { kind, values: "" }]);
  }
  function updateRow(i: number, values: string) {
    setRows((rs) => rs.map((r, idx) => (idx === i ? { ...r, values } : r)));
  }
  function removeRow(i: number) {
    setRows((rs) => rs.filter((_, idx) => idx !== i));
  }
  function updateArgRow(i: number, patch: Partial<ArgRow>) {
    setArgRows((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  }

  const usedKinds = new Set(rows.map((r) => r.kind));

  return (
    <div>
      {rows.length === 0 && argRows.length === 0 && (
        <p className="hint-text" style={{ marginBottom: 12 }}>{t("rulebuilder.empty")}</p>
      )}

      {rows.map((row, i) => {
        const meta = RULE_META.find((m) => m.kind === row.kind)!;
        return (
          <div key={i} style={{ border: "1px solid var(--border,#e5e7eb)", borderRadius: 8, padding: 12, marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
              <strong style={{ fontSize: 14 }}>{meta.icon} {t(`rulebuilder.kind_${row.kind}`)}</strong>
              <button type="button" className="btn btn-sm" onClick={() => removeRow(i)} style={{ padding: "2px 8px" }}>✕</button>
            </div>
            <p className="hint-text" style={{ fontSize: 12, margin: "0 0 8px" }}>{t(`rulebuilder.hint_${row.kind}`)}</p>
            <input
              value={row.values}
              onChange={(e) => updateRow(i, e.target.value)}
              placeholder={t(`rulebuilder.ph_${row.kind}`)}
              style={{ width: "100%" }}
            />
          </div>
        );
      })}

      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 6 }}>
        {RULE_META.filter((m) => !usedKinds.has(m.kind)).map((m) => (
          <button key={m.kind} type="button" className="btn btn-sm" onClick={() => addRow(m.kind)}>
            + {m.icon} {t(`rulebuilder.kind_${m.kind}`)}
          </button>
        ))}
      </div>

      {/* ---- argument rules (ASI02) ---- */}
      <div style={{ marginTop: 20, borderTop: "1px solid var(--border,#e5e7eb)", paddingTop: 14 }}>
        <strong style={{ fontSize: 14 }}>🎯 {t("rulebuilder.args_title", "Argument constraints")}</strong>
        <p className="hint-text" style={{ fontSize: 12, margin: "4px 0 10px" }}>
          {t(
            "rulebuilder.args_hint",
            "Limit WHAT a tool may be called with. A missing argument counts as a violation; for lists every element must comply.",
          )}
        </p>

        {argRows.map((row, i) => (
          <div
            key={i}
            style={{ border: "1px solid var(--border,#e5e7eb)", borderRadius: 8, padding: 12, marginBottom: 10 }}
          >
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 8 }}>
              <div className="field" style={{ margin: 0 }}>
                <label>{t("rulebuilder.args_tool", "Tool")}</label>
                <input value={row.tool} placeholder="db.query, payments.*" onChange={(e) => updateArgRow(i, { tool: e.target.value })} />
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label>{t("rulebuilder.args_arg", "Argument")}</label>
                <input value={row.arg} placeholder="sql, to, options.cc" onChange={(e) => updateArgRow(i, { arg: e.target.value })} />
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label>{t("rulebuilder.args_op", "Must")}</label>
                <select value={row.op} onChange={(e) => updateArgRow(i, { op: e.target.value as ArgOp })}>
                  {ARG_OPS.map((op) => (
                    <option key={op} value={op}>{t(`rulebuilder.op_${op}`, op)}</option>
                  ))}
                </select>
              </div>
              <div className="field" style={{ margin: 0, gridColumn: "span 2" }}>
                <label>{t("rulebuilder.args_value", "Value")}</label>
                <input
                  value={row.value}
                  placeholder={t(`rulebuilder.ph_op_${row.op}`, "")}
                  onChange={(e) => updateArgRow(i, { value: e.target.value })}
                  className={row.op === "matches" || row.op === "not_matches" ? "mono" : undefined}
                />
              </div>
              <div className="field" style={{ margin: 0 }}>
                <label>{t("rulebuilder.args_effect", "Otherwise")}</label>
                <select value={row.effect} onChange={(e) => updateArgRow(i, { effect: e.target.value as ArgEffect })}>
                  <option value="deny">{t("rulebuilder.effect_deny", "Deny")}</option>
                  <option value="require_approval">{t("rulebuilder.effect_require_approval", "Require approval")}</option>
                </select>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 6 }}>
              <span className="hint-text" style={{ fontSize: 12 }}>{t(`rulebuilder.hint_op_${row.op}`, "")}</span>
              <button
                type="button"
                className="btn btn-sm"
                style={{ padding: "2px 8px" }}
                onClick={() => setArgRows((rs) => rs.filter((_, idx) => idx !== i))}
              >
                ✕
              </button>
            </div>
          </div>
        ))}

        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setArgRows((rs) => [...rs, { tool: "", arg: "", op: "not_matches", value: "", effect: "deny" }])}
          >
            + 🎯 {t("rulebuilder.args_add", "Add constraint")}
          </button>
          {ARG_PRESETS.map((p) => (
            <button key={p.key} type="button" className="btn btn-sm" onClick={() => setArgRows((rs) => [...rs, { ...p.row }])}>
              + {t(`rulebuilder.preset_${p.key}`, p.key)}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
