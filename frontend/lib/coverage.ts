// Protection coverage (backend app/services/coverage.py): which sentence
// explains an item's state. The facts are the ones the server judged on.

export type CoverageState = "ok" | "attention" | "missing";

export interface CoverageItem {
  key: string;
  state: CoverageState;
  href: string;
  optional: boolean;
  facts: Record<string, number | boolean | null>;
}

export interface CoverageSummary {
  ok: number;
  attention: number;
  missing: number;
  needs_action: number;
}

/** The i18n key (under "coverage.") of the sentence that says why, and its values. */
export function evidence(item: CoverageItem): { key: string; values: Record<string, unknown> } {
  const f = item.facts;
  const base = `${item.key}.`;
  if (item.state === "ok" || item.state === "missing") return { key: base + item.state, values: f };
  switch (item.key) {
    case "signed_policy":
      if (f.problem) return { key: base + "attention_problem", values: f };
      if (f.draft != null) return { key: base + "attention_draft", values: f };
      return { key: base + "attention_unsigned", values: { ...f, count: f.unsigned } };
    case "proxy":
      if (!f.policy) return { key: base + "attention_policy", values: f };
      return { key: base + "attention_offline", values: f };
    default:
      return { key: base + "attention", values: f };
  }
}

/** The i18n key (under "coverage.") of how to fix it: a sensor that is set up but
 * offline, reporting errors or only observing needs another step than one never
 * registered. */
export function fixKey(item: CoverageItem): string {
  const f = item.facts;
  if (item.key === "sensors" && item.state === "attention") {
    if (Number(f.online) < Number(f.total)) return "sensors.fix_offline";
    if (Number(f.problems) > 0) return "sensors.fix_errors";
    return "sensors.fix_enforce";
  }
  return `${item.key}.fix`;
}

/** The dashboard shows coverage when something that was set up stopped working. */
export function needsDashboard(summary: CoverageSummary | undefined): boolean {
  return !!summary && summary.attention > 0;
}

/** The top bar's one word on the protection (simple mode): something that was
 * set up stopped working; a required part is not set up yet; or every required
 * part works. Optional parts that were never set up do not count. */
export type ProtectionState = "attention" | "setup" | "ok";

export function protectionState(summary: CoverageSummary): ProtectionState {
  if (summary.attention > 0) return "attention";
  if (summary.needs_action > 0) return "setup";
  return "ok";
}
