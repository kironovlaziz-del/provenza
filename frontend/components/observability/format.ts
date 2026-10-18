// Number and duration formatting shared by the monitoring panels.

export function fmtNumber(v: number | null | undefined, digits = 0): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  return v.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: 0 });
}

/** A rate per second, with as many decimals as small values need. */
export function fmtRate(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  if (v === 0) return "0";
  if (v < 0.1) return v.toLocaleString(undefined, { maximumSignificantDigits: 2 });
  if (v < 10) return v.toLocaleString(undefined, { maximumFractionDigits: 2 });
  return v.toLocaleString(undefined, { maximumFractionDigits: 0 });
}

export function fmtPercent(v: number | null | undefined): string {
  if (v === null || v === undefined || !Number.isFinite(v)) return "—";
  if (v === 0) return "0 %";
  if (v < 0.1) return "<0.1 %";
  return `${v.toLocaleString(undefined, { maximumFractionDigits: 1 })} %`;
}

/** Seconds as milliseconds or seconds, e.g. 0.0123 -> "12 ms". */
export function fmtLatency(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const ms = seconds * 1000;
  if (ms < 10) return `${ms.toLocaleString(undefined, { maximumFractionDigits: 1 })} ms`;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toLocaleString(undefined, { maximumFractionDigits: 2 })} s`;
}

/** An age in seconds as "12 s", "4 min", "3 h 5 min", "2 d". */
export function fmtAge(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
  return `${Math.floor(h / 24)} d`;
}

export function fmtClock(ts: number, withDate = false): string {
  const d = new Date(ts * 1000);
  return withDate
    ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
