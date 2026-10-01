"use client";

import Link from "next/link";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth";
import {
  OBS_EVENT_TYPES,
  getBreakdown,
  getObsEvents,
  getObsSummary,
  getTimeseries,
  obsError,
  openObsStream,
  revealEvent,
  type Breakdown,
  type ObsDim,
  type ObsEvent,
  type ObsEventType,
  type ObsMetric,
  type ObsSummary,
  type StreamState,
  type Timeseries,
} from "@/lib/observability_api";

/* ------------------------------------------------------------------ palette */
// Categorical slots (dark steps, validated against the panel surface #25262e):
// assigned to a key the first time it is seen and kept, so a colour follows
// its entity, never its rank. Decisions and statuses use fixed meanings.
const SLOTS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"];
const OTHER = "#69707d";
const FIXED: Record<string, string> = {
  allowed: "#199e70", completed: "#199e70", accepted: "#199e70", verified: "#199e70",
  denied: "#e66767", blocked: "#e66767", rejected: "#e66767", unverified: "#e66767",
  pending_approval: "#c98500", quarantined: "#c98500", rate_limited: "#c98500",
  filtered: "#d95926", failed: "#d55181", other: OTHER,
  "action.checked": "#3987e5", "action.recorded": "#9085e9", "llm.call": "#199e70",
  "a2a.message": "#c98500", "delegation.hop": "#d55181", "incident.created": "#e66767",
};
const slotOf = new Map<string, string>();
function colorFor(dim: string, key: string): string {
  if (FIXED[key]) return FIXED[key];
  const id = `${dim}:${key}`;
  if (!slotOf.has(id)) {
    const used = Array.from(slotOf.keys()).filter((k) => k.startsWith(`${dim}:`)).length;
    slotOf.set(id, SLOTS[used % SLOTS.length]);
  }
  return slotOf.get(id)!;
}

const WINDOWS = [15, 60, 360, 1440, 10080];
const TERM_MAX = 2000;
const fmtWin = (m: number) => (m < 60 ? `${m}m` : m < 1440 ? `${m / 60}h` : `${m / 1440}d`);
const fmtNum = (v: number | null | undefined) =>
  v == null ? "—" : v >= 1e6 ? `${(v / 1e6).toFixed(1)}M` : v >= 1e4 ? `${(v / 1e3).toFixed(1)}k` : `${Math.round(v * 10) / 10}`;
const fmtTime = (iso: string, minutes: number) => {
  const d = new Date(iso);
  return minutes > 1440
    ? d.toLocaleDateString(undefined, { day: "2-digit", month: "2-digit" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit" })
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", ...(minutes <= 15 ? { second: "2-digit" } : {}) });
};

const CSS = `
.obsk { --bg:#1d1e24; --panel:#25262e; --border:#343741; --grid:#343741; --text:#dfe5ef; --muted:#98a2b3; --dim:#69707d;
  background:var(--bg); color:var(--text); min-height:100vh; padding:16px; font-size:13px; }
.obsk a { color:#6aa9ff; }
.obsk .bar { display:flex; gap:12px; align-items:center; flex-wrap:wrap; background:var(--panel); border:1px solid var(--border);
  border-radius:6px; padding:10px 14px; margin-bottom:12px; }
.obsk h1 { font-size:20px; font-weight:600; margin:0 12px 0 0; color:var(--text); }
.obsk h2 { font-size:17px; font-weight:600; margin:18px 0 10px; color:var(--text); }
.obsk .btn { background:#2f3038; color:var(--text); border:1px solid var(--border); border-radius:4px; padding:4px 10px; cursor:pointer; font-size:12px; }
.obsk .btn.on { background:#1e5bb8; border-color:#1e5bb8; color:#fff; }
.obsk select, .obsk input[type=text] { background:#1d1e24; color:var(--text); border:1px solid var(--border); border-radius:4px; padding:4px 8px; font-size:12px; width:auto; }
.obsk .grid { display:grid; grid-template-columns:repeat(12, minmax(0,1fr)); gap:12px; }
.obsk .p { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:12px 14px; min-width:0; }
.obsk .pt { font-weight:600; font-size:12px; margin-bottom:8px; font-family:ui-monospace,Menlo,Consolas,monospace; color:#e6ebf2; }
.obsk .kpi .v { font-size:24px; font-weight:700; }
.obsk .kpi .l { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }
.obsk .kpi .s { color:var(--muted); font-size:11px; }
.obsk .lg { width:100%; border-collapse:collapse; font-size:12px; }
.obsk .lg td { padding:3px 4px; border-bottom:1px solid #2c2d35; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:170px; color:var(--text); }
.obsk .lg tr { cursor:pointer; }
.obsk .lg tr.off td { opacity:.35; }
.obsk .ax { position:absolute; font-size:11px; color:var(--muted); white-space:nowrap; pointer-events:none; line-height:14px; }
.obsk .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; vertical-align:middle; }
.obsk .tip { position:absolute; pointer-events:none; background:#000000d9; border:1px solid var(--border); border-radius:4px; padding:6px 8px;
  font-size:11px; z-index:5; white-space:nowrap; color:var(--text); }
.obsk table.t { width:100%; border-collapse:collapse; font-size:12px; }
.obsk table.t th { text-align:left; color:var(--muted); font-weight:500; padding:4px 6px; border-bottom:1px solid var(--border); background:transparent; }
.obsk table.t td { padding:5px 6px; border-bottom:1px solid #2c2d35; color:var(--text); }
.obsk .pill { border-radius:3px; padding:1px 6px; font-size:11px; font-family:ui-monospace,Menlo,Consolas,monospace; }
.obsk .term { background:#0c0c0c; border:1px solid var(--border); border-radius:6px; font-family:ui-monospace,"Cascadia Mono",Menlo,Consolas,monospace;
  font-size:12px; line-height:1.5; color:#cccccc; height:560px; overflow:auto; padding:8px 10px; }
.obsk .term .ln { white-space:pre-wrap; word-break:break-word; }
.obsk .term .ln:hover { background:#1a1a1a; }
.obsk .term .c { color:#8b949e; padding-left:22px; white-space:pre-wrap; word-break:break-word; }
.obsk .term .raw { color:#ffcf70; padding-left:12px; white-space:pre-wrap; word-break:break-word; border-left:2px solid #c98500; margin:2px 0 4px 22px; }
.obsk .term .lk { color:#58a6ff; cursor:pointer; margin-left:8px; }
@media (max-width: 900px) { .obsk .grid > * { grid-column: span 12 !important; } }
`;

/* ------------------------------------------------------------------ charts */

type LabelFn = (dim: string, key: string) => string;

function Legend({ items, hidden, toggle }: {
  items: { key: string; label: string; color: string; total: number }[];
  hidden: Set<string>;
  toggle: (k: string) => void;
}) {
  return (
    <table className="lg">
      <tbody>
        {items.map((i) => (
          <tr key={i.key} className={hidden.has(i.key) ? "off" : ""} onClick={() => toggle(i.key)} title={i.label}>
            <td><span className="dot" style={{ background: i.color }} />{i.label}</td>
            <td style={{ textAlign: "right", fontWeight: 600 }}>{fmtNum(i.total)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TimeChart({ title, ts, label, height = 190, legendRight = true, unit }: {
  title: string;
  ts: Timeseries | null;
  label: LabelFn;
  height?: number;
  legendRight?: boolean;
  unit?: string;
}) {
  const { t } = useTranslation();
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const stacked = ts ? ts.metric !== "p95_ms" : true;
  const series = useMemo(() => (ts?.series ?? []).filter((s) => !hidden.has(s.key)), [ts, hidden]);
  const n = ts?.buckets.length ?? 0;
  const max = useMemo(() => {
    let m = 0;
    for (let i = 0; i < n; i++) {
      if (stacked) m = Math.max(m, series.reduce((a, s) => a + s.values[i], 0));
      else for (const s of series) m = Math.max(m, s.values[i]);
    }
    return m || 1;
  }, [series, n, stacked]);
  const nice = useMemo(() => {
    const p = Math.pow(10, Math.floor(Math.log10(max)));
    const step = [1, 2, 2.5, 5, 10].map((k) => k * p).find((s) => max / s <= 4) ?? p * 10;
    return { top: Math.ceil(max / step) * step, step };
  }, [max]);

  // the SVG is stretched to the panel width; the y-axis gutter is plain HTML (GUTTER px)
  const W = 1000, H = height, padL = 0, padB = 20, padT = 8, GUTTER = 40;
  const plotW = W - 4, plotH = H - padB - padT;
  const bw = n ? plotW / n : 0;
  const y = (v: number) => padT + plotH - (v / nice.top) * plotH;
  const ticks: number[] = [];
  for (let v = 0; v <= nice.top + 1e-9; v += nice.step) ticks.push(v);
  // 5 time labels on the wide chart, 3 on the small ones so they never collide
  const xLabels = !n ? [] : legendRight ? [0, Math.floor(n / 4), Math.floor(n / 2), Math.floor((3 * n) / 4), n - 1] : [0, Math.floor(n / 2), n - 1];

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!n || !boxRef.current) return;
    const r = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = Math.min(n - 1, Math.max(0, Math.floor((px - padL) / bw)));
    const br = boxRef.current.getBoundingClientRect();
    setHover({ i, x: e.clientX - br.left, y: e.clientY - br.top });
  }

  const legendItems = ts ? ts.series.map((s) => ({ key: s.key, label: label(ts.dim, s.key), color: colorFor(ts.dim, s.key), total: s.total })) : [];
  return (
    <div className="p" style={{ height: "100%" }}>
      <div className="pt">{title}</div>
      <div style={{ display: legendRight ? "flex" : "block", gap: 12 }}>
        <div ref={boxRef} style={{ position: "relative", flex: 1, minWidth: 0, paddingLeft: ts && ts.series.length ? GUTTER : 0 }}>
          <div style={{ position: "relative" }}>
          {!ts || !ts.series.length ? (
            <div style={{ height: H, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--dim)" }}>
              {ts ? t("obs.no_data", "No data in this window") : t("common.loading", "Loading…")}
            </div>
          ) : (
            <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: "100%", height: H, display: "block" }}
              onMouseMove={onMove} onMouseLeave={() => setHover(null)} role="img" aria-label={title}>
              {ticks.map((v) => (
                <line key={v} x1={padL} x2={W} y1={y(v)} y2={y(v)} stroke="var(--grid)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
              ))}
              {stacked
                ? ts.buckets.map((_, i) => {
                    let acc = 0;
                    return series.map((s) => {
                      const v = s.values[i];
                      if (!v) return null;
                      const y1 = y(acc + v), y0 = y(acc);
                      acc += v;
                      return (
                        <rect key={`${s.key}${i}`} x={padL + i * bw + bw * 0.12} width={Math.max(1, bw * 0.76)} y={y1}
                          height={Math.max(0.5, y0 - y1 - 0.6)} fill={colorFor(ts.dim, s.key)} />
                      );
                    });
                  })
                : series.map((s) => (
                    <polyline key={s.key} fill="none" stroke={colorFor(ts.dim, s.key)} strokeWidth={2} vectorEffect="non-scaling-stroke"
                      points={s.values.map((v, i) => `${padL + i * bw + bw / 2},${y(v)}`).join(" ")} />
                  ))}
              {hover && (
                <line x1={padL + hover.i * bw + bw / 2} x2={padL + hover.i * bw + bw / 2} y1={padT} y2={padT + plotH}
                  stroke="#ffffff55" strokeWidth={1} vectorEffect="non-scaling-stroke" />
              )}
            </svg>
          )}
          {ts && ts.series.length > 0 && (
            <>
              {/* axis text as HTML: the SVG is stretched, text inside it would be distorted */}
              {ticks.map((v) => (
                <span key={`y${v}`} className="ax" style={{ left: -GUTTER, width: GUTTER - 6, textAlign: "right", top: y(v) - 7 }}>{fmtNum(v)}</span>
              ))}
              {xLabels.map((i, j) => (
                <span key={`x${i}`} className="ax" style={{
                  left: `${(100 * (padL + i * bw + bw / 2)) / W}%`, top: H - 16,
                  transform: j === 0 ? "none" : j === xLabels.length - 1 ? "translateX(-100%)" : "translateX(-50%)",
                }}>{fmtTime(ts.buckets[i], ts.window_minutes)}</span>
              ))}
            </>
          )}
          </div>
          {hover && ts && (
            <div className="tip" style={{ left: Math.max(0, Math.min(hover.x + 12, (boxRef.current?.clientWidth ?? 300) - 190)), top: Math.max(0, hover.y - 20) }}>
              <div style={{ marginBottom: 4, color: "var(--muted)" }}>{new Date(ts.buckets[hover.i]).toLocaleString()}</div>
              {series.filter((s) => s.values[hover.i]).map((s) => (
                <div key={s.key}>
                  <span className="dot" style={{ background: colorFor(ts.dim, s.key) }} />
                  {label(ts.dim, s.key)}: <b>{fmtNum(s.values[hover.i])}{unit ?? ""}</b>
                </div>
              ))}
              {!series.some((s) => s.values[hover.i]) && <div>0</div>}
            </div>
          )}
        </div>
        {legendItems.length > 0 && (
          <div style={{ width: legendRight ? 220 : "100%", maxHeight: legendRight ? H : 120, overflowY: "auto", marginTop: legendRight ? 0 : 8 }}>
            <Legend items={legendItems} hidden={hidden}
              toggle={(k) => setHidden((h) => { const s = new Set(h); if (s.has(k)) s.delete(k); else s.add(k); return s; })} />
          </div>
        )}
      </div>
    </div>
  );
}

function HBars({ title, bd, label }: { title: string; bd: Breakdown | null; label: LabelFn }) {
  const { t } = useTranslation();
  const rows = bd?.rows ?? [];
  const max = Math.max(1, ...rows.map((r) => r.total));
  const parts = Array.from(new Set(rows.flatMap((r) => Object.keys(r.parts))));
  return (
    <div className="p" style={{ height: "100%" }}>
      <div className="pt">{title}</div>
      {!bd || !rows.length ? (
        <div style={{ color: "var(--dim)", padding: "30px 0", textAlign: "center" }}>
          {bd ? t("obs.no_data", "No data in this window") : t("common.loading", "Loading…")}
        </div>
      ) : (
        <>
          {rows.map((r) => (
            <div key={r.key} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}
              title={parts.filter((p) => r.parts[p]).map((p) => `${label(bd.by, p)}: ${r.parts[p]}`).join(" · ")}>
              <span style={{ width: 150, textAlign: "right", fontFamily: "ui-monospace,Menlo,monospace", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {label(bd.dim, r.key)}
              </span>
              <div style={{ flex: 1, display: "flex", height: 12, gap: 2 }}>
                {parts.filter((p) => r.parts[p]).map((p) => (
                  <div key={p} style={{ width: `${(100 * r.parts[p]) / max}%`, background: colorFor(bd.by, p), borderRadius: 2 }} />
                ))}
              </div>
              <span style={{ width: 40, textAlign: "right" }}>{r.total}</span>
            </div>
          ))}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 8, color: "var(--muted)", fontSize: 11 }}>
            {parts.map((p) => <span key={p}><span className="dot" style={{ background: colorFor(bd.by, p) }} />{label(bd.by, p)}</span>)}
          </div>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ terminal */

type RawState = { label: string; text: string }[] | "loading" | { error: string };
const pad = (s: string, n: number) => (s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length));
const TAG: Record<ObsEventType, [string, string]> = {
  "action.checked": ["CHECK ", "#58a6ff"],
  "action.recorded": ["ACTION", "#bc8cff"],
  "llm.call": ["LLM   ", "#3fb950"],
  "a2a.message": ["A2A   ", "#d29922"],
  "delegation.hop": ["DELEG ", "#db61a2"],
  "incident.created": ["INCDNT", "#f85149"],
};
const VERDICT: Record<string, string> = {
  allowed: "#3fb950", completed: "#3fb950", accepted: "#3fb950", verified: "#3fb950",
  denied: "#f85149", blocked: "#f85149", rejected: "#f85149", failed: "#f85149", unverified: "#f85149",
  pending_approval: "#d29922", quarantined: "#d29922", rate_limited: "#d29922", filtered: "#d29922",
  critical: "#f85149", high: "#f0883e", medium: "#d29922", low: "#8b949e",
};

function lineParts(e: ObsEvent, name: (id?: number) => string): { text: string; color?: string }[] {
  const out: { text: string; color?: string }[] = [];
  const verdict = (s?: string) => {
    if (s) out.push({ text: ` ${s.toUpperCase()}`, color: VERDICT[s] ?? "#cccccc" });
  };
  switch (e.type) {
    case "action.checked":
      out.push({ text: e.tool ?? "?" }, { text: " →", color: "#8b949e" });
      verdict(e.decision);
      if (e.incident_type) out.push({ text: ` incident=${e.incident_type}`, color: "#f85149" });
      break;
    case "action.recorded":
      out.push({ text: `${e.tool ?? "?"} ${e.action_type ?? ""}` }, { text: " →", color: "#8b949e" });
      verdict(e.decision);
      if (e.duration_ms != null) out.push({ text: ` ${e.duration_ms}ms`, color: "#8b949e" });
      break;
    case "llm.call":
      out.push({ text: e.model ?? "?" });
      verdict(e.status);
      if (e.duration_ms != null) out.push({ text: ` ${e.duration_ms}ms`, color: "#8b949e" });
      if (e.prompt_tokens != null || e.completion_tokens != null)
        out.push({ text: ` tokens in=${e.prompt_tokens ?? 0} out=${e.completion_tokens ?? 0}`, color: "#8b949e" });
      if (e.flags?.length) out.push({ text: ` [${e.flags.join(", ")}]`, color: "#d29922" });
      break;
    case "a2a.message":
      out.push({ text: `→ ${name(e.to_agent_id)} ${e.message_type ?? ""}` });
      verdict(e.status);
      break;
    case "delegation.hop":
      out.push({ text: `→ ${name(e.to_agent_id)} depth=${e.depth ?? "?"}${e.capabilities?.length ? ` caps=${e.capabilities.join(",")}` : ""}` });
      verdict(e.verified ? "verified" : "unverified");
      break;
    case "incident.created":
      out.push({ text: e.incident_type ?? "?", color: "#f85149" });
      verdict(e.severity);
      break;
  }
  if (e.chain_id) out.push({ text: ` chain#${e.chain_id}`, color: "#6e7681" });
  if (e.guards?.length) out.push({ text: ` ${e.guards.join(" ")}`, color: "#f0883e" });
  return out;
}

function Terminal(props: {
  events: ObsEvent[];
  names: Map<number, string>;
  isAdmin: boolean;
  paused: boolean;
  setPaused: (p: boolean) => void;
  onClear: () => void;
  state: StreamState;
}) {
  const { events, names, isAdmin, paused, setPaused, onClear, state } = props;
  const { t } = useTranslation();
  const boxRef = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  const [search, setSearch] = useState("");
  const [showContent, setShowContent] = useState(true);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [raw, setRaw] = useState<Record<string, RawState>>({});
  const name = useCallback((id?: number) => (id == null ? "—" : names.get(id) ?? `#${id}`), [names]);

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return events;
    return events.filter((e) =>
      [name(e.agent_id), e.type, e.tool, e.model, e.decision, e.status, e.incident_type, ...(e.guards ?? []), ...(e.content ?? []).map((c) => c.text)]
        .some((x) => x != null && String(x).toLowerCase().includes(q)),
    );
  }, [events, search, name]);

  useEffect(() => {
    if (follow && boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [shown, follow, raw]);

  async function doReveal(e: ObsEvent) {
    const k = `${e.type}:${e.id}`;
    const cur = raw[k];
    if (cur && cur !== "loading") {
      setRaw((r) => { const n = { ...r }; delete n[k]; return n; });
      return;
    }
    const reason = window.prompt(t("obs.reveal_prompt", "Show this event WITHOUT PII masking? The request is recorded in the audit log. Reason:"), "");
    if (reason === null) return;
    setRaw((r) => ({ ...r, [k]: "loading" }));
    try {
      const content = await revealEvent(e.type, e.id, reason);
      setRaw((r) => ({ ...r, [k]: content }));
    } catch (err) {
      setRaw((r) => ({ ...r, [k]: { error: obsError(err, t("obs.reveal_failed", "Could not load the original.")) } }));
    }
  }

  function toggleOpen(k: string) {
    setOpen((o) => { const s = new Set(o); if (s.has(k)) s.delete(k); else s.add(k); return s; });
  }

  return (
    <div className="p">
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
        <span className="pt" style={{ margin: 0 }}>agent.activity.terminal</span>
        <span style={{ color: state === "live" ? "#3fb950" : "#d29922", fontSize: 12 }}>● {t(`obs.state_${state}`, state)}</span>
        <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("obs.grep", "grep…")} style={{ width: 200 }} />
        <button className={`btn${showContent ? " on" : ""}`} onClick={() => setShowContent(!showContent)}>{t("obs.show_content", "Content (masked)")}</button>
        <button className={`btn${follow ? " on" : ""}`} onClick={() => setFollow(!follow)}>{t("obs.follow", "Follow")}</button>
        <button className={`btn${paused ? " on" : ""}`} onClick={() => setPaused(!paused)}>{paused ? t("obs.resume", "Resume") : t("obs.pause", "Pause")}</button>
        <button className="btn" onClick={onClear}>{t("obs.clear", "Clear")}</button>
        <span style={{ color: "var(--muted)", fontSize: 11, marginLeft: "auto" }}>
          {shown.length}/{events.length} · {t("obs.pii_note", "PII masked; originals only on an admin's audited request")}
        </span>
      </div>
      <div className="term" ref={boxRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
          if (atBottom !== follow) setFollow(atBottom);
        }}>
        {shown.length === 0 && <div style={{ color: "#6e7681" }}>$ {t("obs.waiting", "waiting for agent activity…")}</div>}
        {shown.map((e) => {
          const k = `${e.type}:${e.id}`;
          const [tag, tagColor] = TAG[e.type] ?? [e.type, "#cccccc"];
          const d = new Date(e.ts);
          const stamp = `${d.toLocaleTimeString(undefined, { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`;
          const content = e.content ?? [];
          const isOpen = open.has(k);
          const r = raw[k];
          return (
            <div key={k}>
              <div className="ln">
                <span style={{ color: "#6e7681" }}>{stamp} </span>
                <span style={{ color: tagColor, fontWeight: 700 }}>{tag}</span>
                <span style={{ color: "#79c0ff" }}> {pad(name(e.agent_id), 20)} </span>
                {lineParts(e, name).map((p, i) => <span key={i} style={{ color: p.color }}>{p.text}</span>)}
                {showContent && content.some((c) => c.text.length > 240) && (
                  <span className="lk" onClick={() => toggleOpen(k)}>{isOpen ? "[−]" : "[+]"}</span>
                )}
                {isAdmin && content.length > 0 && (
                  <span className="lk" style={{ color: r && r !== "loading" ? "#ffcf70" : undefined }} onClick={() => doReveal(e)}
                    title={t("obs.reveal_hint", "Admins only. Recorded in the audit log.")}>
                    {r === "loading" ? "[…]" : r ? `[${t("obs.hide_raw", "hide original")}]` : `[${t("obs.show_raw", "original")}]`}
                  </span>
                )}
                {e.content_error && <span style={{ color: "#f85149" }}> [{t("obs.content_unavailable", "content unavailable")}]</span>}
              </div>
              {showContent && content.map((c, i) => (
                <div className="c" key={i}>
                  <span style={{ color: "#6e7681" }}>{pad(c.label, 12)}│ </span>
                  {isOpen || c.text.length <= 240 ? c.text : `${c.text.slice(0, 240)} …`}
                </div>
              ))}
              {r && r !== "loading" && !Array.isArray(r) && <div className="raw">{r.error}</div>}
              {Array.isArray(r) && (
                <div className="raw">
                  <div style={{ color: "#f0883e", fontWeight: 700 }}>⚠ {t("obs.unmasked", "UNMASKED — recorded in the audit log")}</div>
                  {r.length === 0 && <div>{t("obs.no_content", "no content stored for this event")}</div>}
                  {r.map((c, i) => <div key={i}><span style={{ color: "#c98500" }}>{pad(c.label, 12)}│ </span>{c.text}</div>)}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ page */

type Panel = { id: string; title: string; dim: ObsDim; metric: ObsMetric; unit?: string };
const PANELS: Panel[] = [
  { id: "type", title: "agent.events.count.timeseries", dim: "type", metric: "count" },
  { id: "decision", title: "agent.decisions.by_verdict", dim: "decision", metric: "count" },
  { id: "model", title: "llm.calls.by_model", dim: "model", metric: "count" },
  { id: "tokens", title: "llm.tokens.by_model", dim: "model", metric: "tokens" },
  { id: "latency", title: "llm.latency.p95_ms.by_model", dim: "model", metric: "p95_ms", unit: " ms" },
  { id: "llm_status", title: "llm.calls.by_status", dim: "llm_status", metric: "count" },
  { id: "agent", title: "agent.events.by_agent", dim: "agent", metric: "count" },
  { id: "guard", title: "guards.fired.timeline", dim: "guard", metric: "count" },
  { id: "a2a", title: "a2a.messages.by_status", dim: "a2a_status", metric: "count" },
  { id: "incident", title: "incidents.by_type", dim: "incident", metric: "count" },
];
const P = Object.fromEntries(PANELS.map((p) => [p.id, p])) as Record<string, Panel>;

export default function AgentObservabilityPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = (user?.role as string | undefined) === "admin";
  const [minutes, setMinutes] = useState(60);
  const [agentIds, setAgentIds] = useState<number[]>([]);
  const [types, setTypes] = useState<ObsEventType[]>([...OBS_EVENT_TYPES]);
  const [summary, setSummary] = useState<ObsSummary | null>(null);
  const [series, setSeries] = useState<Record<string, Timeseries>>({});
  const [tools, setTools] = useState<Breakdown | null>(null);
  const [term, setTerm] = useState<ObsEvent[]>([]);
  const [held, setHeld] = useState<ObsEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [stream, setStream] = useState<{ state: StreamState; detail?: string }>({ state: "connecting" });
  const [error, setError] = useState<string | null>(null);
  const [auto, setAuto] = useState(true);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const names = useMemo(() => new Map((summary?.agents ?? []).map((a) => [a.id, a.name])), [summary]);
  const label: LabelFn = useCallback(
    (dim, key) => {
      if (dim === "agent") return names.get(Number(key)) ?? `#${key}`;
      if (dim === "type") return t(`obs.type.${key.replace(".", "_")}`, key);
      if (key === "other") return t("obs.other", "other");
      return key;
    },
    [names, t],
  );
  const filters = useMemo(() => ({ agentIds, types }), [agentIds, types]);

  const load = useCallback(async () => {
    try {
      const [s, b, ...ts] = await Promise.all([
        getObsSummary(minutes, agentIds),
        getBreakdown("tool", "decision", minutes, agentIds),
        ...PANELS.map((p) => getTimeseries(p.dim, p.metric, minutes, agentIds)),
      ]);
      setSummary(s as ObsSummary);
      setTools(b as Breakdown);
      setSeries(Object.fromEntries(PANELS.map((p, i) => [p.id, ts[i] as Timeseries])));
      setError(null);
    } catch (e) {
      setError(obsError(e, t("obs.load_failed", "Could not load data.")));
    }
  }, [minutes, agentIds, t]);

  useEffect(() => {
    load();
    if (!auto) return;
    const id = setInterval(load, minutes <= 60 ? 10000 : 30000);
    return () => clearInterval(id);
  }, [load, auto, minutes]);

  // terminal: backfill + live stream with masked content; reopens when filters change
  useEffect(() => {
    let cancelled = false;
    setTerm([]);
    setHeld([]);
    getObsEvents(filters, 60, 200, true)
      .then((evs) => {
        if (cancelled) return;
        setTerm((cur) => {
          const seen = new Set(cur.map((e) => `${e.type}:${e.id}`));
          return [...evs.slice().reverse().filter((e) => !seen.has(`${e.type}:${e.id}`)), ...cur].slice(-TERM_MAX);
        });
      })
      .catch((e) => {
        if (!cancelled) setError(obsError(e, t("obs.load_failed", "Could not load data.")));
      });
    const close = openObsStream(
      filters,
      (events) => {
        if (pausedRef.current) setHeld((h) => [...h, ...events].slice(-TERM_MAX));
        else setTerm((cur) => [...cur, ...events].slice(-TERM_MAX));
      },
      (state, detail) => setStream({ state, detail }),
      true,
    );
    return () => {
      cancelled = true;
      close();
    };
  }, [filters, t]);

  function setPausedAndFlush(p: boolean) {
    if (!p) {
      setTerm((cur) => [...cur, ...held].slice(-TERM_MAX));
      setHeld([]);
    }
    setPaused(p);
  }

  function toggleAgent(id: number) {
    setAgentIds((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));
  }

  const tt = summary?.totals;
  const kpis: { l: string; v: React.ReactNode; s?: React.ReactNode; c?: string }[] = [
    { l: t("obs.k.events", "Events"), v: fmtNum(tt?.events), s: `${tt?.active_agents ?? "—"} ${t("obs.k.active_agents", "active agents")}` },
    { l: t("obs.k.decisions", "Decisions"), v: fmtNum(tt?.decisions), s: tt?.deny_rate != null ? `${tt.deny_rate}% ${t("obs.k.denied", "denied")}` : undefined },
    { l: t("obs.k.denied_n", "Denied"), v: fmtNum(tt?.denied), c: "#e66767" },
    { l: t("obs.k.pending", "Waiting for approval"), v: fmtNum(tt?.pending), c: "#c98500", s: <Link href="/agent-approvals">{t("obs.review", "review")} →</Link> },
    { l: t("obs.k.llm", "LLM calls"), v: fmtNum(tt?.llm_calls), s: tt ? `${tt.llm_errors} ${t("obs.k.errors", "blocked / failed")}` : undefined },
    { l: t("obs.k.tokens", "Tokens"), v: fmtNum(tt?.llm_tokens), s: tt?.llm_p95_ms != null ? `p95 ${Math.round(tt.llm_p95_ms)} ms` : undefined },
    { l: t("obs.k.incidents", "Incidents"), v: fmtNum(tt?.incidents), c: "#e66767", s: tt ? <Link href="/agent-incidents">{t("obs.open", "open")}: {tt.open_incidents} →</Link> : undefined },
    { l: t("obs.k.a2a", "A2A / delegations"), v: `${fmtNum(tt?.a2a_messages)} / ${fmtNum(tt?.delegations)}` },
  ];
  const chart = (id: string, opts: { height?: number; legendRight?: boolean } = {}) => (
    <TimeChart title={P[id].title} ts={series[id] ?? null} label={label} unit={P[id].unit} height={opts.height ?? 150}
      legendRight={opts.legendRight ?? false} />
  );

  return (
    <div className="obsk">
      <style>{CSS}</style>

      <div className="bar">
        <h1>{t("obs.title", "Agent observability")}</h1>
        <span style={{ color: stream.state === "live" ? "#3fb950" : "#d29922" }} title={stream.detail}>● {t(`obs.state_${stream.state}`, stream.state)}</span>
        <span style={{ display: "inline-flex", gap: 4 }}>
          {WINDOWS.map((m) => <button key={m} className={`btn${minutes === m ? " on" : ""}`} onClick={() => setMinutes(m)}>{fmtWin(m)}</button>)}
        </span>
        <button className={`btn${auto ? " on" : ""}`} onClick={() => setAuto(!auto)}>{t("obs.auto", "Auto-refresh")}</button>
        <select value="" onChange={(e) => { if (e.target.value) toggleAgent(Number(e.target.value)); }}>
          <option value="">{t("obs.add_agent", "Filter by agent…")}</option>
          {(summary?.agents ?? []).filter((a) => !agentIds.includes(a.id)).map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </select>
        {agentIds.map((id) => <button key={id} className="btn on" onClick={() => toggleAgent(id)}>{names.get(id) ?? `#${id}`} ✕</button>)}
        <span style={{ display: "inline-flex", gap: 8, flexWrap: "wrap", marginLeft: "auto" }}>
          {OBS_EVENT_TYPES.map((tp) => (
            <label key={tp} style={{ display: "inline-flex", gap: 4, alignItems: "center", fontSize: 12, cursor: "pointer" }}>
              <input type="checkbox" checked={types.includes(tp)}
                onChange={() => setTypes((c) => (c.includes(tp) ? (c.length > 1 ? c.filter((x) => x !== tp) : c) : [...c, tp]))} />
              <span className="dot" style={{ background: colorFor("type", tp) }} />{label("type", tp)}
            </label>
          ))}
        </span>
      </div>

      {error && <div className="p" style={{ borderColor: "#e66767", color: "#e66767", marginBottom: 12 }}>{error}</div>}

      <div className="grid" style={{ marginBottom: 12 }}>
        {kpis.map((k) => (
          <div key={k.l} className="p kpi" style={{ gridColumn: "span 3" }}>
            <div className="l">{k.l}</div>
            <div className="v" style={{ color: k.c }}>{k.v}</div>
            {k.s != null && <div className="s">{k.s}</div>}
          </div>
        ))}
      </div>

      <div className="grid">
        <div style={{ gridColumn: "span 8" }}>{chart("type", { height: 240, legendRight: true })}</div>
        <div style={{ gridColumn: "span 4" }}>{chart("decision", { height: 170 })}</div>
      </div>

      <h2>{t("obs.sec_llm", "LLM traffic")}</h2>
      <div className="grid">
        <div style={{ gridColumn: "span 4" }}>{chart("model")}</div>
        <div style={{ gridColumn: "span 4" }}>{chart("tokens")}</div>
        <div style={{ gridColumn: "span 4" }}>{chart("latency")}</div>
        <div style={{ gridColumn: "span 4" }}>{chart("llm_status")}</div>
        <div style={{ gridColumn: "span 8" }}><HBars title="agent.tools.by_verdict" bd={tools} label={label} /></div>
      </div>

      <h2>{t("obs.sec_agents", "Agents, guards and incidents")}</h2>
      <div className="grid">
        {["agent", "guard", "a2a", "incident"].map((id) => <div key={id} style={{ gridColumn: "span 3" }}>{chart(id, { height: 140 })}</div>)}
        <div className="p" style={{ gridColumn: "span 12", overflowX: "auto" }}>
          <div className="pt">agents.activity.table</div>
          <table className="t">
            <thead>
              <tr>
                <th>{t("obs.agent", "Agent")}</th>
                <th>{t("obs.status", "Status")}</th>
                <th style={{ textAlign: "right" }}>{t("obs.k.events", "Events")}</th>
                <th style={{ textAlign: "right" }}>{t("obs.k.decisions", "Decisions")}</th>
                <th style={{ textAlign: "right" }}>{t("obs.k.denied_n", "Denied")}</th>
                <th style={{ textAlign: "right" }}>{t("obs.k.llm", "LLM calls")}</th>
                <th style={{ textAlign: "right" }}>{t("obs.k.tokens", "Tokens")}</th>
                <th style={{ textAlign: "right" }}>{t("obs.k.incidents", "Incidents")}</th>
                <th style={{ textAlign: "right" }}>p95</th>
                <th style={{ textAlign: "right" }}>{t("obs.last_seen", "Last seen")}</th>
              </tr>
            </thead>
            <tbody>
              {(summary?.agents ?? [])
                .slice()
                .sort((a, b) => (b.last_seen ?? "").localeCompare(a.last_seen ?? "") || b.events - a.events)
                .map((a) => (
                  <tr key={a.id} style={{ cursor: "pointer", background: agentIds.includes(a.id) ? "#1e5bb833" : undefined }}
                    onClick={() => toggleAgent(a.id)} title={t("obs.click_filter", "Click to filter by this agent")}>
                    <td><span className="dot" style={{ background: colorFor("agent", String(a.id)) }} /><b>{a.name}</b> <span style={{ color: "var(--dim)" }}>{a.agent_type}</span></td>
                    <td>
                      <span className="pill" style={{ background: a.status === "active" ? "#199e7033" : "#e6676733", color: a.status === "active" ? "#3fb950" : "#f85149" }}>{a.status}</span>
                      {a.key_revoked && <span className="pill" style={{ background: "#e6676733", color: "#f85149", marginLeft: 4 }}>{t("obs.key_revoked", "key revoked")}</span>}
                    </td>
                    <td style={{ textAlign: "right" }}>{a.events}</td>
                    <td style={{ textAlign: "right" }}>{a.decisions}</td>
                    <td style={{ textAlign: "right", color: a.denied ? "#e66767" : undefined }}>{a.denied}</td>
                    <td style={{ textAlign: "right" }}>{a.llm_calls}</td>
                    <td style={{ textAlign: "right" }}>{fmtNum(a.llm_tokens)}</td>
                    <td style={{ textAlign: "right", color: a.incidents ? "#e66767" : undefined }}>{a.incidents}</td>
                    <td style={{ textAlign: "right" }}>{a.p95_ms != null ? `${Math.round(a.p95_ms)} ms` : "—"}</td>
                    <td style={{ textAlign: "right" }}>{a.last_seen ? new Date(a.last_seen).toLocaleTimeString() : "—"}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <h2>{t("obs.sec_terminal", "Live activity")}</h2>
      <Terminal events={term} names={names} isAdmin={isAdmin} paused={paused} setPaused={setPausedAndFlush}
        onClear={() => { setTerm([]); setHeld([]); }} state={stream.state} />
      {paused && held.length > 0 && (
        <div style={{ color: "var(--muted)", marginTop: 6 }}>{held.length} {t("obs.new", "new")} — {t("obs.paused_hint", "press Resume")}</div>
      )}
    </div>
  );
}
