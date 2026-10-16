"use client";

// The live activity window on the expanded sensor row.
//
// Two streams arrive here and are merged into one chronological feed:
//   - violations: what the kernel refused or observed (EV_VIOLATION)
//   - activity:   sampled allowed connects (EV_ALLOWED), every Nth one
//
// The kernel still writes allowed traffic to the ringbuf only on a
// sample, so the window is not a packet log: it is enough to see the
// shape of what a workload does, without the volume of every connect.
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  listSensorActivity,
  listSensorViolations,
  type ActivityT,
  type SensorT,
  type ViolationT,
} from "@/lib/egress_sensor_api";

const POLL_MS = 2000;
const MAX_ROWS = 500;

// A row is either a violation or a sampled allowed connect. The two come
// from different tables, so their ids collide; key is namespaced.
type Row =
  | { kind: "violation"; key: string; id: number; ts: string; data: ViolationT }
  | { kind: "activity"; key: string; id: number; ts: string; data: ActivityT };

function rowFromViolation(v: ViolationT): Row {
  return { kind: "violation", key: `vio-${v.id}`, id: v.id, ts: v.created_at, data: v };
}

function rowFromActivity(a: ActivityT): Row {
  return { kind: "activity", key: `act-${a.id}`, id: a.id, ts: a.created_at, data: a };
}

export function SensorActivity({ sensor }: { sensor: SensorT }) {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<Row[]>([]);
  const [paused, setPaused] = useState(false);
  const [atBottom, setAtBottom] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  const load = useCallback(() => {
    Promise.all([
      listSensorViolations(sensor.id, 200),
      listSensorActivity(sensor.id, 200),
    ])
      .then(([vios, acts]) => {
        setRows((prev) => {
          // Merge by key, dropping rows that fell out of either API window.
          const seen = new Map<string, Row>();
          for (const r of prev) seen.set(r.key, r);
          for (const v of vios) {
            const r = rowFromViolation(v);
            seen.set(r.key, r);
          }
          for (const a of acts) {
            const r = rowFromActivity(a);
            seen.set(r.key, r);
          }
          // The console reads oldest-first.
          const merged = [...seen.values()].sort((x, y) => {
            if (x.ts < y.ts) return -1;
            if (x.ts > y.ts) return 1;
            return x.key.localeCompare(y.key);
          });
          return merged.length > MAX_ROWS ? merged.slice(merged.length - MAX_ROWS) : merged;
        });
        setError(null);
      })
      .catch((err) => setError(String(err)));
  }, [sensor.id]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (paused) return;
    const id = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(id);
  }, [paused, load]);

  // Auto-scroll only when the user is already at the bottom. Scrolling up
  // is treated as "I am reading history" and stops the scroll; scrolling
  // back down resumes it. This is the standard console behaviour.
  useEffect(() => {
    if (!atBottom || paused) return;
    const box = boxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [rows, atBottom, paused]);

  function onScroll() {
    const box = boxRef.current;
    if (!box) return;
    const near = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
    setAtBottom(near);
  }

  function jumpToLatest() {
    const box = boxRef.current;
    if (!box) return;
    box.scrollTop = box.scrollHeight;
    setAtBottom(true);
    setPaused(false);
  }

  const counters = useMemo(() => {
    return {
      allowed: sensor.allowed_total ?? 0,
      denied: sensor.denied_total ?? 0,
      observed: sensor.observed_total ?? 0,
    };
  }, [sensor.allowed_total, sensor.denied_total, sensor.observed_total]);

  const fmt = (iso: string) => new Date(iso).toLocaleTimeString(i18n.language);

  function iconFor(action: string): { cls: string; glyph: string } {
    if (action === "blocked") return { cls: "icon-deny", glyph: "✕" };
    if (action === "alerted") return { cls: "icon-obs", glyph: "!" };
    if (action === "allowed") return { cls: "icon-allow", glyph: "✓" };
    return { cls: "icon-obs", glyph: "•" };
  }

  function describeRow(r: Row): string {
    const d = r.data;
    const parts: string[] = [];
    parts.push(d.action);
    parts.push(d.kind);
    if (d.protocol) parts.push(d.protocol);
    if (d.dst_name) parts.push(d.dst_name);
    if (d.dst_ip) parts.push(`→ ${d.dst_ip}${d.dst_port ? ":" + d.dst_port : ""}`);
    if (d.comm) parts.push(`[${d.comm}]`);
    if (d.count > 1) parts.push(`×${d.count}`);
    return parts.join(" ");
  }

  return (
    <div>
      <div className="sensor-activity-counters">
        <span className="allow">
          <span className="num">{counters.allowed.toLocaleString()}</span>{" "}
          <span className="lbl">{t("rt.sensors.counter_allowed")}</span>
        </span>
        <span className="deny">
          <span className="num">{counters.denied.toLocaleString()}</span>{" "}
          <span className="lbl">{t("rt.sensors.counter_denied")}</span>
        </span>
        <span className="obs">
          <span className="num">{counters.observed.toLocaleString()}</span>{" "}
          <span className="lbl">{t("rt.sensors.counter_observed")}</span>
        </span>
      </div>

      <div className="sensor-activity-controls">
        <button className="btn btn-sm" onClick={() => setPaused(p => !p)}>
          {paused ? t("rt.sensors.act_resume") : t("rt.sensors.act_pause")}
        </button>
        <button className="btn btn-sm" onClick={() => setRows([])}>
          {t("rt.sensors.act_clear")}
        </button>
        {!atBottom && !paused && (
          <button className="btn btn-sm btn-primary" onClick={jumpToLatest}>
            {t("rt.sensors.act_latest")}
          </button>
        )}
        {error && <span style={{ color: "var(--danger, #c0392b)" }}>{error}</span>}
      </div>

      <div className="sensor-activity" ref={boxRef} onScroll={onScroll}>
        {rows.length === 0 ? (
          <div className="sensor-activity-empty">{t("rt.sensors.act_none")}</div>
        ) : (
          rows.map((r) => {
            const { cls, glyph } = iconFor(r.data.action);
            return (
              <div key={r.key} className="sensor-activity-line">
                <span className="t">{fmt(r.ts)}</span>
                <span className={cls}>{glyph}</span>
                <span>{describeRow(r)}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
