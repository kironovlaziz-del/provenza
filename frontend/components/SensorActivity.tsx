"use client";

// The live activity window on the expanded sensor row: the last N
// violations the sensor reported, as a scrollable console.
//
// Only violations, not allowed traffic: the kernel writes to the ringbuf
// on a decision it refuses or observes; allowed connections leave no
// trace by design. The counters above give the allowed/denied/observed
// rates; this window is where you read the detail behind them.
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { listSensorViolations, type SensorT, type ViolationT } from "@/lib/egress_sensor_api";

const POLL_MS = 2000;
const MAX_ROWS = 500;

export function SensorActivity({ sensor }: { sensor: SensorT }) {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<ViolationT[]>([]);
  const [paused, setPaused] = useState(false);
  const [atBottom, setAtBottom] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  const load = useCallback(() => {
    listSensorViolations(sensor.id, 200)
      .then((incoming) => {
        // The API returns newest-first; the console reads oldest-first.
        const asc = [...incoming].reverse();
        setRows((prev) => {
          // Merge by id, drop rows that fell out of the API window.
          const seen = new Map<number, ViolationT>();
          for (const r of prev) seen.set(r.id, r);
          for (const r of asc) seen.set(r.id, r);
          const merged = [...seen.values()].sort((a, b) => a.id - b.id);
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
    // Rates need deltas; the backend does not keep history yet, so here
    // we show totals with the elapsed wall-clock since the sensor was
    // last seen. A small nudge that is honest about what we know.
    return {
      allowed: sensor.allowed_total ?? 0,
      denied: sensor.denied_total ?? 0,
      observed: sensor.observed_total ?? 0,
    };
  }, [sensor.allowed_total, sensor.denied_total, sensor.observed_total]);

  const fmt = (iso: string) => new Date(iso).toLocaleTimeString(i18n.language);

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
          rows.map((v) => (
            <div key={v.id} className="sensor-activity-line">
              <span className="t">{fmt(v.created_at)}</span>
              <span className={v.action === "blocked" ? "icon-deny" : v.action === "alerted" ? "icon-obs" : "icon-allow"}>
                {v.action === "blocked" ? "✕" : v.action === "alerted" ? "!" : "•"}
              </span>
              <span>
                {v.action} {v.kind}
                {v.protocol ? ` ${v.protocol}` : ""}
                {v.dst_name ? ` ${v.dst_name}` : ""}
                {v.dst_ip ? ` → ${v.dst_ip}${v.dst_port ? ":" + v.dst_port : ""}` : ""}
                {v.comm ? ` [${v.comm}]` : ""}
                {v.count > 1 ? ` ×${v.count}` : ""}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
