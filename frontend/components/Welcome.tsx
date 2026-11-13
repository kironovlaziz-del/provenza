"use client";

/**
 * The welcome page at /, for visitors who are not signed in: what Provenza
 * does, one agent call played step by step, and the way to sign in.
 *
 * Nothing on it comes from the server: the decisions, the actions and the
 * receipt are illustrations, so an anonymous visitor learns nothing about the
 * organizations here. Styles: app/welcome.css (black and white; only
 * transform and opacity move). The deep grid is drawn on a canvas, paused
 * while it is off screen or the tab is hidden; with "reduce motion" nothing
 * moves and the call shows its last step.
 */

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { SUPPORTED_LANGUAGES } from "@/lib/i18n";

const REPO = "https://github.com/kironovlaziz-del/provenza";
const STEPS = 8;
const STEP_MS = 1200;

type FeedEvent = { tag: string; kind: "solid" | "ghost" | "dash"; what: string; who: string };
type Problem = { title: string; problem: string; solution: string };
type Step = { title: string; text: string };

function reducedMotion(): boolean {
  return typeof window !== "undefined" && !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

/** Floor and ceiling of a grid running to a horizon, moving towards the viewer. */
function useDeepGrid(ref: React.RefObject<HTMLCanvasElement | null>) {
  useEffect(() => {
    const cv = ref.current;
    const ctx = cv?.getContext("2d");
    if (!cv || !ctx) return;
    const still = reducedMotion();
    let W = 1, H = 1, raf = 0, visible = true;
    const t0 = performance.now();

    const size = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const r = cv.getBoundingClientRect();
      W = Math.max(1, Math.round(r.width));
      H = Math.max(1, Math.round(r.height));
      cv.width = W * dpr;
      cv.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = (now: number) => {
      const hy = H * 0.5, cx = W / 2, f = 360, cam = 160;
      const gap = 120, rows = 18, cols = 16;
      const shift = still ? 0 : (((now - t0) / 1000) * 70) % gap;
      ctx.clearRect(0, 0, W, H);
      ctx.lineWidth = 1;
      for (const side of [1, -1]) {               // 1: floor, -1: ceiling
        const dim = side === 1 ? 1 : 0.55;
        for (let i = 0; i < rows; i++) {         // across, near to far
          const z = i * gap - shift + 40;
          if (z <= 20) continue;
          const y = hy + side * ((cam * f) / z);
          if (side === 1 ? y > H + 2 : y < -2) continue;
          if (Math.abs(y - hy) < 10) continue;    // lines packed at the horizon would shimmer
          const depth = 1 - z / (rows * gap);
          const a = depth * depth * 0.6 * dim * Math.min(1, (z - 20) / 80);
          ctx.strokeStyle = `rgba(255,255,255,${a.toFixed(3)})`;
          ctx.beginPath();
          ctx.moveTo(0, Math.round(y) + 0.5);
          ctx.lineTo(W, Math.round(y) + 0.5);
          ctx.stroke();
        }
        for (let j = -cols; j <= cols; j++) {     // along, to the vanishing point
          const x = j * gap, zn = 30, zf = rows * gap;
          const x1 = cx + (x * f) / zn, y1 = hy + (side * cam * f) / zn;
          const x2 = cx + (x * f) / zf, y2 = hy + (side * cam * f) / zf;
          const g = ctx.createLinearGradient(x1, y1, x2, y2);
          g.addColorStop(0, `rgba(255,255,255,${0.5 * dim})`);
          g.addColorStop(1, "rgba(255,255,255,0)");
          ctx.strokeStyle = g;
          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.lineTo(x2, y2);
          ctx.stroke();
        }
      }
      const hg = ctx.createLinearGradient(0, 0, W, 0);
      hg.addColorStop(0, "rgba(255,255,255,0)");
      hg.addColorStop(0.5, "rgba(255,255,255,.55)");
      hg.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = hg;
      ctx.fillRect(0, Math.round(hy), W, 1);
      const v = ctx.createRadialGradient(cx, hy, 0, cx, hy, Math.max(W, H) * 0.7);
      v.addColorStop(0, "rgba(0,0,0,0.25)");
      v.addColorStop(0.55, "rgba(0,0,0,0.55)");
      v.addColorStop(1, "rgba(0,0,0,0.9)");
      ctx.fillStyle = v;
      ctx.fillRect(0, 0, W, H);
    };

    const loop = (now: number) => { draw(now); raf = requestAnimationFrame(loop); };
    const start = () => { if (!raf && !still) raf = requestAnimationFrame(loop); };
    const stop = () => { if (raf) cancelAnimationFrame(raf); raf = 0; };
    const onResize = () => { size(); draw(performance.now()); };
    const onVisibility = () => (document.hidden ? stop() : visible && start());

    size();
    draw(performance.now());
    window.addEventListener("resize", onResize);
    document.addEventListener("visibilitychange", onVisibility);
    let io: IntersectionObserver | null = null;
    if ("IntersectionObserver" in window) {
      io = new IntersectionObserver((es) => {
        visible = es[0]?.isIntersecting ?? true;
        if (visible && !document.hidden) start(); else stop();
      });
      io.observe(cv);
    } else start();
    return () => {
      stop();
      io?.disconnect();
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [ref]);
}

/** Adds wl-in to every .wl-rv inside root once it scrolls into view. */
function useReveal(root: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    const items = Array.from(root.current?.querySelectorAll(".wl-rv") ?? []);
    if (reducedMotion() || !("IntersectionObserver" in window)) {
      items.forEach((e) => e.classList.add("wl-in"));
      return;
    }
    const io = new IntersectionObserver((es) => {
      es.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add("wl-in"); io.unobserve(e.target); }
      });
    }, { threshold: 0.12 });
    items.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [root]);
}

/** The call: eight steps, a pause, then the other scenario. */
type Call = { mode: "allow" | "deny"; step: number; hold: number };
const HOLD = 3; // ticks the last step stays before the other scenario

export function nextCall(c: Call): Call {
  if (c.step < STEPS - 1) return { ...c, step: c.step + 1 };
  if (c.hold < HOLD) return { ...c, hold: c.hold + 1 };
  return { mode: c.mode === "allow" ? "deny" : "allow", step: 0, hold: 0 };
}

function useCall() {
  const [call, setCall] = useState<Call>({ mode: "allow", step: 0, hold: 0 });

  useEffect(() => {
    if (reducedMotion()) { setCall((c) => ({ ...c, step: STEPS - 1 })); return; }
    const id = window.setInterval(() => { if (!document.hidden) setCall(nextCall); }, STEP_MS);
    return () => window.clearInterval(id);
  }, []);

  const choose = (mode: "allow" | "deny") => setCall({ mode, step: reducedMotion() ? STEPS - 1 : 0, hold: 0 });
  return { mode: call.mode, step: call.step, choose };
}

function Mark() {
  return (
    <svg width="30" height="30" viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <g stroke="#fff" strokeWidth="1.3" opacity=".45">
        <line x1="10" y1="14" x2="24" y2="24" /><line x1="38" y1="14" x2="24" y2="24" /><line x1="10" y1="34" x2="24" y2="24" />
      </g>
      <circle cx="10" cy="14" r="2.6" fill="#fff" /><circle cx="38" cy="14" r="2.6" fill="#fff" /><circle cx="10" cy="34" r="2.6" fill="#fff" />
      <circle cx="24" cy="24" r="9" stroke="#fff" strokeWidth="2" />
      <path d="M19.5 24 L22.5 27 L29 20" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Welcome() {
  const { t, i18n } = useTranslation();
  const root = useRef<HTMLDivElement>(null);
  const grid = useRef<HTMLCanvasElement>(null);
  useDeepGrid(grid);
  useReveal(root);
  const { mode, step, choose } = useCall();
  const deny = mode === "deny";

  const list = <T,>(key: string): T[] => {
    const v = t(key, { returnObjects: true });
    return Array.isArray(v) ? (v as T[]) : [];
  };
  const events = list<FeedEvent>("welcome.events");
  const facts = list<string>("welcome.facts");
  const problems = list<Problem>("welcome.problems");
  const steps = list<Step>("welcome.steps");
  const caps = list<string>("welcome.caps");
  const caption =
    step === 4 ? t(deny ? "welcome.cap5_no" : "welcome.cap5_ok")
    : step === 5 ? t(deny ? "welcome.cap6_no" : "welcome.cap6_ok")
    : caps[step] ?? "";

  const check = (at: number, bad: boolean) =>
    "wl-chk" + (step >= at ? (bad ? " wl-no" : " wl-ok") : "") + (step === at - 1 ? " wl-now" : "");
  const checkMark = (at: number, bad: boolean) => (step >= at ? (bad ? "✕" : "✓") : "");
  const reached = step >= 5;

  return (
    <div className="wl" ref={root}>
      <div className="wl-hero">
        <canvas className="wl-grid" ref={grid} aria-hidden="true" />

        <header className="wl-header">
          <div className="wl-wrap wl-bar">
            <a className="wl-brand" href="#top" aria-label="Provenza"><Mark /><span>provenza</span></a>
            <nav className="wl-nav">
              <a className="wl-plain" href="#how">{t("welcome.nav_how")}</a>
              <a className="wl-plain" href="#why">{t("welcome.nav_why")}</a>
              <a className="wl-plain" href={REPO}>{t("welcome.github")}</a>
              <select className="wl-lang" aria-label="Language" value={i18n.language.split("-")[0]}
                onChange={(e) => i18n.changeLanguage(e.target.value)}>
                {SUPPORTED_LANGUAGES.map((l) => <option key={l.code} value={l.code}>{l.label}</option>)}
              </select>
              <Link className="wl-btn wl-btn-white wl-btn-sm" href="/login">{t("welcome.sign_in")}</Link>
            </nav>
          </div>
        </header>

        <div id="top" className="wl-wrap wl-hero-in">
          <div className="wl-hero-text">
            <span className="wl-pill wl-eyebrow"><span className="wl-dot" />{t("welcome.eyebrow")}</span>
            <h1>{t("welcome.title_a")} <span className="wl-soft">{t("welcome.title_b")}</span></h1>
            <p className="wl-lead">{t("welcome.lead")}</p>
            <div className="wl-row" style={{ marginTop: 6 }}>
              <Link className="wl-btn wl-btn-white" href="/login">{t("welcome.cta_sign_in")}</Link>
              <a className="wl-btn wl-btn-line" href="#how">{t("welcome.cta_see")}</a>
            </div>
          </div>

          <div className="wl-feed-card">
            <div className="wl-feed-head">
              <span className="wl-eyebrow" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                <span className="wl-dot" />{t("welcome.feed_title")}
              </span>
              <span style={{ fontSize: 11, color: "var(--wl-dim)" }}>{t("welcome.feed_example")}</span>
            </div>
            <div className="wl-feed">
              <div className="wl-feed-track">
                {[...events, ...events].map((e, i) => (
                  <div className="wl-ev" key={i} aria-hidden={i >= events.length || undefined}>
                    <span className={`wl-tag wl-tag-${e.kind}`}>{e.tag}</span>
                    <div className="wl-ev-t"><b>{e.what}</b><span>{e.who}</span></div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="wl-facts">
        <div className="wl-marq">
          {[...facts, ...facts].map((f, i) => (
            <span className="wl-fact" key={i} aria-hidden={i >= facts.length || undefined}>{f}</span>
          ))}
        </div>
      </div>

      <section id="how" className="wl-block">
        <div className="wl-wrap">
          <h2 className="wl-rv">{t("welcome.how_title")}</h2>
          <p className="wl-sub wl-rv">{t("welcome.how_sub")}</p>

          <div className="wl-demo wl-rv">
            <div className="wl-demo-top">
              <div className="wl-eyebrow">{t(deny ? "welcome.scenario_deny" : "welcome.scenario_allow")}</div>
              <div className="wl-seg" role="group" aria-label={t("welcome.scenario")}>
                <button type="button" aria-pressed={!deny} onClick={() => choose("allow")}>{t("welcome.btn_allow")}</button>
                <button type="button" aria-pressed={deny} onClick={() => choose("deny")}>{t("welcome.btn_deny")}</button>
              </div>
            </div>
            <div className="wl-prog"><i style={{ transform: `scaleX(${(step + 1) / STEPS})` }} /></div>

            <div className="wl-pipe">
              <div className="wl-node wl-on">
                <div className="wl-k">{t("welcome.agent_k")}</div>
                <div className="wl-n">claude-code@laptop</div>
                <div className="wl-d">{t("welcome.agent_d")}</div>
                <div className="wl-code">tools/call deepwiki.ask_wiki_question</div>
              </div>
              <div className="wl-link"><div className={"wl-wire" + (step >= 1 ? " wl-on" : "")}><i /></div></div>
              <div className={"wl-node" + (step >= 1 ? " wl-on" : "")}>
                <div className="wl-k">{t("welcome.gate_k")}</div>
                <div className={check(2, false)}><span className="wl-m">{checkMark(2, false)}</span><span>{t("welcome.chk_sig")}</span></div>
                <div className={check(3, false)}><span className="wl-m">{checkMark(3, false)}</span><span>{t("welcome.chk_rights")}</span></div>
                <div className={check(4, deny)}>
                  <span className="wl-m">{checkMark(4, deny)}</span>
                  <span>{step >= 4 ? t(deny ? "welcome.chk_policy_no" : "welcome.chk_policy_ok") : t("welcome.chk_policy")}</span>
                </div>
              </div>
              <div className="wl-link"><div className={"wl-wire" + (reached ? (deny ? " wl-cut" : " wl-on") : "")}><i /></div></div>
              <div className={"wl-node" + (reached ? (deny ? " wl-off" : " wl-on") : "")}>
                <div className="wl-k">{t("welcome.tool_k")}</div>
                <div className="wl-n">DeepWiki</div>
                <div className="wl-d">{t("welcome.tool_d")}</div>
                <div className={"wl-status" + (reached ? (deny ? " wl-no" : " wl-ok") : "")}>
                  {reached ? t(deny ? "welcome.tool_no" : "welcome.tool_ok") : t("welcome.waiting")}
                </div>
              </div>
            </div>

            <div className="wl-row2">
              <div className={"wl-strip" + (step >= 6 ? " wl-on" : "")}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="8.5" y="14" width="7" height="7" rx="1.5" />
                  <path d="M10 6.5h4M6.5 10v2.5h5.5V14M17.5 10v2.5H12" />
                </svg>
                <div style={{ minWidth: 0 }}>
                  <div className="wl-h">{t("welcome.audit_h")}</div>
                  <div className="wl-v">{step >= 6 ? t(deny ? "welcome.audit_no" : "welcome.audit_ok") : t("welcome.audit_wait")}</div>
                </div>
              </div>
              <div className={"wl-strip" + (step >= 7 ? " wl-on" : "")}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" /><path d="M8.5 12l2.5 2.5 4.5-5" />
                </svg>
                <div style={{ minWidth: 0 }}>
                  <div className="wl-h">{t("welcome.receipt_h")}</div>
                  <div className="wl-v">{step >= 7 ? t(deny ? "welcome.receipt_no" : "welcome.receipt_ok") : t("welcome.receipt_wait")}</div>
                </div>
              </div>
            </div>

            <p className="wl-cap" aria-live="polite"><span className="wl-no-n">{step + 1}/{STEPS}</span>{caption}</p>
          </div>
        </div>
      </section>

      <section id="why" className="wl-block">
        <div className="wl-wrap">
          <h2 className="wl-rv">{t("welcome.why_title")}</h2>
          <p className="wl-sub wl-rv">{t("welcome.why_sub")}</p>
          <div className="wl-grid3">
            {problems.map((p, i) => (
              <article className="wl-card wl-rv" key={i}>
                <div className="wl-orb" aria-hidden="true">
                  <div className="wl-orb-r" /><div className="wl-orb-s" style={{ animationDuration: `${4 + i}s` }}><i /></div>
                  <div className="wl-orb-c">0{i + 1}</div>
                </div>
                <span className="wl-eyebrow">{t("welcome.problem")}</span>
                <h3>{p.title}</h3>
                <p className="wl-prob">{p.problem}</p>
                <hr />
                <span className="wl-eyebrow wl-with">{t("welcome.with")}</span>
                <p>{p.solution}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="wl-block">
        <div className="wl-wrap">
          <h2 className="wl-rv">{t("welcome.steps_title")}</h2>
          <div className="wl-grid4">
            {steps.map((s, i) => (
              <div className="wl-step wl-rv" key={i}>
                <span className="wl-num">0{i + 1}</span>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="wl-block" style={{ paddingTop: 0, borderTop: 0 }}>
        <div className="wl-wrap">
          <div className="wl-cta wl-rv">
            <div>
              <h2>{t("welcome.cta_title")}</h2>
              <p className="wl-sub" style={{ marginTop: 6 }}>{t("welcome.cta_text")}</p>
            </div>
            <div className="wl-row">
              <Link className="wl-btn wl-btn-white" href="/login">{t("welcome.sign_in")}</Link>
              <a className="wl-btn wl-btn-line" href={`${REPO}/blob/main/docs/quickstart.md`}>{t("welcome.cta_install")}</a>
            </div>
          </div>
        </div>
      </section>

      <footer className="wl-footer">
        <div className="wl-wrap">
          <span>Provenza · Apache-2.0</span>
          <a href={REPO}>{t("welcome.footer_source")}</a>
          <a href={`${REPO}/blob/main/docs/security-model.md`}>{t("welcome.footer_security")}</a>
        </div>
      </footer>
    </div>
  );
}
