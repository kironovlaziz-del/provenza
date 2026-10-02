"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import * as d3 from "d3";
import { useTranslation } from "react-i18next";
import { getGovernanceGraph, getHopVerification, type HopVerification } from "@/lib/agent_api";
import { downloadEvidence, SCHEME_HYBRID, verifyEvidence, type VerifyResult } from "@/lib/ed25519_verify";
import type { GraphNodeT, GraphEdgeT } from "@/lib/agent_types";

// d3 mutates node/link objects with x/y/vx/vy; extend the API types.
interface SimNode extends GraphNodeT {
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}
interface SimLink extends GraphEdgeT {
  source: SimNode | number;
  target: SimNode | number;
}

const POLL_MS = 5000;

// Dark-theme palette: brighter, slightly neon colors that glow on the
// dark canvas.
const COL = {
  active: "#3b82f6",      // bright blue
  violation: "#ef4444",   // bright red
  tripped: "#f59e0b",     // amber - halted by the circuit breaker
  suspended: "#64748b",   // slate
  retired: "#475569",
  verifiedEdge: "#22c55e", // green
  particle: "#4ade80",
  edge: "#64748b",
  text: "#e2e8f0",
};

function nodeColor(n: SimNode): string {
  if (n.has_violation) return COL.violation;
  if (n.status === "suspended") return COL.suspended;
  if (n.status === "retired") return COL.retired;
  return COL.active;
}

export function DelegationGraph({ height = 520 }: { height?: number }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const simRef = useRef<d3.Simulation<SimNode, SimLink> | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdgeT | null>(null);
  const [empty, setEmpty] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // keep latest data in refs so polling can diff without re-creating the sim
  const nodesRef = useRef<SimNode[]>([]);
  const linksRef = useRef<SimLink[]>([]);

  const draw = useCallback(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const width = wrapRef.current?.clientWidth || 800;

    const sel = d3.select(svg);
    sel.attr("viewBox", `0 0 ${width} ${height}`);

    // Ensure the zoom root + layer <g> containers exist exactly once.
    // Everything is drawn inside g.zoom-root so a single d3.zoom transform
    // pans/zooms the whole graph. Without the root, the layer selects
    // below match nothing and the graph renders empty.
    if (sel.select("g.zoom-root").empty()) {
      const root = sel.append("g").attr("class", "zoom-root");
      root.append("g").attr("class", "links");
      root.append("g").attr("class", "particles");
      root.append("g").attr("class", "nodes");

      const zoom = d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.3, 3])
        .on("zoom", (event) => {
          root.attr("transform", event.transform.toString());
        });
      sel.call(zoom as any);
      // double-click resets the view
      sel.on("dblclick.zoom", null).on("dblclick", () => {
        sel.transition().duration(400).call(zoom.transform as any, d3.zoomIdentity);
      });
    }

    // ---- links ----
    const linkSel = sel
      .select<SVGGElement>("g.links")
      .selectAll<SVGLineElement, SimLink>("line")
      .data(linksRef.current, (d: any) => d.id);

    linkSel.exit().remove();
    const linkEnter = linkSel
      .enter()
      .append("line")
      .attr("stroke-width", 2)
      .attr("cursor", "pointer")
      .on("click", (_evt, d) => setSelectedEdge(d as GraphEdgeT));
    linkEnter.merge(linkSel as any)
      .attr("stroke", (d) => (d.chain_status === "tripped" ? COL.tripped : d.is_violation ? COL.violation : d.verified ? COL.verifiedEdge : COL.edge))
      .attr("stroke-dasharray", (d) => (d.chain_status === "tripped" ? "2 4" : d.is_violation ? "6 4" : "none"))
      .attr("opacity", (d) => (d.chain_status === "terminated" ? 0.35 : 0.9));

    // ---- particles (one per active edge, animated along the line) ----
    const partSel = sel
      .select<SVGGElement>("g.particles")
      .selectAll<SVGCircleElement, SimLink>("circle")
      .data(
        linksRef.current.filter((l) => l.chain_status === "active" && !l.is_violation),
        (d: any) => d.id
      );
    partSel.exit().remove();
    partSel.enter().append("circle").attr("r", 3.5).attr("fill", COL.particle)
      .attr("filter", "drop-shadow(0 0 4px " + COL.particle + ")");

    // ---- nodes ----
    const nodeSel = sel
      .select<SVGGElement>("g.nodes")
      .selectAll<SVGGElement, SimNode>("g.node")
      .data(nodesRef.current, (d: any) => d.id);

    nodeSel.exit().remove();
    const nodeEnter = nodeSel.enter().append("g").attr("class", "node").attr("cursor", "grab");
    nodeEnter.append("circle").attr("r", 16).attr("filter", "url(#node-glow)");
    // pulse ring for active/busy nodes
    nodeEnter.append("circle").attr("class", "pulse").attr("r", 16).attr("fill", "none");
    nodeEnter
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 32)
      .attr("font-size", 11)
      .attr("font-weight", 500)
      .attr("fill", COL.text);

    const nodeMerge = nodeEnter.merge(nodeSel as any);
    nodeMerge.select("circle").attr("fill", (d) => nodeColor(d));
    nodeMerge.select("text").text((d) => d.name);
    nodeMerge
      .select<SVGCircleElement>("circle.pulse")
      .attr("stroke", (d) => nodeColor(d))
      .attr("stroke-width", 2)
      .attr("data-active", (d) => (d.action_count > 0 || d.has_violation ? "1" : "0"));

    // drag behaviour
    nodeMerge.call(
      d3
        .drag<SVGGElement, SimNode>()
        .on("start", (event, d) => {
          if (!event.active) simRef.current?.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on("drag", (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", (event, d) => {
          if (!event.active) simRef.current?.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }) as any
    );

    // ---- (re)build simulation ----
    if (!simRef.current) {
      simRef.current = d3
        .forceSimulation<SimNode>(nodesRef.current)
        .force("charge", d3.forceManyBody().strength(-160))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collide", d3.forceCollide(46))
        .force("x", d3.forceX(width / 2).strength(0.06))
        .force("y", d3.forceY(height / 2).strength(0.06))
        .force(
          "link",
          d3
            .forceLink<SimNode, SimLink>(linksRef.current)
            .id((d: any) => d.id)
            .distance(140)
        );
    } else {
      simRef.current.nodes(nodesRef.current);
      (simRef.current.force("link") as d3.ForceLink<SimNode, SimLink>).links(linksRef.current);
      // keep the centre in sync with the (possibly now-measured) width
      simRef.current.force("center", d3.forceCenter(width / 2, height / 2));
      simRef.current.alpha(0.6).restart();
    }

    simRef.current.on("tick", () => {
      const w = wrapRef.current?.clientWidth || 800;
      const r = 24; // keep nodes fully inside the viewport
      // clamp every node inside the box so nothing drifts off-screen
      for (const n of nodesRef.current) {
        if (n.x == null || n.y == null) continue;
        n.x = Math.max(r, Math.min(w - r, n.x));
        n.y = Math.max(r, Math.min(height - r, n.y));
      }
      sel
        .select("g.links")
        .selectAll<SVGLineElement, SimLink>("line")
        .attr("x1", (d) => (d.source as SimNode).x!)
        .attr("y1", (d) => (d.source as SimNode).y!)
        .attr("x2", (d) => (d.target as SimNode).x!)
        .attr("y2", (d) => (d.target as SimNode).y!);
      sel
        .select("g.nodes")
        .selectAll<SVGGElement, SimNode>("g.node")
        .attr("transform", (d) => `translate(${d.x},${d.y})`);
    });
  }, [height]);

  // particle animation loop (independent of the sim tick, time-based)
  useEffect(() => {
    let raf = 0;
    const animate = (t: number) => {
      const svg = svgRef.current;
      if (svg) {
        const phase = (t % 2000) / 2000; // 0..1 every 2s
        d3.select(svg)
          .select("g.particles")
          .selectAll<SVGCircleElement, SimLink>("circle")
          .each(function (d) {
            const s = d.source as SimNode;
            const tg = d.target as SimNode;
            if (s.x == null || tg.x == null) return;
            const x = s.x + (tg.x - s.x) * phase;
            const y = s.y! + (tg.y! - s.y!) * phase;
            d3.select(this).attr("cx", x).attr("cy", y);
          });
        // pulse rings - more pronounced for the dark theme
        const pulseR = 18 + Math.sin(t / 260) * 10;
        const pulseOp = 0.7 - (Math.sin(t / 260) + 1) * 0.3;
        d3.select(svg)
          .selectAll<SVGCircleElement, SimNode>("circle.pulse")
          .each(function () {
            const active = this.getAttribute("data-active") === "1";
            d3.select(this)
              .attr("r", active ? pulseR : 16)
              .attr("stroke-width", active ? 2.5 : 0)
              .attr("opacity", active ? Math.max(pulseOp, 0) : 0);
          });
      }
      raf = requestAnimationFrame(animate);
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, []);

  // data load + polling
  useEffect(() => {
    let stopped = false;
    async function load() {
      try {
        const g = await getGovernanceGraph();
        if (stopped) return;
        setError(null);
        setEmpty(g.nodes.length === 0);

        // merge: preserve x/y of existing nodes so the layout doesn't jump
        const prev = new Map(nodesRef.current.map((n) => [n.id, n]));
        nodesRef.current = g.nodes.map((n) => {
          const old = prev.get(n.id);
          return old ? Object.assign(old, n) : { ...n };
        });
        linksRef.current = g.edges.map((e) => ({
          ...e,
          source: e.from_agent_id,
          target: e.to_agent_id,
        })) as SimLink[];
        draw();
      } catch {
        if (!stopped) setError("Could not load the governance graph.");
      }
    }
    load();
    const iv = setInterval(load, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(iv);
      simRef.current?.stop();
    };
  }, [draw]);

  return (
    <div ref={wrapRef} style={{ position: "relative", width: "100%" }}>
      {error && <div className="error-text" style={{ padding: 12 }}>{error}</div>}
      {empty && !error && (
        <div className="hint-text" style={{ padding: 24, textAlign: "center" }}>
          No agents or delegations yet.
        </div>
      )}
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        style={{
          background: "radial-gradient(circle at 50% 40%, #1a2234 0%, #0b0f1a 100%)",
          borderRadius: 8,
          cursor: "grab",
        }}
      >
        <defs>
          <filter id="node-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
      </svg>
      {selectedEdge && (
        <EdgeInspector edge={selectedEdge} onClose={() => setSelectedEdge(null)} />
      )}
    </div>
  );
}

// Panel shown when an edge is clicked: capabilities + signature check in the
// browser. The browser verifies the signature over the exact signed bytes and
// computes the signer key fingerprint itself; independence from the server
// comes from comparing that fingerprint with the agent owner's.
function EdgeInspector({ edge, onClose }: { edge: GraphEdgeT; onClose: () => void }) {
  const { t } = useTranslation();
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [evidence, setEvidence] = useState<HopVerification | null>(null);
  const [signed, setSigned] = useState<Record<string, unknown> | null>(null);

  async function handleVerify() {
    setVerifying(true);
    setResult(null);
    setSigned(null);
    try {
      const v = await getHopVerification(edge.id);
      setEvidence(v);
      let r = await verifyEvidence(v);
      if (r.status === "verified" && v.signed_message) {
        // Only what was signed is shown, and the map must agree with it: the
        // edge's endpoints and capabilities come from other columns that a
        // signature does not protect.
        const msg = JSON.parse(v.signed_message) as Record<string, unknown>;
        const caps = Array.isArray(msg.delegated_capabilities) ? (msg.delegated_capabilities as string[]) : [];
        const same =
          v.record_id === edge.id &&
          msg.from_agent_id === edge.from_agent_id &&
          msg.to_agent_id === edge.to_agent_id &&
          JSON.stringify([...caps].sort()) === JSON.stringify([...edge.delegated_capabilities].sort());
        if (same) setSigned(msg);
        else r = { ...r, status: "failed", message: t("agent_map.sig_map_mismatch") };
      }
      setResult(r);
    } catch {
      setResult({ status: "error", message: t("agent_map.sig_load_failed") });
    } finally {
      setVerifying(false);
    }
  }

  function renderResult() {
    if (!result) return null;
    const color: Record<string, string> = {
      verified: "#22c55e", failed: "#ef4444", unsupported: "#f59e0b", no_signature: "#94a3b8", error: "#ef4444",
    };
    return (
      <div style={{ marginTop: 8, fontSize: 12 }}>
        <div style={{ color: color[result.status], fontWeight: 600 }}>
          {t(`agent_map.sig_${result.status}`)}
          {result.status !== "verified" && result.message ? ` — ${result.message}` : ""}
        </div>
        {result.scheme && result.status === "verified" && (
          <div style={{ color: "#94a3b8", marginTop: 4 }}>
            {t("agent_map.sig_scheme")}:{" "}
            <span style={{ color: "#e2e8f0" }}>
              {result.scheme === SCHEME_HYBRID ? t("agent_map.sig_scheme_hybrid") : t("agent_map.sig_scheme_classic")}
            </span>
          </div>
        )}
        {signed && (
          <div style={{ marginTop: 8 }}>
            <div style={{ color: "#94a3b8" }}>{t("agent_map.sig_signed_content")}</div>
            <div className="mono" style={{ fontSize: 11, wordBreak: "break-word" }}>
              {t("agent_map.sig_task")}: {String(signed.task ?? "—")}
              <br />
              {t("agent_map.sig_caps")}: {Array.isArray(signed.delegated_capabilities) ? (signed.delegated_capabilities as string[]).join(", ") || "—" : "—"}
              {typeof signed.issued_at === "number" && (
                <>
                  <br />
                  {t("agent_map.sig_issued")}: {new Date((signed.issued_at as number) * 1000).toLocaleString()}
                </>
              )}
            </div>
          </div>
        )}
        {result.fingerprint && (
          <div style={{ marginTop: 8 }}>
            <div style={{ color: "#94a3b8" }}>{t("agent_map.sig_fingerprint")}</div>
            <code className="mono" style={{ fontSize: 11, wordBreak: "break-all", color: "#e2e8f0" }}>{result.fingerprint}</code>
            <div style={{ color: "#94a3b8", marginTop: 4 }}>{t("agent_map.sig_compare")}</div>
          </div>
        )}
        {evidence?.key_origin === "server" && result.status === "verified" && (
          <div style={{ color: "#f59e0b", marginTop: 6 }}>{t("agent_map.sig_server_key")}</div>
        )}
        {evidence?.key_origin === "agent" && result.status === "verified" && (
          <div style={{ color: "#94a3b8", marginTop: 6 }}>{t("agent_map.sig_agent_key")}</div>
        )}
        {evidence && evidence.has_signature && (
          <button
            onClick={() => downloadEvidence(evidence, `provenza-delegation-${edge.id}-evidence.json`)}
            style={{
              marginTop: 8, background: "none", border: "1px solid #334155", color: "#e2e8f0",
              borderRadius: 6, padding: "4px 10px", fontSize: 12, cursor: "pointer", width: "100%",
            }}
          >
            {t("agent_map.sig_download")}
          </button>
        )}
      </div>
    );
  }

  return (
    <div
      style={{
        position: "absolute",
        top: 12,
        right: 12,
        width: 320,
        background: "rgba(17,24,39,0.95)",
        border: "1px solid #334155",
        borderRadius: 8,
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
        padding: 14,
        fontSize: 13,
        color: "#e2e8f0",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <strong>Delegation #{edge.id}</strong>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", fontSize: 16 }}>✕</button>
      </div>
      <div style={{ marginBottom: 6 }}>
        <span style={{ color: "#94a3b8" }}>Chain:</span> #{edge.chain_id} ({edge.chain_status})
      </div>
      <div style={{ marginBottom: 6 }}>
        <span style={{ color: "#94a3b8" }}>Delegated:</span>{" "}
        <span className="mono" style={{ fontSize: 11 }}>
          {edge.delegated_capabilities.join(", ") || "—"}
        </span>
      </div>
      {edge.is_violation && (
        <div style={{ color: "#ef4444", fontWeight: 600, marginTop: 6 }}>⚠ Violated chain</div>
      )}
      {edge.chain_status === "tripped" && (
        <div style={{ color: "#f59e0b", fontWeight: 600, marginTop: 6 }}>
          ⚡ Halted by the circuit breaker —{" "}
          <a href="/agent-breaker" style={{ color: "#fbbf24" }}>review</a>
        </div>
      )}

      <div style={{ marginTop: 10, borderTop: "1px solid #334155", paddingTop: 10 }}>
        <button
          onClick={handleVerify}
          disabled={verifying}
          style={{
            background: "#3b82f6", color: "#fff", border: "none", borderRadius: 6,
            padding: "6px 12px", fontSize: 12, cursor: "pointer", width: "100%",
          }}
        >
          {verifying ? t("agent_map.sig_verifying") : t("agent_map.sig_verify")}
        </button>
        {renderResult()}
      </div>
    </div>
  );
}
