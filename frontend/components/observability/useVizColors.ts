"use client";

import { useEffect, useState } from "react";

/** The chart colors of the current theme (the --viz-* tokens in globals.css).
 *  SVG attributes do not resolve CSS variables reliably, so the values are
 *  read from the stylesheet and read again when the theme changes. */
export const VIZ_TOKENS = ["blue", "aqua", "orange", "p50", "p95", "p99", "grid"] as const;
export type VizToken = (typeof VIZ_TOKENS)[number];
export type VizColors = Record<VizToken, string>;

const FALLBACK: VizColors = {
  blue: "#3987e5",
  aqua: "#199e70",
  orange: "#d95926",
  p50: "#1c5cab",
  p95: "#3987e5",
  p99: "#9ec5f4",
  grid: "rgba(255, 255, 255, 0.06)",
};

function read(): VizColors {
  if (typeof window === "undefined") return FALLBACK;
  const style = getComputedStyle(document.documentElement);
  const out = { ...FALLBACK };
  for (const k of VIZ_TOKENS) {
    const v = style.getPropertyValue(`--viz-${k}`).trim();
    if (v) out[k] = v;
  }
  return out;
}

export function useVizColors(): VizColors {
  const [colors, setColors] = useState<VizColors>(FALLBACK);
  useEffect(() => {
    setColors(read());
    const observer = new MutationObserver(() => setColors(read()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);
  return colors;
}
