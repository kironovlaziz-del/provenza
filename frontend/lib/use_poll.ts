// Run fn every `ms` while the tab is visible, and at once when a hidden tab
// comes back. The latest fn is called, so a caller need not memoize it.
import { useEffect, useRef } from "react";

export function usePollWhileVisible(fn: () => void, ms: number) {
  const latest = useRef(fn);
  useEffect(() => { latest.current = fn; }, [fn]);
  useEffect(() => {
    const tick = () => { if (document.visibilityState === "visible") latest.current(); };
    const id = window.setInterval(tick, ms);
    document.addEventListener("visibilitychange", tick);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", tick);
    };
  }, [ms]);
}
