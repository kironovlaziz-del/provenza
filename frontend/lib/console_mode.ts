// The console's two modes. Simple (the default): four tabs - AI agents, Rules,
// Audit log, Shadow AI - with Settings and Help, Stop all, what waits for a
// decision and whether the protection works, in the top bar. Full: every page
// (lib/navigation.ts). The mode only chooses what the navigation shows: every
// page keeps its address and opens in either mode, and the server sees no
// difference. The choice is kept in this browser.

import { useCallback, useSyncExternalStore } from "react";

export type ConsoleMode = "simple" | "full";

export const MODE_KEY = "pvz.console";
const EVENT = "pvz-console-mode";

/** The mode kept in this browser; simple unless the person chose the full console. */
export function loadMode(): ConsoleMode {
  try {
    return window.localStorage.getItem(MODE_KEY) === "full" ? "full" : "simple";
  } catch {
    return "simple";   // storage refused (private mode): the default
  }
}

export function saveMode(mode: ConsoleMode): void {
  try {
    window.localStorage.setItem(MODE_KEY, mode);
  } catch {
    /* not kept: this page still switches */
  }
  window.dispatchEvent(new Event(EVENT));
}

function subscribe(onChange: () => void): () => void {
  // this tab (saveMode) and the browser's other tabs (storage)
  const onStorage = (e: StorageEvent) => { if (e.key === MODE_KEY || e.key === null) onChange(); };
  window.addEventListener(EVENT, onChange);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(EVENT, onChange);
    window.removeEventListener("storage", onStorage);
  };
}

/** The current mode and a setter; every component using it follows a change at once. */
export function useConsoleMode(): [ConsoleMode, (mode: ConsoleMode) => void] {
  const mode = useSyncExternalStore(subscribe, loadMode, () => "simple" as ConsoleMode);
  const set = useCallback((m: ConsoleMode) => saveMode(m), []);
  return [mode, set];
}
