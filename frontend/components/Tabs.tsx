"use client";

// Tabs whose choice lives in the URL (?tab=...): a tab can be linked to, and
// an old page's address can redirect straight to it (next.config.ts).

import React from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

export interface TabDef {
  key: string;
  label: React.ReactNode;
  badge?: number;
}

export function useTab(keys: string[], fallback?: string): [string, (key: string) => void] {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const wanted = params.get("tab") ?? "";
  const current = keys.includes(wanted) ? wanted : fallback ?? keys[0];
  const set = (key: string) => {
    const next = new URLSearchParams(params.toString());
    next.set("tab", key);
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  };
  return [current, set];
}

export function Tabs({ tabs, current, onChange }: { tabs: TabDef[]; current: string; onChange: (key: string) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          role="tab"
          aria-selected={tab.key === current}
          className={`tab${tab.key === current ? " tab-active" : ""}`}
          onClick={() => onChange(tab.key)}
        >
          {tab.label}
          {tab.badge ? <span className="tab-badge">{tab.badge}</span> : null}
        </button>
      ))}
    </div>
  );
}
