"use client";

// Shadow AI -> What works: where the findings come from, and whether each
// source reports now. The browser extension and the endpoint agent report by
// themselves (their state is the protection coverage's, GET /system/setup);
// DNS and proxy logs are imported by hand on this page. Admins only: they set
// the sources up, and the coverage is theirs to read.

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { STATE_STYLE, evidence, type CoverageItem } from "@/lib/coverage";

/** The coverage items that feed Shadow AI, in the order shown. */
export const SHADOW_SOURCES = ["browsers", "endpoint_agents"];

export function ShadowSources({ onImport }: { onImport?: () => void }) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [items, setItems] = useState<CoverageItem[] | null>(null);

  useEffect(() => {
    if (user?.role !== "admin") return;
    api.get<{ coverage?: { items: CoverageItem[] } }>("/system/setup")
      .then(({ data }) => setItems((data.coverage?.items ?? []).filter((i) => SHADOW_SOURCES.includes(i.key))
        .sort((a, b) => SHADOW_SOURCES.indexOf(a.key) - SHADOW_SOURCES.indexOf(b.key))))
      .catch(() => setItems(null));
  }, [user?.role]);

  if (user?.role !== "admin" || !items) return null;

  return (
    <section className="panel u-mb-16" aria-labelledby="shadow-sources-title">
      <div className="panel-header"><h2 id="shadow-sources-title">{t("shadow_sources.title")}</h2></div>
      <div className="panel-body">
        <p className="hint-text" style={{ marginTop: 0 }}>{t("shadow_sources.hint")}</p>
        <ul className="shadow-sources">
          {items.map((i) => {
            const s = STATE_STYLE[i.state];
            const why = evidence(i);
            return (
              <li key={i.key}>
                <span className="shadow-source-mark" style={{ color: s.color }} aria-hidden="true">{s.mark}</span>
                <span className="shadow-source-text">
                  <b>{t(`coverage.${i.key}.title`)}</b>
                  <span className="hint-text" style={{ color: s.color }}> · {t(`coverage.state_${i.state}`)}</span>
                  <small>{t(`coverage.${why.key}`, why.values)}</small>
                </span>
                {i.state !== "ok" && <Link className="btn btn-sm" href={i.href}>{t("setup.go")}</Link>}
              </li>
            );
          })}
          <li>
            <span className="shadow-source-mark" style={{ color: "var(--text-muted)" }} aria-hidden="true">↥</span>
            <span className="shadow-source-text">
              <b>{t("shadow_sources.logs_title")}</b>
              <span className="hint-text"> · {t("shadow_sources.logs_state")}</span>
              <small>{t("shadow_sources.logs_hint")}</small>
            </span>
            {onImport && <button type="button" className="btn btn-sm" onClick={onImport}>{t("log_import.open")}</button>}
          </li>
        </ul>
      </div>
    </section>
  );
}
