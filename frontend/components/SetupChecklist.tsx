"use client";

// What a new installation still needs (backend GET /system/setup), and
// whether each part of the protection works now (its "coverage"). Shown to
// admins on the dashboard until the required steps are done, or when
// something that was set up stopped working; always on the Settings page.

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { STATE_STYLE, evidence, fixKey, needsDashboard, type CoverageItem, type CoverageSummary } from "@/lib/coverage";

interface Item {
  key: string;
  done: boolean;
  href: string;
  optional?: boolean;
}

interface Setup {
  items: Item[];
  complete: boolean;
  coverage?: { items: CoverageItem[]; summary: CoverageSummary };
}

const FOLDED_KEY = "pvz.setup.folded";


/** always: also when every required step is done (the Settings page keeps it, open). */
export function SetupChecklist({ always = false }: { always?: boolean } = {}) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [setup, setSetup] = useState<Setup | null>(null);
  const [folded, setFolded] = useState(false);

  useEffect(() => {
    if (user?.role !== "admin") return;
    try {
      setFolded(window.localStorage.getItem(FOLDED_KEY) === "1");
    } catch {
      /* private mode */
    }
    api.get<Setup>("/system/setup")
      .then(({ data }) => setSetup(data))
      .catch(() => setSetup(null));
  }, [user?.role]);

  if (!setup) return null;
  const { items, complete, coverage } = setup;
  const alert = needsDashboard(coverage?.summary);
  if (complete && !always && !alert) return null;
  const left = items.filter((i) => !i.done && !i.optional).length;

  function fold(next: boolean) {
    setFolded(next);
    try {
      window.localStorage.setItem(FOLDED_KEY, next ? "1" : "0");
    } catch {
      /* private mode */
    }
  }

  return (
    <>
      {(!complete || always) && (
        <div className="panel u-mb-16" style={{ borderColor: "var(--accent)" }}>
          <div className="panel-header u-flex u-justify-between u-items-center">
            <h2>{t("setup.title")} <span className="tab-badge">{left}</span></h2>
            <button className="btn btn-sm" onClick={() => fold(!folded)}>{folded ? t("setup.show") : t("setup.hide")}</button>
          </div>
          {!folded && (
            <div className="panel-body">
              <p className="hint-text">{t("setup.hint")}</p>
              <table>
                <tbody>
                  {items.map((i) => (
                    <tr key={i.key}>
                      <td style={{ width: 28 }}>{i.done ? "✓" : "○"}</td>
                      <td>
                        <strong style={i.done ? { opacity: 0.6 } : undefined}>{t(`setup.${i.key}`)}</strong>
                        {i.optional && <span className="hint-text"> · {t("setup.optional")}</span>}
                        {!i.done && <div className="hint-text">{t(`setup.${i.key}_hint`)}</div>}
                      </td>
                      <td className="u-nowrap" style={{ textAlign: "right" }}>
                        {!i.done && <Link className="btn btn-sm btn-primary" href={i.href}>{t("setup.go")}</Link>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {coverage && (always || alert) && <Coverage items={coverage.items} summary={coverage.summary} />}
    </>
  );
}

function Coverage({ items, summary }: { items: CoverageItem[]; summary: CoverageSummary }) {
  const { t } = useTranslation();
  return (
    <div className="panel u-mb-16" style={{ borderColor: summary.attention ? "var(--risk-medium)" : undefined }}>
      <div className="panel-header u-flex u-justify-between u-items-center">
        <h2>
          {t("coverage.title")}{" "}
          {summary.needs_action > 0 && <span className="tab-badge">{summary.needs_action} {t("coverage.needs")}</span>}
        </h2>
      </div>
      <div className="panel-body">
        <p className="hint-text">{t("coverage.hint")}</p>
        <table>
          <tbody>
            {items.map((i) => {
              const s = STATE_STYLE[i.state];
              const why = evidence(i);
              return (
                <tr key={i.key}>
                  <td style={{ width: 28, color: s.color, fontWeight: 700 }} aria-label={t(`coverage.state_${i.state}`)}>{s.mark}</td>
                  <td>
                    <strong>{t(`coverage.${i.key}.title`)}</strong>
                    <span className="hint-text" style={{ color: s.color }}> · {t(`coverage.state_${i.state}`)}</span>
                    {i.optional && <span className="hint-text"> · {t("setup.optional")}</span>}
                    <div className="hint-text">{t(`coverage.${why.key}`, why.values)}</div>
                    {i.state !== "ok" && (
                      <div className="hint-text"><strong>{t("coverage.fix_label")}:</strong> {t(`coverage.${fixKey(i)}`)}</div>
                    )}
                  </td>
                  <td className="u-nowrap" style={{ textAlign: "right" }}>
                    {i.state !== "ok" && <Link className="btn btn-sm btn-primary" href={i.href}>{t("setup.go")}</Link>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
