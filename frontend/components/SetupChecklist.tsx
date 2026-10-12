"use client";

// What a new installation still needs (backend GET /system/setup). Shown to
// admins on the dashboard until the required steps are done; can be folded.

import Link from "next/link";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

interface Item {
  key: string;
  done: boolean;
  href: string;
  optional?: boolean;
}

const FOLDED_KEY = "pvz.setup.folded";

export function SetupChecklist() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [items, setItems] = useState<Item[] | null>(null);
  const [complete, setComplete] = useState(true);
  const [folded, setFolded] = useState(false);

  useEffect(() => {
    if (user?.role !== "admin") return;
    try {
      setFolded(window.localStorage.getItem(FOLDED_KEY) === "1");
    } catch {
      /* private mode */
    }
    api.get<{ items: Item[]; complete: boolean }>("/system/setup")
      .then(({ data }) => {
        setItems(data.items);
        setComplete(data.complete);
      })
      .catch(() => setItems(null));
  }, [user?.role]);

  if (!items || complete) return null;
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
  );
}
