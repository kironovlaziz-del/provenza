"use client";

// Settings: one page that lists every setting this role may open, in groups,
// with what each one is for; on top, for admins, what a new installation still
// needs. The pages keep their own addresses and link back here. Simple mode
// lists the settings for you and for people; the full console all of them.
// Here, too, the switch between simple mode and the full console.

import Link from "next/link";
import React from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { SetupChecklist } from "@/components/SetupChecklist";
import { Icon } from "@/components/Icon";
import { useAuth } from "@/lib/auth";
import { useConsoleMode } from "@/lib/console_mode";
import { visibleSections } from "@/lib/navigation";

const GROUPS = ["you", "people", "gateways", "data", "system"];

export default function SettingsPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [mode, setMode] = useConsoleMode();
  const simple = mode === "simple";
  const section = visibleSections(user?.role, !!user?.is_operator, mode).find((s) => s.key === "settings");
  const pages = (section?.pages ?? []).filter((p) => p.group);

  return (
    <>
      <PageHeader title={t("nav.settings")} />
      <div className="content">
        <section className="panel console-mode" aria-labelledby="console-mode-title">
          <div className="panel-body console-mode-body">
            <span className="console-mode-text">
              <b id="console-mode-title">{t(simple ? "console_mode.simple_title" : "console_mode.full_title")}</b>
              <small>{t(simple ? "console_mode.simple_hint" : "console_mode.full_hint")}</small>
            </span>
            <button type="button" className="btn btn-sm" onClick={() => setMode(simple ? "full" : "simple")}>
              {t(simple ? "console_mode.to_full" : "console_mode.to_simple")}
            </button>
          </div>
        </section>
        {user?.role === "admin" && <SetupChecklist always />}
        {GROUPS.map((g) => {
          const list = pages.filter((p) => p.group === g);
          if (list.length === 0) return null;
          return (
            <section key={g} className="hub-group">
              <h2>{t(`settings_hub.group.${g}`)}</h2>
              <div className="hub-grid">
                {list.map((p) => {
                  const key = p.labelKey.split(".").pop();
                  return (
                    <Link key={p.href} href={p.href} className="hub-card">
                      <span className="hub-card-text">
                        <b>{t(p.labelKey)}</b>
                        <small>{t(`settings_hub.desc.${key}`)}</small>
                      </span>
                      <Icon name="chevron" size={16} />
                    </Link>
                  );
                })}
              </div>
            </section>
          );
        })}
      </div>
    </>
  );
}
