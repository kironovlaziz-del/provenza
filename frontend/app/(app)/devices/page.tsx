"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { translateApiError } from "@/lib/errors";
import { ago, getDevice, listDevices, type DeviceDetailT, type DeviceT } from "@/lib/endpoints_api";

// A device that has not reported for this long is shown as quiet.
const QUIET_AFTER_MS = 24 * 3600 * 1000;

export default function DevicesPage() {
  const { t, i18n } = useTranslation();
  const [q, setQ] = useState("");
  const [items, setItems] = useState<DeviceT[] | null>(null);
  const [total, setTotal] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const [details, setDetails] = useState<Record<number, DeviceDetailT>>({});
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((query: string) => {
    setError(null);
    listDevices(query)
      .then((p) => {
        setItems(p.items);
        setTotal(p.total);
      })
      .catch((e) => setError(translateApiError(e?.response?.data?.detail, t, t("devices.load_failed"))));
  }, [t]);

  useEffect(() => {
    const h = setTimeout(() => load(q), q ? 300 : 0);
    return () => clearTimeout(h);
  }, [q, load]);

  // /devices?focus=<id> (from Agents Found) opens that device
  useEffect(() => {
    const focus = Number(new URLSearchParams(window.location.search).get("focus"));
    if (focus > 0) toggle(focus);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggle(id: number) {
    if (open === id) {
      setOpen(null);
      return;
    }
    setOpen(id);
    if (!details[id]) {
      getDevice(id)
        .then((d) => setDetails((m) => ({ ...m, [id]: d })))
        .catch((e) => setError(translateApiError(e?.response?.data?.detail, t, t("devices.load_failed"))));
    }
  }

  const quiet = (d: DeviceT) => Date.now() - new Date(d.last_seen_at).getTime() > QUIET_AFTER_MS;

  return (
    <>
      <PageHeader title={t("devices.title")} />
      <div className="content">
        <p className="hint-text u-mb-16">{t("devices.hint")}</p>
        {error && <p className="error-text u-mb-16">{error}</p>}

        <div className="panel">
          <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <h2>{t("devices.table_title", { count: total })}</h2>
            <input
              type="search"
              value={q}
              maxLength={100}
              onChange={(e) => setQ(e.target.value)}
              placeholder={t("devices.search")}
              aria-label={t("devices.search")}
              style={{ width: 240, maxWidth: "100%" }}
            />
          </div>
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>{t("devices.col_device")}</th>
                  <th>{t("devices.col_source")}</th>
                  <th>{t("devices.col_agents")}</th>
                  <th>{t("devices.col_last_seen")}</th>
                  <th>{t("devices.col_collector")}</th>
                </tr>
              </thead>
              <tbody>
                {items === null && <tr className="empty-row"><td colSpan={5}>{t("common.loading")}</td></tr>}
                {items?.length === 0 && (
                  <tr className="empty-row">
                    <td colSpan={5}>
                      {q ? t("devices.no_match") : t("devices.empty")}{" "}
                      {!q && <Link href="/ingestion-sources">{t("devices.empty_link")}</Link>}
                    </td>
                  </tr>
                )}
                {items?.map((d) => (
                  <React.Fragment key={d.id}>
                    <tr onClick={() => toggle(d.id)} style={{ cursor: "pointer" }} aria-expanded={open === d.id}>
                      <td>
                        <span aria-hidden="true" style={{ display: "inline-block", width: 12, transform: open === d.id ? "rotate(90deg)" : "none", transition: "transform .15s" }}>▸</span>{" "}
                        <span className="mono" style={{ fontWeight: 600 }}>{d.host_id}</span>
                        {d.last_user && <div className="hint-text" style={{ fontSize: 11, marginLeft: 16 }}>{d.last_user}</div>}
                      </td>
                      <td>
                        {d.source.name}
                        <div className="hint-text" style={{ fontSize: 11 }}>{t(`devices.source_${d.source.source_type}`, d.source.source_type)}</div>
                      </td>
                      <td>
                        {d.agents_found === 0 ? "—" : d.agents_found}
                        {d.agents_new > 0 && (
                          <span className="pill pill-medium" style={{ marginLeft: 6 }}>
                            {t("devices.new_agents", { count: d.agents_new })}
                          </span>
                        )}
                      </td>
                      <td style={{ fontSize: 12 }} title={new Date(d.last_seen_at).toLocaleString(i18n.language)}>
                        {ago(d.last_seen_at, i18n.language)}
                        {quiet(d) && <span className="pill pill-neutral" style={{ marginLeft: 6 }}>{t("devices.quiet")}</span>}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        {[d.os, d.agent_version && `v${d.agent_version}`].filter(Boolean).join(" · ") || "—"}
                      </td>
                    </tr>
                    {open === d.id && (
                      <tr>
                        <td colSpan={5} style={{ background: "var(--bg-subtle, transparent)" }}>
                          {!details[d.id] ? (
                            <span className="hint-text">{t("common.loading")}</span>
                          ) : (
                            <div style={{ display: "grid", gap: 8 }}>
                              <div className="hint-text" style={{ fontSize: 12 }}>
                                {t("devices.first_seen", { when: new Date(d.first_seen_at).toLocaleString(i18n.language) })}
                                {" · "}
                                {t("devices.events", { count: d.event_count })}
                              </div>
                              {details[d.id].agents.length === 0 ? (
                                <span className="hint-text">{t("devices.no_agents")}</span>
                              ) : (
                                <ul style={{ margin: 0, paddingLeft: 18 }}>
                                  {details[d.id].agents.map((a) => (
                                    <li key={a.id} style={{ fontSize: 13 }}>
                                      <strong>{a.name}</strong>{" "}
                                      <span className="hint-text">{t(`found.category_${a.category}`, a.category)}</span>{" "}
                                      <span className="pill pill-neutral">{t(`found.status_${a.status}`)}</span>
                                      {a.registered_agent && (
                                        <> → <Link href={`/agents/${a.registered_agent.id}`}>{a.registered_agent.name}</Link></>
                                      )}
                                    </li>
                                  ))}
                                </ul>
                              )}
                              {details[d.id].agents.some((a) => a.status === "new") && (
                                <Link href="/agents-found" className="btn btn-sm" style={{ justifySelf: "start" }}>
                                  {t("devices.review_found")}
                                </Link>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
