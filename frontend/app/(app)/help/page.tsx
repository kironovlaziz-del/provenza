"use client";

// Help: guides for the people who use Provenza - where to start, a guide per
// role, one article per feature, and the FAQ. Searchable.

import Link from "next/link";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { Icon } from "@/components/Icon";
import { useAuth } from "@/lib/auth";
import { HELP_GROUPS, helpArticles } from "@/lib/help";

export default function HelpPage() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const [query, setQuery] = useState("");
  const articles = helpArticles(i18n.language);
  const q = query.trim().toLowerCase();
  const text = (a: (typeof articles)[number]) =>
    [a.title, a.summary, ...a.body.flatMap((b) => b.slice(1).flat() as string[])].join(" ").toLowerCase();
  const hits = q ? articles.filter((a) => text(a).includes(q)) : null;
  const mine = articles.find((a) => a.group === "roles" && a.roles?.includes((user?.role ?? "user") as never));

  const card = (a: (typeof articles)[number]) => (
    <Link key={a.slug} href={`/help/${a.slug}`} className="hub-card">
      <span className="hub-card-text">
        <b>{a.title}</b>
        <small>{a.summary}</small>
      </span>
      <Icon name="chevron" size={16} />
    </Link>
  );

  return (
    <>
      <PageHeader title={t("nav.help")} />
      <div className="content help-hub">
        <p className="hint-text u-mb-16">{t("help.intro")}</p>
        <div className="help-search">
          <Icon name="search" size={16} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("help.search")}
            aria-label={t("help.search")} />
        </div>

        {hits ? (
          <section className="hub-group">
            <h2>{t("help.results", { count: hits.length })}</h2>
            <div className="hub-grid">{hits.map(card)}</div>
            {hits.length === 0 && <p className="hint-text">{t("help.no_results")}</p>}
          </section>
        ) : (
          <>
            {mine && (
              <section className="hub-group">
                <h2>{t("help.for_you")}</h2>
                <div className="hub-grid">{card(mine)}</div>
              </section>
            )}
            {HELP_GROUPS.map((g) => {
              const list = articles.filter((a) => a.group === g);
              if (list.length === 0) return null;
              return (
                <section key={g} className="hub-group">
                  <h2>{t(`help.group.${g}`)}</h2>
                  <div className="hub-grid">{list.map(card)}</div>
                </section>
              );
            })}
          </>
        )}
      </div>
    </>
  );
}
