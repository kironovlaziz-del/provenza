"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import React from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/PageHeader";
import { HelpBlocks } from "@/components/HelpText";
import { helpArticle, helpArticles } from "@/lib/help";
import { useAuth } from "@/lib/auth";
import { canOpen } from "@/lib/navigation";

export default function HelpArticlePage() {
  const { t, i18n } = useTranslation();
  const { user } = useAuth();
  const params = useParams<{ slug: string }>();
  const slug = String(params?.slug ?? "");
  const article = helpArticle(i18n.language, slug);
  const all = helpArticles(i18n.language);

  if (!article) {
    return (
      <>
        <PageHeader title={t("nav.help")} />
        <div className="content">
          <p className="hint-text">{t("help.not_found")}</p>
          <Link href="/help">{t("help.back")}</Link>
        </div>
      </>
    );
  }

  const sections = article.body.map((b, i) => [b, i] as const).filter(([b]) => b[0] === "h");
  const related = all.filter((a) => a.slug !== article.slug && a.group === article.group).slice(0, 4);

  return (
    <>
      <PageHeader title={article.title} />
      <div className="content">
        <div className="help-layout">
          <article className="help-article">
            <p className="help-lead">{article.summary}</p>
            {article.roles && (
              <p className="help-roles">
                {t("help.for")} {article.roles.map((r) => t(`help.role.${r}`)).join(", ")}
              </p>
            )}
            <HelpBlocks blocks={article.body} labels={{ tip: t("help.tip"), warn: t("help.warn") }} />
            {article.page && canOpen(article.page, user?.role, !!user?.is_operator) && (
              <p className="help-open">
                <Link href={article.page} className="btn btn-primary">{t("help.open_page")}</Link>
              </p>
            )}
          </article>
          <aside className="help-aside">
            {sections.length > 2 && (
              <nav className="panel help-toc" aria-label={t("help.contents")}>
                <div className="panel-header"><h2>{t("help.contents")}</h2></div>
                <div className="panel-body">
                  {sections.map(([b, i]) => <a key={i} href={`#s${i}`}>{b[1] as string}</a>)}
                </div>
              </nav>
            )}
            {related.length > 0 && (
              <nav className="panel help-toc" aria-label={t("help.related")}>
                <div className="panel-header"><h2>{t("help.related")}</h2></div>
                <div className="panel-body">
                  {related.map((a) => <Link key={a.slug} href={`/help/${a.slug}`}>{a.title}</Link>)}
                </div>
              </nav>
            )}
          </aside>
        </div>
      </div>
    </>
  );
}
