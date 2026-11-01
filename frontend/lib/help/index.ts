import type { Article, HelpGroup } from "./types";
import { ARTICLES_EN } from "./en";
import { ARTICLES_UZ } from "./uz";

export type { Article, Block, HelpGroup } from "./types";

export const HELP_GROUPS: HelpGroup[] = ["start", "roles", "features", "faq"];

/** The articles in the reader's language; one missing there falls back to English. */
export function helpArticles(lang: string | undefined): Article[] {
  if (!lang?.startsWith("uz")) return ARTICLES_EN;
  const uz = new Map(ARTICLES_UZ.map((a) => [a.slug, a]));
  return ARTICLES_EN.map((a) => uz.get(a.slug) ?? a);
}

export function helpArticle(lang: string | undefined, slug: string): Article | undefined {
  return helpArticles(lang).find((a) => a.slug === slug);
}
