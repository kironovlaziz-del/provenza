import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ARTICLES_EN } from "@/lib/help/en";
import { ARTICLES_UZ } from "@/lib/help/uz";
import { helpArticles } from "@/lib/help";

const APP = join(__dirname, "..", "app", "(app)");

function links(text: string): string[] {
  return [...text.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
}

function allText(a: (typeof ARTICLES_EN)[number]): string {
  return [a.summary, ...a.body.flatMap((b) => b.slice(1).flat() as string[])].join("\n");
}

describe("help articles", () => {
  it("has every English article in Uzbek, in the same shape", () => {
    expect(ARTICLES_UZ.map((a) => a.slug)).toEqual(ARTICLES_EN.map((a) => a.slug));
    for (const en of ARTICLES_EN) {
      const uz = ARTICLES_UZ.find((a) => a.slug === en.slug)!;
      expect(uz.group).toBe(en.group);
      expect(uz.page).toBe(en.page);
      expect(uz.body.map((b) => b[0])).toEqual(en.body.map((b) => b[0]));
      expect(links(allText(uz)).sort()).toEqual(links(allText(en)).sort());
    }
  });

  it("links only to pages that exist", () => {
    const slugs = new Set(ARTICLES_EN.map((a) => a.slug));
    for (const a of [...ARTICLES_EN, ...ARTICLES_UZ]) {
      for (const href of [...links(allText(a)), ...(a.page ? [a.page] : [])]) {
        const path = href.split("?")[0].split("#")[0];
        if (path.startsWith("/help/")) expect(slugs.has(path.slice(6)), `${a.slug} → ${href}`).toBe(true);
        else expect(existsSync(join(APP, path)), `${a.slug} → ${href}`).toBe(true);
      }
    }
  });

  it("falls back to English for any other language", () => {
    expect(helpArticles("ru")).toBe(ARTICLES_EN);
    expect(helpArticles("uz")[0].title).toBe(ARTICLES_UZ[0].title);
  });
});
