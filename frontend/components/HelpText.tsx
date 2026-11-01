import Link from "next/link";
import React from "react";
import type { Block } from "@/lib/help";

/** Text with **bold** and [links](/path): a link to a page of this site stays in
 *  the app, anything else opens in a new tab. No HTML is ever interpreted. */
export function HelpInline({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  const re = /\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^)\s]+)\)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) parts.push(<strong key={i++}>{m[1]}</strong>);
    else if (m[3].startsWith("/") && !m[3].startsWith("//")) parts.push(<Link key={i++} href={m[3]}>{m[2]}</Link>);
    else if (m[3].startsWith("https://")) parts.push(<a key={i++} href={m[3]} target="_blank" rel="noreferrer">{m[2]}</a>);
    else parts.push(m[2]);
    last = re.lastIndex;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <>{parts}</>;
}

export function HelpBlocks({ blocks, labels }: { blocks: Block[]; labels: { tip: string; warn: string } }) {
  return (
    <>
      {blocks.map((b, i) => {
        switch (b[0]) {
          case "h":
            return <h2 key={i} id={`s${i}`}><HelpInline text={b[1]} /></h2>;
          case "p":
            return <p key={i}><HelpInline text={b[1]} /></p>;
          case "steps":
            return <ol key={i} className="help-steps">{b[1].map((s, j) => <li key={j}><HelpInline text={s} /></li>)}</ol>;
          case "list":
            return <ul key={i}>{b[1].map((s, j) => <li key={j}><HelpInline text={s} /></li>)}</ul>;
          case "tip":
            return <div key={i} className="help-note help-tip"><b>{labels.tip}</b> <HelpInline text={b[1]} /></div>;
          case "warn":
            return <div key={i} className="help-note help-warn"><b>{labels.warn}</b> <HelpInline text={b[1]} /></div>;
          case "qa":
            return (
              <details key={i} className="help-qa">
                <summary><HelpInline text={b[1]} /></summary>
                <p><HelpInline text={b[2]} /></p>
              </details>
            );
          default:
            return null;
        }
      })}
    </>
  );
}
