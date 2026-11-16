// Text in a tool definition that a person cannot see but an agent's model
// reads (backend/app/pvp/hidden_text.py, docs/hidden-text.md). The server
// finds and judges it; this only makes it visible on screen.

export type HiddenLevel = "clean" | "confirm" | "refuse";

export interface HiddenFinding {
  path: string;
  kind: "tag_text" | "bidi" | "control" | "variation_data" | "invisible" | "private_use" | "padding";
  count: number;
  first_at: number;
  codepoints: string[];
  /** the text tag characters or variation selectors spell, decoded */
  hidden?: string;
}

const hex = (cp: number) => "U+" + cp.toString(16).toUpperCase().padStart(4, "0");

function invisible(cp: number): boolean {
  return (
    (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0xfeff || cp === 0x00ad || cp === 0x061c || cp === 0x180e || cp === 0x115f || cp === 0x1160 ||
    cp === 0x3164 || cp === 0xffa0 || (cp >= 0xfff9 && cp <= 0xfffb) || (cp >= 0xe000 && cp <= 0xf8ff) ||
    (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || (cp >= 0x7f && cp <= 0x9f)
  );
}

/** The text with what is invisible shown: tag characters as the text they
 *  spell, every other invisible or control character by its code point. */
export function reveal(text: string): string {
  let out = "";
  let tags = "";
  const flush = () => {
    if (tags) out += `⟦hidden: ${tags}⟧`;
    tags = "";
  };
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      tags += cp >= 0xe0020 && cp <= 0xe007e ? String.fromCodePoint(cp - 0xe0000) : `[${hex(cp)}]`;
      continue;
    }
    flush();
    if (invisible(cp) || (cp >= 0xe0100 && cp <= 0xe01ef) || (cp >= 0xfe00 && cp <= 0xfe0d)) out += `⟦${hex(cp)}⟧`;
    else out += ch;
  }
  flush();
  return out;
}

/** The API code of a refusal, if it is one of the hidden-text ones. */
export function hiddenCode(err: unknown): "tool.hidden_text" | "tool.hidden_text_confirm" | null {
  const d = (err as { response?: { status?: number; data?: { detail?: unknown } } })?.response?.data?.detail;
  const code = typeof d === "string" ? d : (d as { code?: string } | undefined)?.code;
  return code === "tool.hidden_text" || code === "tool.hidden_text_confirm" ? code : null;
}

/** Approve; when the server asks the approver to confirm invisible characters,
 *  ask, and approve again confirming. Returns false when the person declined. */
export async function approveConfirming(approve: (confirm: boolean) => Promise<unknown>,
                                        ask: () => Promise<boolean>): Promise<boolean> {
  try {
    await approve(false);
    return true;
  } catch (err) {
    if (hiddenCode(err) !== "tool.hidden_text_confirm") throw err;
    if (!(await ask())) return false;
    await approve(true);
    return true;
  }
}
