# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Hidden text in what a model reads about a tool (docs/hidden-text.md).

A person approves a tool by reading its definition; the agent's model reads
the same definition, character by character. Text one sees and the other
does not breaks that: instructions spelled in Unicode tag characters
("ASCII smuggling") are invisible on screen and read by the model as plain
text; bidirectional controls show a person different text than the bytes
say; variation selectors can carry a whole hidden message after a single
visible character; long runs of blank space push text out of view.

scan() walks a definition (an MCP tool, an A2A agent card, an HTTP tool)
and reports, per string or key, what it found:

  refuse     no reason to be in a tool description; such a definition
             cannot be approved and is not served even if it was approved
             before this check existed
    tag_text        Unicode tag characters (U+E0000-E007F) outside an emoji
                    flag sequence - with the text they spell decoded
    bidi            bidirectional embeddings, overrides, isolates (Trojan Source)
    control         control characters other than tab and line breaks
    variation_data  variation selectors U+E0100-E01EF, or two or more in a row

  confirm    sometimes legitimate; the approver must confirm having seen it
    invisible       zero-width and other invisible format characters (a
                    zero-width joiner inside an emoji is fine)
    private_use     private-use characters (no meaning anyone agreed on)
    padding         40 blank characters or 10 line breaks in a row

The check never rewrites: a cleaned definition would no longer hash to what
the upstream serves, and the approval pins that hash.
"""

import re
import unicodedata
from typing import Any, Dict, List

REFUSE = ("tag_text", "bidi", "control", "variation_data")
CONFIRM = ("invisible", "private_use", "padding")
MAX_FINDINGS = 50
MAX_DECODED = 500

_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_MARKS = {0x200E, 0x200F, 0x061C}          # direction marks: invisible, not reordering
_ZWJ = 0x200D
_FLAG = 0x1F3F4                            # black flag: a tag sequence after it is a subdivision flag
_PADDING = re.compile(r"[ \t  - 　]{40,}|(?:\r?\n[ \t]*){10,}")
# invisible "letters" that are not format characters
_FILLERS = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800}


def _vs(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _vs_byte(cp: int) -> int:
    return cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16


def _emoji(cp: int) -> bool:
    return cp >= 0x1F000 or (0x2600 <= cp <= 0x27BF) or unicodedata.category(chr(cp)) == "So"


def _scan_text(s: str, path: str, out: List[Dict[str, Any]]) -> None:
    found: Dict[str, Dict[str, Any]] = {}

    def add(kind: str, at: int, cp: int) -> None:
        f = found.setdefault(kind, {"path": path, "kind": kind, "count": 0, "first_at": at, "codepoints": []})
        f["count"] += 1
        h = f"U+{cp:04X}"
        if h not in f["codepoints"] and len(f["codepoints"]) < 8:
            f["codepoints"].append(h)

    i, n = 0, len(s)
    while i < n:
        cp = ord(s[i])
        if 0xE0000 <= cp <= 0xE007F:
            j = i
            while j < n and 0xE0000 <= ord(s[j]) <= 0xE007F:
                j += 1
            run = s[i:j]
            flag = (i > 0 and ord(s[i - 1]) == _FLAG and ord(run[-1]) == 0xE007F
                    and all(0xE0030 <= ord(c) <= 0xE007A for c in run[:-1]))
            if not flag:
                for k, c in enumerate(run):
                    add("tag_text", i + k, ord(c))
                f = found["tag_text"]
                f["hidden"] = (f.get("hidden", "") + "".join(
                    chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E))[:MAX_DECODED]
            i = j
            continue
        if _vs(cp):
            j = i
            while j < n and _vs(ord(s[j])):
                j += 1
            # one selector after a character is how emoji choose their look; a run
            # of them, or the supplementary ones, is data: one byte a selector
            if j - i > 1 or cp >= 0xE0100:
                for k in range(i, j):
                    add("variation_data", k, ord(s[k]))
                data = bytes(_vs_byte(ord(c)) for c in s[i:j])
                f = found["variation_data"]
                f["hidden"] = (f.get("hidden", "") + data.decode("utf-8", "replace"))[:MAX_DECODED]
            i = j
            continue
        elif cp in _BIDI:
            add("bidi", i, cp)
        elif unicodedata.category(s[i]) == "Cc" and s[i] not in "\t\n\r":
            add("control", i, cp)
        elif cp == _ZWJ:
            # inside an emoji sequence (a family, a heart on fire) it joins; anywhere else it hides
            before = i > 0 and (_emoji(ord(s[i - 1])) or (
                i > 1 and ord(s[i - 1]) in (0xFE0E, 0xFE0F) and _emoji(ord(s[i - 2]))))
            if not (before and i + 1 < n and _emoji(ord(s[i + 1]))):
                add("invisible", i, cp)
        elif unicodedata.category(s[i]) == "Cf" or cp in _MARKS or cp in _FILLERS:
            add("invisible", i, cp)
        elif unicodedata.category(s[i]) == "Co":
            add("private_use", i, cp)
        i += 1
    for m in _PADDING.finditer(s):
        f = found.setdefault("padding", {"path": path, "kind": "padding", "count": 0, "first_at": m.start(),
                                         "codepoints": []})
        f["count"] += 1
    out.extend(found.values())


def scan(value: Any, path: str = "$") -> List[Dict[str, Any]]:
    """What hides in the strings and keys of a JSON value: a list of
    {path, kind, count, first_at, codepoints[, hidden]} - at most MAX_FINDINGS."""
    out: List[Dict[str, Any]] = []
    stack = [(value, path)]
    while stack and len(out) < MAX_FINDINGS:
        v, p = stack.pop()
        if isinstance(v, str):
            _scan_text(v, p, out)
        elif isinstance(v, dict):
            for k in sorted(v, key=str, reverse=True):
                kp = f"{p}.{k}"
                if isinstance(k, str):
                    _scan_text(k, kp + " (key)", out)
                stack.append((v[k], kp))
        elif isinstance(v, list):
            for idx in range(len(v) - 1, -1, -1):
                stack.append((v[idx], f"{p}[{idx}]"))
    return out[:MAX_FINDINGS]


def level(findings: List[Dict[str, Any]]) -> str:
    """"refuse", "confirm" or "clean"."""
    kinds = {f["kind"] for f in findings}
    if kinds & set(REFUSE):
        return "refuse"
    return "confirm" if kinds else "clean"


def summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """For the audit log and API answers: the level, the kinds and where."""
    return {"level": level(findings), "kinds": sorted({f["kind"] for f in findings}),
            "paths": sorted({f["path"] for f in findings})[:20]}


def require_approvable(findings: List[Dict[str, Any]], confirmed: bool) -> None:
    """Approval of a definition: refused outright for hidden text, and for
    invisible characters until the approver confirms having seen them."""
    from fastapi import status

    from app.core.errors import api_error

    lv = level(findings)
    kinds = ", ".join(sorted({f["kind"] for f in findings}))
    if lv == "refuse":
        raise api_error(status.HTTP_409_CONFLICT, "tool.hidden_text", kinds=kinds)
    if lv == "confirm" and not confirmed:
        raise api_error(status.HTTP_409_CONFLICT, "tool.hidden_text_confirm", kinds=kinds)


def servable(definition: Any) -> bool:
    """A definition with hidden text is not shown to an agent's model, even
    if it was approved before this check existed."""
    return level(scan(definition)) != "refuse"
