# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Undoing the usual disguises before the Prompt Firewall looks for secrets
(services/prompt_firewall.py). The firewall's patterns match what is written;
people who want data through write it so that it does not match:

  invisible     zero-width spaces, soft hyphens, bidi controls inside a word
  width / form  ＠, full-width digits, ligatures (NFKC)
  look-alikes   Cyrillic or Greek letters inside a Latin word ("pаssword" with
                a Cyrillic "а") - only in words that already have Latin
                letters or digits, so Russian and Uzbek text is left alone
  spacing       "j o h n @ e x a m p l e . c o m", "4 1 1 1 - 1 1 1 1 ..."
  spelled out   "john (at) example [dot] com"
  encodings     base64 / hex runs, decoded (see encoded_runs)

Blocked terms are matched with their own reduction (core/term_match.py),
which already reads look-alikes, digits for letters and spaced-out words.

normalize() returns the new text and, for each of its characters, the span
of the original it came from - so whatever is found in the new text is
masked in the original, where it is.
"""

import base64
import binascii
import re
import unicodedata
from typing import Iterator, List, Tuple

INVISIBLE = {"\u00ad", "\u034f", "\u061c", "\u115f", "\u1160", "\u17b4", "\u17b5", "\u180e", "\u200b", "\u200c",
             "\u200d", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2060", "\u2061",
             "\u2062", "\u2063", "\u2064", "\u2066", "\u2067", "\u2068", "\u2069", "\u3164", "\ufeff", "\uffa0"}

# letters that look Latin: Cyrillic and Greek
CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "з": "3", "и": "u", "к": "k", "м": "m", "н": "h", "о": "o", "п": "n",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "һ": "h", "ӏ": "l", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "З": "3", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "Ԛ": "Q", "Ԝ": "W", "Һ": "H", "Ӏ": "I",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "υ": "u", "ι": "i", "κ": "k", "τ": "t", "χ": "x", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
}

_SPACED = re.compile(r"(?<![^\s(\[{\"'])(?:\S[ .\-_·|/]){4,}\S(?![^\s)\]}\"'.,;:!?])")
_AT = re.compile(r"\s*[(\[{]\s*at\s*[)\]}]\s*|\s+at\s+(?=\S+\s*(?:[(\[{]\s*dot\s*[)\]}]|\s+dot\s+))", re.IGNORECASE)
_DOT = re.compile(r"\s*[(\[{]\s*dot\s*[)\]}]\s*|\s+dot\s+(?=[a-z]{2,})", re.IGNORECASE)

Mapped = List[Tuple[str, int, int]]      # (character, original start, original end)


def _mapped(text: str) -> Mapped:
    return [(ch, i, i + 1) for i, ch in enumerate(text)]


def _join(m: Mapped) -> str:
    return "".join(c for c, _, _ in m)


def _replace(m: Mapped, pattern: re.Pattern, repl) -> Mapped:
    """Apply a regex replacement on the characters, keeping where each came
    from (a replacement takes the span of what it replaced)."""
    text = _join(m)
    out: Mapped = []
    at = 0
    for match in pattern.finditer(text):
        s, e = match.span()
        out.extend(m[at:s])
        new = repl(match) if callable(repl) else repl
        if s < e:
            start, end = m[s][1], m[e - 1][2]
            out.extend((ch, start, end) for ch in new)
        at = e
    out.extend(m[at:])
    return out


def _has_latin_or_digit(word: str) -> bool:
    return any(("a" <= c.lower() <= "z") or c.isdigit() for c in word)


def normalize(text: str) -> Tuple[str, List[Tuple[int, int]]]:
    """(the normalized text, for each of its characters the original span)."""
    m: Mapped = []
    for i, ch in enumerate(text):
        if ch in INVISIBLE or unicodedata.category(ch) == "Cf":
            continue
        for n in unicodedata.normalize("NFKC", ch):
            m.append((n, i, i + 1))
    # look-alikes, word by word: only where the word already has Latin letters or digits
    out: Mapped = []
    word: Mapped = []
    for item in m + [(" ", len(text), len(text))]:
        if item[0].isspace():
            if word:
                mixed = _has_latin_or_digit(_join(word))
                out.extend((CONFUSABLES.get(c, c) if mixed else c, s, e) for c, s, e in word)
                word = []
            out.append(item)
        else:
            word.append(item)
    m = out[:-1]
    m = _replace(m, _AT, "@")
    m = _replace(m, _DOT, ".")
    # a spaced-out run is character, separator, character, ...: keep the characters
    m = _replace(m, _SPACED, lambda mt: mt.group(0)[::2])
    return _join(m), [(s, e) for _, s, e in m]


def original_span(spans: List[Tuple[int, int]], start: int, end: int) -> Tuple[int, int]:
    return spans[start][0], spans[end - 1][1]


# ---------------------------------------------------------------- encodings

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,4096}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,2048}(?![0-9A-Fa-f])")
MAX_RUNS = 32


def _printable(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    return text if text and printable / len(text) > 0.9 else ""


def encoded_runs(text: str) -> Iterator[Tuple[int, int, str, str]]:
    """(start, end, "base64" | "hex", decoded text) for runs that decode to
    readable text - at most MAX_RUNS per prompt."""
    seen = 0
    for kind, pattern in (("hex", _HEX), ("base64", _B64)):
        for m in pattern.finditer(text):
            if seen >= MAX_RUNS:
                return
            chunk = m.group(0)
            try:
                if kind == "hex":
                    raw = bytes.fromhex(chunk)
                else:
                    if chunk.isdigit() or chunk.isalpha() and chunk.islower():
                        continue       # an ordinary long word or number, not base64
                    padded = chunk + "=" * (-len(chunk) % 4)
                    raw = base64.urlsafe_b64decode(padded) if ("-" in chunk or "_" in chunk) \
                        else base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError):
                continue
            decoded = _printable(raw)
            if decoded:
                seen += 1
                yield m.start(), m.end(), kind, decoded
