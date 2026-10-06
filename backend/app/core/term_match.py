# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Finding blocked terms in a prompt, including the usual ways of hiding them.

Text and term are reduced the same way before they are compared:
  * Unicode compatibility forms (full-width letters, ligatures) and accents
    are dropped - also accents typed as separate combining marks - and case
    is folded;
  * look-alike letters of other scripts become the Latin ones (Cyrillic "о"
    in "Prоject", Greek "ο") - on both sides, so a Cyrillic term still finds
    itself;
  * in a word that has letters, digits standing for letters are read as
    letters (0 o, 1 i, 3 e, 4 a, 5 s, 7 t, 8 b - and when the text has such a
    "1", a term with "l" is also looked for with "i" there, so "he11o" finds
    "hello"); a number on its own stays a number;
  * "$" at the start of a word is an "s"; invisible characters are removed.

The text is then split into words (runs of letters and digits). Between two
words there is either a space or a "glue" (_ - . / ' and the like, with no
space), and spaced-out single letters ("P r o j e c t") are glued together.

A term matches when its letters appear with the text's spaces falling only
where the term itself has a word boundary:
  * "Project Titan" matches project titan, Project_Titan, PROJECT-TITAN,
    ProjectTitan, P r o j e c t  T i t a n, Pr0ject T1tan;
  * "therapist" does not match "the rapist", "dit" does not match "send it".
In **word** mode the match also starts and ends at word edges ("class" does
not contain the word "ass", "titan.com" does contain "titan"); in
**substring** mode it may start or end inside a word ("titanium").

All searches are str.find / str.startswith over one string (C speed), so a
long prompt and thousands of terms stay cheap.
"""

import time
import unicodedata
from bisect import bisect_right
from dataclasses import dataclass, field
from functools import lru_cache
from itertools import combinations
from typing import Iterable, List, Optional, Set, Tuple

MATCH_MODES = ("word", "substring")
ACTIONS = ("block", "monitor")
MAX_TERM_LENGTH = 200
MAX_KEY_LENGTH = 400
MAX_HITS_PER_TERM = 50
MAX_SCAN_SECONDS = 2.0   # for all terms on one text; past it the check reports itself incomplete
MAX_REJECTED = 200    # word-mode occurrences not at word edges, before switching to a per-word scan

_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "ү": "y", "һ": "h", "ӏ": "i",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "μ": "m", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
    # Armenian
    "օ": "o", "ս": "u", "ո": "n", "հ": "h", "ց": "g",
    # Latin variants
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ß": "ss", "æ": "ae", "œ": "oe",
}
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}
_INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u180e", "\u200e", "\u200f"}


@lru_cache(maxsize=8192)
def _letters(ch: str) -> str:
    """The reduced letters of one character; "" when it is not a letter or digit."""
    out = []
    for c in unicodedata.normalize("NFKD", ch):
        if unicodedata.combining(c):
            continue
        for d in c.casefold():
            d = _CONFUSABLES.get(d, d)
            for e in d:
                if e.isalnum():
                    out.append(e)
    return "".join(out)


@dataclass
class _Reduced:
    words: List[str]                   # reduced letters per word
    spans: List[Tuple[int, int]]       # each word's (start, end) in the original text
    glued: List[bool]                  # glued[k]: words k and k+1 are joined without a space
    camel: List[Set[int]] = field(default_factory=list)  # term only: camelCase splits inside each word
    src: List[List[int]] = field(default_factory=list)   # per word, per letter: index in the original text
    ones: bool = False                 # a "1" was read as a letter somewhere


def _reduce(text: str, camel: bool = False) -> _Reduced:
    words: List[str] = []
    spans: List[Tuple[int, int]] = []
    srcs: List[List[int]] = []
    camels: List[Set[int]] = []
    seps: List[str] = []
    cur: List[str] = []
    cur_src: List[int] = []
    cur_camel: Set[int] = set()
    cur_start, last_end, sep = -1, 0, ""
    prev_lower = False
    for i, ch in enumerate(text):
        if ch in _INVISIBLE:
            continue
        if unicodedata.combining(ch):
            if cur:  # an accent typed separately belongs to the letter before it
                last_end = i + 1
            continue
        r = _letters(ch)
        if ch == "$" and not cur and i + 1 < len(text) and _letters(text[i + 1]).isalpha():
            r = "s"
        if r:
            if not cur:
                cur_start = i
                seps.append(sep)
                sep = ""
            elif camel and prev_lower and ch.isupper():
                cur_camel.add(len("".join(cur)))
            cur.append(r)
            cur_src.extend([i] * len(r))
            last_end = i + 1
            prev_lower = ch.islower()
        else:
            if cur:
                words.append("".join(cur))
                spans.append((cur_start, last_end))
                srcs.append(cur_src)
                camels.append(cur_camel)
                cur, cur_src, cur_camel = [], [], set()
            sep += ch
            prev_lower = False
    if cur:
        words.append("".join(cur))
        spans.append((cur_start, last_end))
        srcs.append(cur_src)
        camels.append(cur_camel)
    # digits stand for letters only in words that have letters
    ones = False
    for k, w in enumerate(words):
        if any(c.isalpha() for c in w) and any(c.isdigit() for c in w):
            ones = ones or "1" in w
            words[k] = "".join(_LEET.get(c, c) for c in w)
    # seps[k] is what came before word k; a join is glue when it has no whitespace,
    # or inside a run of three or more single letters split by spaces (spaced-out
    # writing - not "a" and "b" that happen to be next to each other)
    glued = []
    for k in range(len(words) - 1):
        s = seps[k + 1]
        glued.append(bool(s) and not any(c.isspace() for c in s))
    k = 0
    while k < len(words):
        j = k
        while (j + 1 < len(words) and len(words[j]) == 1 and len(words[j + 1]) == 1
               and len(seps[j + 1]) <= 2 and seps[j + 1].strip() == ""):
            j += 1
        if j - k >= 2 and len(words[k]) == 1:
            for x in range(k, j):
                glued[x] = True
        k = j + 1
    return _Reduced(words, spans, glued, camels, srcs, ones)


@lru_cache(maxsize=20000)
def _term_shape(term: str) -> Tuple[str, Tuple[int, ...]]:
    """The term's letters and where it has word boundaries (between its
    words, at _ - . and at camelCase)."""
    r = _reduce(term, camel=True)
    key, bounds, pos = "", set(), 0
    for k, w in enumerate(r.words):
        if k:
            bounds.add(pos)
        bounds.update(pos + c for c in r.camel[k])
        key += w
        pos += len(w)
    return key, tuple(sorted(b for b in bounds if 0 < b < len(key)))


def term_key(term: str) -> str:
    """The term's letters after reduction: what is searched for. Empty when
    the term has no letters or digits."""
    return _term_shape(" ".join(str(term or "").split()))[0]


def _variants(key: str, bounds: Tuple[int, ...], ones: bool = False) -> List[str]:
    """The term written with a space at some of its boundaries (all subsets
    up to three boundaries; otherwise none or all), and each of those with
    every "l" as "i" when the text had a "1" in a word (how a "1" written for
    an "l" reads)."""
    choices = ([c for n in range(len(bounds) + 1) for c in combinations(bounds, n)] if len(bounds) <= 3
               else [(), bounds])
    out = []
    for c in choices:
        s, last = [], 0
        for b in c:
            s.append(key[last:b])
            last = b
        s.append(key[last:])
        out.append(" ".join(s))
    if ones and "l" in key:
        out += [v.replace("l", "i") for v in out]
    return list(dict.fromkeys(out))


@dataclass
class Term:
    id: Optional[int]
    term: str
    match: str = "word"
    action: str = "block"
    key: str = ""          # recomputed from the term: the reduction may improve over time
    scope: str = "org"
    category: Optional[str] = None

    def __post_init__(self):
        self.key = term_key(self.term)


@dataclass
class Hit:
    term: Term
    spans: List[Tuple[int, int]] = field(default_factory=list)


class _Text:
    """The reduced text as one string: glued words joined directly, others
    with one space."""

    def __init__(self, text: str):
        r = _reduce(text)
        parts: List[str] = []
        self.src: List[int] = []          # string position -> index in the original text (-1 for a space)
        self.starts: List[int] = []       # where each word starts in the string
        pos = 0
        for k, w in enumerate(r.words):
            if k and not r.glued[k - 1]:
                parts.append(" ")
                self.src.append(-1)
                pos += 1
            self.starts.append(pos)
            parts.append(w)
            self.src.extend(r.src[k])
            pos += len(w)
        self.s = "".join(parts)
        self.start_set = set(self.starts)
        self.end_set = {st + len(w) for st, w in zip(self.starts, r.words)}
        self.r = r
        self._prefix: dict = {}

    def starts_with(self, v: str) -> List[int]:
        """Word starts where the string continues with v's first letters
        (indexed on first use, by up to four letters)."""
        n = min(4, len(v))
        index = self._prefix.get(n)
        if index is None:
            index = {}
            for st in self.starts:
                index.setdefault(self.s[st:st + n], []).append(st)
            self._prefix[n] = index
        return index.get(v[:n], [])

    def span(self, a: int, b: int) -> Tuple[int, int]:
        """Original-text span of string positions [a, b), widened to whole words."""
        k1 = bisect_right(self.starts, a) - 1
        k2 = bisect_right(self.starts, b - 1) - 1
        return self.r.spans[k1][0], self.r.spans[k2][1]


def find(text: str, terms: Iterable[Term]) -> List[Hit]:
    """Every term found in the text, with where (spans in the original text)."""
    return scan(text, terms)[0]


def scan(text: str, terms: Iterable[Term], budget: float = MAX_SCAN_SECONDS) -> Tuple[List[Hit], bool]:
    """(hits, complete): complete is False when the text took longer than
    `budget` to check (a crafted prompt) - the caller should not let it
    through unchecked."""
    terms = [t for t in terms if t.key]
    if not text or not terms:
        return [], True
    deadline = time.monotonic() + budget
    tx = _Text(text)
    if not tx.s:
        return [], True
    hits: List[Hit] = []
    letters = tx.s.replace(" ", "")
    letters_i = letters.replace("l", "i") if tx.r.ones else letters
    for n, t in enumerate(terms):
        if n % 64 == 0 and time.monotonic() > deadline:
            return hits, False
        if t.key not in letters and (not tx.r.ones or t.key.replace("l", "i") not in letters_i):  # cheap first check
            continue
        key, bounds = _term_shape(" ".join(t.term.split()))
        found: List[Tuple[int, int]] = []
        seen = set()
        for v in _variants(key, bounds, tx.r.ones):
            rejected = 0
            at = tx.s.find(v)
            while at != -1 and len(found) < MAX_HITS_PER_TERM:
                end = at + len(v)
                if t.match == "word" and (at not in tx.start_set or end not in tx.end_set):
                    rejected += 1
                    if rejected > MAX_REJECTED:
                        # many near-misses (crafted?): check word starts only
                        for st in tx.starts_with(v):
                            if len(found) >= MAX_HITS_PER_TERM:
                                break
                            if st > at and tx.s.startswith(v, st) and st + len(v) in tx.end_set and st not in seen:
                                seen.add(st)
                                found.append(tx.span(st, st + len(v)))
                        break
                elif at not in seen:
                    seen.add(at)
                    found.append(tx.span(at, end))
                at = tx.s.find(v, at + 1)
        if found:
            hits.append(Hit(t, sorted(dict.fromkeys(found))))
    return hits, time.monotonic() <= deadline
