# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Custom PII patterns: checking an admin's regular expression before it runs
on every prompt, and running it with a time limit.

A regular expression can take exponential time on a crafted input
("catastrophic backtracking", ReDoS): `(a|aa)+$` on forty a's and a "!"
runs for minutes, and `.*.*x` takes time growing with the square of the
whole prompt. Three layers keep a custom rule from stalling requests:

  1. static checks on the parsed pattern (stdlib parser): no back
     references; no variable-length repetition inside another repetition
     (`(a+)+`, `(\\w+\\s?)*`, `(.*a){20}`); no alternation inside a
     repetition (`(a|aa)+`); no open-ended repetition of characters that
     include spaces (`.*`, `\\D+`, `[^@]+`, `[a-z ]*` - prose is one long
     run of those; use `{0,50}`); counts at most 1000 in all; at most 500
     characters; nothing that matches the empty text; braces only as counts;
  2. a timing test when the rule is saved: the pattern runs over prose-like
     text with its own literal parts placed in it and must finish within
     SAVE_TEST_TIMEOUT;
  3. at run time every custom rule runs with RULE_TIMEOUT (and all of them
     within SCAN_BUDGET per text) through the `regex` module, which can stop
     a match; a rule that runs out is reported (the firewall then refuses
     the prompt rather than let unchecked text through).

What is left is quadratic at worst in a run of narrow characters (`\\w+@`
on a 100k run of letters): fast on real text, and a crafted prompt only
gets itself refused.

Patterns use the `regex` module's syntax, which is a superset of Python's
`re` (the static checks parse them with `re`, so `regex`-only constructs
are refused, and braces that are not counts too - `regex` reads some as
fuzzy matching).
"""

import re
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

try:  # the parser of the stdlib engine, for the static checks
    import re._parser as _sre_parse  # Python >= 3.11
    import re._constants as _sre_c
except ImportError:  # pragma: no cover - Python 3.10
    import sre_constants as _sre_c  # type: ignore
    import sre_parse as _sre_parse  # type: ignore

import regex

MAX_PATTERN_LENGTH = 500
MAX_REPEAT_COUNT = 1000      # also the product of nested counts
MAX_SAMPLE_LENGTH = 20000
MAX_MATCHES = 10000          # per rule per text; beyond it the whole text counts as matched
RULE_TIMEOUT = 0.25          # seconds per rule per text, at run time
SCAN_BUDGET = 0.5            # seconds for all custom rules on one text
SAVE_TEST_TIMEOUT = 0.05     # seconds per test input of SAVE_TEST_LENGTH, when saving: a fifth of
                             # RULE_TIMEOUT for a fifth of a 100k prompt
SAVE_TEST_LENGTH = 20000
LABEL_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")

# Built-in detectors (services/prompt_firewall.py). `source` says how they
# find things: regex here, names through the NER model and the gazetteer.
BUILTIN: List[Dict[str, str]] = [
    {"type": "EMAIL", "source": "regex", "example": "john@example.com"},
    {"type": "PHONE", "source": "regex", "example": "+998 90 123-45-67"},
    {"type": "CREDIT_CARD", "source": "regex", "example": "4111 1111 1111 1111"},
    {"type": "SSN", "source": "regex", "example": "123-45-6789"},
    {"type": "IP_ADDRESS", "source": "regex", "example": "10.1.2.3"},
    {"type": "API_KEY", "source": "regex", "example": "sk-abcdefghijklmnop"},
    {"type": "PERSON", "source": "names", "example": "Aziz Karimov"},
    {"type": "ORG", "source": "names", "example": "Uztelecom"},
    {"type": "LOCATION", "source": "names", "example": "Toshkent"},
]
BUILTIN_TYPES = [b["type"] for b in BUILTIN]
ACTIONS = ("mask", "block")


class TooManyMatches(Exception):
    """More than MAX_MATCHES values in one text."""


class PiiPatternError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def _walk(items, in_repeat: bool = False, mult: int = 1) -> None:
    """in_repeat: inside a repetition of more than once; mult: the product
    of the counts around this point (nested fixed counts are expanded when
    compiled)."""
    c = _sre_c
    possessive = getattr(c, "POSSESSIVE_REPEAT", None)
    atomic = getattr(c, "ATOMIC_GROUP", None)
    for op, av in items:
        if op in (c.MAX_REPEAT, c.MIN_REPEAT) or (possessive is not None and op == possessive):
            lo, hi, sub = av
            unbounded = hi == c.MAXREPEAT
            if in_repeat and lo != hi:
                raise PiiPatternError("pii.nested_quantifier",
                                      "a repetition of variable length inside another repetition, like (a+)+ "
                                      "or (\\d{3}-?){3} - write the parts out")
            if unbounded and _broad(sub):
                raise PiiPatternError("pii.broad_repeat",
                                      "an open-ended repetition of characters that include spaces, like .* "
                                      "or [^@]+ - give it a limit, like {0,50}")
            m = mult * max(lo if unbounded else hi, 1)
            if (not unbounded and hi > MAX_REPEAT_COUNT) or m > MAX_REPEAT_COUNT:
                raise PiiPatternError("pii.repeat_too_large", f"at most {MAX_REPEAT_COUNT} in all")
            _walk(sub, in_repeat or hi > 1, m)
        elif op == c.BRANCH:
            if in_repeat:
                raise PiiPatternError("pii.alternation_in_repeat",
                                      "alternatives inside a repetition, like (a|aa)+ - use a character class")
            for branch in av[1]:
                _walk(branch, in_repeat, mult)
        elif op == c.SUBPATTERN:
            _walk(av[-1], in_repeat, mult)
        elif op in (c.ASSERT, c.ASSERT_NOT):
            _walk(av[1], in_repeat, mult)
        elif atomic is not None and op == atomic:
            _walk(av, in_repeat, mult)
        elif op in (c.GROUPREF, c.GROUPREF_EXISTS):
            raise PiiPatternError("pii.backreference", "back references are not allowed")


try:
    import re._compiler as _sre_compile  # Python >= 3.11
except ImportError:  # pragma: no cover - Python 3.10
    import sre_compile as _sre_compile  # type: ignore

_SINGLE = {_sre_c.ANY, _sre_c.IN, _sre_c.NOT_LITERAL, _sre_c.LITERAL}


def _broad(sub) -> bool:
    """A single-character item that matches a space or a line break AND a
    letter or digit: an open-ended run of it can span a whole prompt."""
    items = list(sub)
    if len(items) != 1 or items[0][0] not in _SINGLE:
        return False
    try:
        rx = _sre_compile.compile(sub, getattr(sub.state, "flags", 0))
    except Exception:  # noqa: BLE001 - when in doubt, call it broad
        return True
    spacey = any(rx.fullmatch(ch) for ch in (" ", "\n", "\t"))
    wordy = any(rx.fullmatch(ch) for ch in ("a", "Z", "5", "я", "-", "."))
    return spacey and wordy


_QUANT = re.compile(r"\{\d+(?:,\d*)?\}|\{,\d+\}")


def _check_braces(pattern: str) -> None:
    """An unescaped { must be a count. Python's parser reads other braces as
    text, while the run-time engine reads some as fuzzy matching
    ({e<=3}), which the static checks would not see."""
    i, in_class = 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            if pattern[i + 1:i + 3] == "N{":  # \N{NAME}: a named character
                close = pattern.find("}", i)
                i = close + 1 if close > 0 else len(pattern)
                continue
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "^":
                i += 1
            if pattern[i + 1:i + 2] == "]":  # a leading ] is literal
                i += 1
        elif ch == "{" and not _QUANT.match(pattern, i):
            raise PiiPatternError("pii.braces", "write \\{ for a literal brace")
        i += 1


def _flags(ignore_case: bool) -> int:
    return regex.V0 | (regex.IGNORECASE if ignore_case else 0)


@lru_cache(maxsize=512)
def compile_rule(pattern: str, ignore_case: bool):
    """The compiled pattern (run-time engine). Assumes validate() passed."""
    return regex.compile(pattern, _flags(ignore_case))


_PROSE = ("Hello team, the report for client 4521 is ready - see https://example.com/r/77 and mail "
          "ops@example.com before 12.10.2026. Order no. 88-1907, amount 1 250 000 UZS; call +998 90 123 45 67.\n")


def _literals(items, out: List[str]) -> None:
    """Runs of literal characters in the parsed pattern ("password", "ДОГ-")."""
    run: List[str] = []
    for op, av in items:
        if op == _sre_c.LITERAL:
            run.append(chr(av))
            continue
        if run:
            out.append("".join(run))
            run = []
        if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT) or op == getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            _literals(av[2], out)
        elif op == _sre_c.SUBPATTERN:
            _literals(av[-1], out)
        elif op == _sre_c.BRANCH:
            for b in av[1]:
                _literals(b, out)
        elif op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
            _literals(av[1], out)
    if run:
        out.append("".join(run))


def _test_inputs(parsed, n: int = SAVE_TEST_LENGTH) -> List[str]:
    """Prose-like text the way prompts look, with the pattern's own literal
    parts placed in it - at the start, all through, and with the last one
    missing - so that the engine cannot skip the work by not finding them."""
    lits: List[str] = []
    _literals(list(parsed), lits)
    lits = [x for x in dict.fromkeys(lits) if x.strip()][:10]
    prose = (_PROSE * (n // len(_PROSE) + 1))[:n]
    out = [prose, prose.replace("\n", " ")]
    if lits:
        joined = " ".join(lits)
        out.append(joined + " " + prose)
        out.append(prose + " " + " ".join(lits[:-1]))
        step = max(len(prose) // 100, 1)
        sprinkled = "".join(prose[k:k + step] + " " + lits[(k // step) % len(lits)] for k in range(0, len(prose), step))
        out.append(sprinkled)
        out.append(sprinkled.replace("\n", " "))
    return out


def _timing(compiled, parsed) -> None:
    for text in _test_inputs(parsed):
        try:
            find(compiled, text, SAVE_TEST_TIMEOUT, max_matches=None)
        except TimeoutError:
            raise PiiPatternError("pii.too_slow",
                                  f"over {int(SAVE_TEST_TIMEOUT * 1000)} ms on {len(text)} characters of text")


def validate(pattern: str, ignore_case: bool = False, timing: bool = True):
    """Check a custom pattern; returns it compiled or raises PiiPatternError."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise PiiPatternError("pii.pattern_required")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PiiPatternError("pii.pattern_too_long", f"at most {MAX_PATTERN_LENGTH} characters")
    try:
        parsed = _sre_parse.parse(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as e:
        raise PiiPatternError("pii.pattern_invalid", str(e)[:200])
    except RecursionError:
        raise PiiPatternError("pii.pattern_invalid", "nested too deeply")
    _walk(list(parsed))
    _check_braces(pattern)
    try:
        compiled = regex.compile(pattern, _flags(ignore_case))
    except regex.error as e:
        raise PiiPatternError("pii.pattern_invalid", str(e)[:200])
    if compiled.fullmatch("") is not None:
        raise PiiPatternError("pii.matches_empty", "the pattern matches empty text")
    if timing:
        _timing(compiled, parsed)
    return compiled


def validate_label(label: str) -> str:
    label = (label or "").strip().upper()
    if not LABEL_RE.match(label):
        raise PiiPatternError("pii.label_invalid", "2-32 of A-Z, 0-9, _ starting with a letter")
    if label in BUILTIN_TYPES:
        raise PiiPatternError("pii.label_builtin", label)
    return label


def find(compiled, text: str, timeout: float = RULE_TIMEOUT,
         max_matches: Optional[int] = MAX_MATCHES) -> List[Tuple[int, int]]:
    """Non-empty matches as (start, end). TimeoutError when out of time;
    TooManyMatches beyond max_matches."""
    if timeout <= 0:
        raise TimeoutError("no time left")
    out = []
    for m in compiled.finditer(text, timeout=timeout):  # the timeout covers the whole iteration
        if m.end() > m.start():
            out.append((m.start(), m.end()))
            if max_matches is not None and len(out) > max_matches:
                raise TooManyMatches()
    return out


def test(pattern: str, ignore_case: bool, sample: str, timing: bool = False) -> Tuple[Dict[str, Any], Any]:
    """A draft rule against a sample: whether it is accepted, and what it
    finds; with the compiled pattern (not cached) when accepted. The live
    tester skips the timing test (saving runs it)."""
    sample = (sample or "")[:MAX_SAMPLE_LENGTH]
    try:
        compiled = validate(pattern, ignore_case, timing=timing)
    except PiiPatternError as e:
        return {"ok": False, "error": e.code, "detail": e.detail, "matches": []}, None
    started = time.monotonic()
    try:
        spans = find(compiled, sample, max_matches=None)
    except TimeoutError:
        return {"ok": False, "error": "pii.too_slow", "detail": "on this sample", "matches": []}, None
    return {"ok": True, "error": None, "detail": None,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "matches": [{"start": s_, "end": e, "text": sample[s_:e][:200]} for s_, e in spans[:100]],
            "count": len(spans)}, compiled


def engine_info() -> Optional[str]:
    return getattr(regex, "__version__", None)
