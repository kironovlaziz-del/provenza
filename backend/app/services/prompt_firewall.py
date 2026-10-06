# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Prompt Firewall

Runs on every AI request before it reaches the Policy Engine / provider call.

Four layers of protection:

  1. Regex detectors - emails, credit cards, SSNs, IP addresses, API keys,
     phone numbers - and the organization's own patterns (PII rules,
     services/pii_rules.py). Each type can be switched off or set to block
     the prompt instead of masking it; without settings all built-in types
     are on and mask.

  2. Blocked terms - the active policy version can declare a list of
     substrings that cause the entire prompt to be rejected.

  3. NER - person names, organizations, and locations via a spaCy model.
     Optional: when spacy or the model is missing, the layer is skipped.

  4. Gazetteer - fixed lists of well-known Uzbek cities and companies.
     Complements NER, which needs enough context to extract. A short
     prompt like "Aziz Karimov Toshkentga jonadi" may fall outside the
     training distribution, but the gazetteer always catches "Toshkent".

Regex, gazetteer, and NER run on the ORIGINAL text. Their matches are
merged by character offset with priority custom rules > built-in regex >
gazetteer > NER: any lower-priority match that overlaps a higher-priority
one is dropped (so a 14-digit tax id caught by a custom rule is not
reported as a card number). A type set to block refuses the prompt when it
is found; a custom rule that runs out of time refuses it too, since the
text could not be checked.
"""

import bisect
import logging
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

from app.core.config import settings

logger = logging.getLogger("prompt_firewall")


@dataclass
class FirewallResult:
    masked_text: str
    flags: List[str] = field(default_factory=list)
    blocked: bool = False
    blocked_reason: str | None = None
    # ids of custom rules that ran out of time on this text
    timed_out: List[int] = field(default_factory=list)
    # blocked terms found (core/term_match.Hit), blocking and monitored ones
    term_hits: List[Any] = field(default_factory=list)


@dataclass
class CustomRule:
    id: int
    label: str
    compiled: Any        # a `regex` pattern (core/pii_patterns.py); None: did not compile
    action: str = "mask"


@dataclass
class PiiConfig:
    """What to look for and what to do: `actions` maps a built-in type to
    "mask" or "block" (a type not listed is off); `custom` are the
    organization's own rules, checked first."""
    actions: Dict[str, str]
    custom: List[CustomRule] = field(default_factory=list)
    # seconds the custom rules may still spend across all scans of one
    # request (the gateway scans every message); None: each scan gets
    # SCAN_BUDGET. Only time spent in the rules is charged.
    budget: Optional[float] = None


def default_config() -> PiiConfig:
    from app.core.pii_patterns import BUILTIN_TYPES

    return PiiConfig(actions={t: "mask" for t in BUILTIN_TYPES})


_DETECTORS: List[Tuple[str, Pattern[str]]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (
        "API_KEY",
        re.compile(r"\b(?:sk|pk|api|key)[-_][A-Za-z0-9]{12,}\b", re.IGNORECASE),
    ),
    (
        "PHONE",
        re.compile(
            r"(?<!\d)(?:\+\d[\d\-\s()]{7,}\d|\(\d{2,4}\)[\d\-\s()]{5,}\d)(?!\d)"
        ),
    ),
]


_DETECTOR_LABELS = {label for label, _ in _DETECTORS}
WITHHELD_TEXT = "[WITHHELD: a PII rule could not check this text in time]"


_NER_LABEL_MAP = {
    "PERSON": "PERSON",
    "PER": "PERSON",
    "ORG": "ORG",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
}


# ---------------------------------------------------------------------------
# Gazetteer for Uzbek entities
# ---------------------------------------------------------------------------
#
# Fixed lists of common entity mentions, applied only to uz by default.
# They are intentionally short and easy to extend - add entries as you
# collect more data. Each entry may be followed by a case suffix
# ("Toshkent" -> "Toshkentga", "Toshkentda", ...); the pattern consumes
# the suffix so the full token is masked.

_UZ_LOCATIONS = [
    "Toshkent", "Samarqand", "Buxoro", "Andijon", "Namangan", "Farg'ona",
    "Nukus", "Xiva", "Qarshi", "Termiz", "Chirchiq", "Angren",
    "Margilon", "Navoiy", "Jizzax", "Guliston", "Urganch", "Denov",
    "Kokand",
]
_UZ_LOCATION_SUFFIXES = ["ning", "ga", "da", "dan", "gacha", "dagi"]

_UZ_ORGS = [
    "UzAuto Motors", "Uztelecom", "Tashkent City", "Uzum Market",
    "Payme", "Click", "Humans", "UzCard", "Beeline Uzbekistan", "TBC Bank",
]


def _gazetteer_pattern(names: List[str], suffixes: List[str] | None = None) -> Pattern[str]:
    names_sorted = sorted(names, key=len, reverse=True)
    name_alt = "|".join(re.escape(n) for n in names_sorted)
    if suffixes:
        suf_alt = "|".join(re.escape(s) for s in suffixes)
        return re.compile(rf"\b(?:{name_alt})(?:{suf_alt})?\b")
    return re.compile(rf"\b(?:{name_alt})\b")


_GAZETTEER: dict = {
    "uz": [
        ("LOCATION", _gazetteer_pattern(_UZ_LOCATIONS, _UZ_LOCATION_SUFFIXES)),
        ("ORG", _gazetteer_pattern(_UZ_ORGS)),
    ],
}


def _gazetteer_matches(text: str, language: str) -> List[Tuple[int, int, str]]:
    out: List[Tuple[int, int, str]] = []
    for label, pattern in _GAZETTEER.get(language, []):
        for m in pattern.finditer(text):
            out.append((m.start(), m.end(), label))
    return out


# ---------------------------------------------------------------------------
# NER
# ---------------------------------------------------------------------------


@lru_cache(maxsize=8)
def _load_ner(language: str):
    if not settings.PROMPT_FIREWALL_NER_ENABLED:
        return None

    models = settings.PROMPT_FIREWALL_NER_MODELS or {}
    model_path = models.get(language)
    if not model_path and settings.PROMPT_FIREWALL_NER_DEFAULT_LANG:
        model_path = models.get(settings.PROMPT_FIREWALL_NER_DEFAULT_LANG)
    if not model_path:
        return None

    try:
        import spacy  # type: ignore
    except ImportError:
        logger.warning(
            "PROMPT_FIREWALL_NER_ENABLED=true but spacy is not installed."
        )
        return None

    from pathlib import Path

    candidate = Path(model_path)
    if not candidate.is_absolute() and candidate.exists():
        resolved = str(candidate.resolve())
    else:
        resolved = model_path

    try:
        return spacy.load(resolved)
    except OSError:
        logger.warning(
            "spaCy model '%s' (language=%s) is not installed or not built yet.",
            model_path,
            language,
        )
        return None


def _ner_matches(text: str, language: str) -> List[Tuple[int, int, str]]:
    nlp = _load_ner(language)
    if nlp is None:
        return []
    doc = nlp(text)
    out: List[Tuple[int, int, str]] = []
    for ent in doc.ents:
        tag = _NER_LABEL_MAP.get(ent.label_)
        if tag:
            out.append((ent.start_char, ent.end_char, tag))
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _regex_matches(text: str, enabled: Optional[Iterable[str]] = None) -> List[Tuple[int, int, str]]:
    out: List[Tuple[int, int, str]] = []
    for label, pattern in _DETECTORS:
        if enabled is not None and label not in enabled:
            continue
        for m in pattern.finditer(text):
            out.append((m.start(), m.end(), label))
    return out


def _custom_matches(text: str, cfg: "PiiConfig") -> Tuple[List[Tuple[int, int, str]], List[int]]:
    """Matches of the organization's rules within one time budget: each rule
    gets at most RULE_TIMEOUT and all together SCAN_BUDGET (or what is left
    of the request's budget). A rule out of time, or one that did not
    compile, is reported as timed out. A rule with more than MAX_MATCHES
    values in the text counts as matching all of it."""
    from app.core.pii_patterns import RULE_TIMEOUT, SCAN_BUDGET, TooManyMatches, find

    out: List[Tuple[int, int, str]] = []
    timed_out: List[int] = []
    allowance = SCAN_BUDGET if cfg.budget is None else min(SCAN_BUDGET, cfg.budget)
    spent = 0.0
    for rule in cfg.custom:
        left = min(RULE_TIMEOUT, allowance - spent)
        if rule.compiled is None or left <= 0:
            timed_out.append(rule.id)
            continue
        started = time.monotonic()
        try:
            out += [(s, e, rule.label) for s, e in find(rule.compiled, text, left)]
        except TimeoutError:
            timed_out.append(rule.id)
        except TooManyMatches:
            out.append((0, len(text), rule.label))
        spent += time.monotonic() - started
    if cfg.budget is not None:
        cfg.budget = max(cfg.budget - spent, 0.0)
    return out, timed_out


def _overlaps(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    a_s, a_e = a
    b_s, b_e = b
    return not (a_e <= b_s or a_s >= b_e)


def _find_blocked_terms(text: str, blocked_terms: Iterable[Any]) -> Tuple[List[Any], bool]:
    """Hits of blocked terms (core/term_match.py). A plain string is a
    blocking term matched anywhere (the behaviour of callers that pass
    strings); services/blocked_terms.py passes Term objects with their own
    match mode and action."""
    from app.core.term_match import Term, scan

    terms = []
    for t in blocked_terms:
        if isinstance(t, Term):
            terms.append(t)
        elif (t or "").strip():
            terms.append(Term(None, t.strip(), match="substring", action="block"))
    if not terms:
        return [], True
    return scan(text, terms)


def _apply_masks(text: str, matches: List[Tuple[int, int, str]]) -> str:
    """Matches do not overlap (see _accept_by_priority)."""
    if not matches:
        return text
    parts: List[str] = []
    at = 0
    for start, end, label in sorted(matches, key=lambda x: x[0]):
        parts.append(text[at:start])
        parts.append(f"[MASKED:{label}]")
        at = end
    parts.append(text[at:])
    return "".join(parts)


def _accept_by_priority(
    candidates: List[Tuple[int, int, str]],
    accepted: List[Tuple[int, int, str]],
) -> None:
    """
    Append candidates whose span does not overlap any already-accepted
    match. Accepts in the given order, so callers control priority by
    the order they invoke this function. Accepted spans never overlap, so
    a sorted list and bisection find the neighbours (n log n, not n^2).
    """
    spans = sorted((s, e) for s, e, _ in accepted)
    starts = [s for s, _ in spans]
    for s, e, tag in candidates:
        i = bisect.bisect_right(starts, s)
        if i > 0 and spans[i - 1][1] > s:      # the one starting before reaches into it
            continue
        if i < len(spans) and spans[i][0] < e:  # the next one starts inside it
            continue
        spans.insert(i, (s, e))
        starts.insert(i, s)
        accepted.append((s, e, tag))


def _covered(span: Tuple[int, int], cover: List[Tuple[int, int]]) -> bool:
    i = bisect.bisect_right([c[0] for c in cover], span[0])
    return i > 0 and cover[i - 1][1] >= span[1]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan(
    text: str,
    blocked_terms: Iterable[str] | None = None,
    language: str = "en",
    pii: Optional[PiiConfig] = None,
    mask_only: bool = False,
) -> FirewallResult:
    """
    Run the full firewall pipeline over a prompt.

    `pii`: the organization's PII settings (default: every built-in type
    on, masking). `mask_only`: never refuse - for showing stored text
    masked: block rules mask, and text a rule could not check in time is
    withheld.

    Priority order for overlapping spans: custom rules > regex > gazetteer > NER.
    """
    term_hits, complete = _find_blocked_terms(text, list(blocked_terms or [])) if not mask_only else ([], True)
    if not complete:  # a crafted text that takes too long to check is not let through unchecked
        return FirewallResult(masked_text="", flags=["blocked_terms_timeout"], blocked=True,
                              blocked_reason="The blocked-terms check did not finish in time", term_hits=term_hits)
    # monitored terms are counted (services/blocked_terms.record_hits), never shown in flags:
    # the people being watched for them see the flags
    term_flags = [f"blocked_term:{h.term.term}" for h in term_hits if h.term.action == "block"]
    blocking_terms = [h for h in term_hits if h.term.action == "block"]
    if blocking_terms:
        return FirewallResult(
            masked_text="",
            flags=term_flags,
            blocked=True,
            blocked_reason=f"Prompt contains a blocked term: {blocking_terms[0].term.term}",
            term_hits=term_hits,
        )

    cfg = pii or default_config()
    actions: Dict[str, str] = dict(cfg.actions)
    for rule in cfg.custom:
        actions[rule.label] = rule.action
    custom_labels = {rule.label for rule in cfg.custom}

    custom, timed_out = _custom_matches(text, cfg)
    if timed_out:
        labels = [r.label for r in cfg.custom if r.id in timed_out]
        flags = [f"pii_timeout:{label.lower()}" for label in labels]
        if mask_only:  # unchecked text is not shown
            return FirewallResult(masked_text=WITHHELD_TEXT, flags=flags, timed_out=timed_out)
        return FirewallResult(
            masked_text="",
            flags=term_flags + flags,
            blocked=True,
            blocked_reason=f"The PII rule {labels[0]} could not check the prompt in time",
            timed_out=timed_out,
            term_hits=term_hits,
        )

    def enabled(matches: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
        return [m for m in matches if m[2] in actions]

    accepted: List[Tuple[int, int, str]] = []
    builtin = (_regex_matches(text, actions) + enabled(_gazetteer_matches(text, language))
               + enabled(_ner_matches(text, language)))

    _accept_by_priority(custom, accepted)
    regex_found = [m for m in builtin if m[2] in _DETECTOR_LABELS]
    _accept_by_priority(regex_found, accepted)
    _accept_by_priority([m for m in builtin if m[2] not in _DETECTOR_LABELS], accepted)

    # a type set to block blocks wherever it is found - unless one of the
    # organization's own rules covers the whole span (the admin said what
    # that is: a 14-digit tax id is not a card number)
    custom_cover = sorted((s, e) for s, e, _ in custom)
    blocking: List[str] = []
    for s, e, label in sorted(custom + builtin):
        if actions.get(label) != "block" or label in blocking:
            continue
        if label not in custom_labels and _covered((s, e), custom_cover):
            continue
        blocking.append(label)
    if blocking and not mask_only:
        return FirewallResult(
            masked_text="",
            flags=[f"blocked_pii:{label.lower()}" for label in blocking],
            blocked=True,
            blocked_reason=f"Prompt contains {', '.join(blocking)}, which this organization blocks",
            timed_out=timed_out,
            term_hits=term_hits,
        )

    flags: List[str] = list(term_flags)
    for _, _, label in accepted:
        f = f"masked:{label.lower()}"
        if f not in flags:
            flags.append(f)

    masked_text = _apply_masks(text, accepted)

    return FirewallResult(masked_text=masked_text, flags=flags, blocked=False, timed_out=timed_out,
                          term_hits=term_hits)
