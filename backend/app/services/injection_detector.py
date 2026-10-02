# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Prompt-injection detector - OWASP Agentic Top 10, ASI01 (agent goal hijack).

Pure functions, no database: the same code scans tool arguments on
/actions/check, tool outputs on /actions/record and text pasted into the
UI tester.

Each pattern has a weight; a label counts once however often it matches.
The score (capped at 100) gives the verdict:

    score >= threshold (default 60)  -> "injection"
    score >= 30                      -> "suspicious"
    otherwise                        -> "clean"

Before matching, text is NFKC-normalised and invisible characters are
removed, so "ign<U+200B>ore previous instructions" (with a zero-width space) is still caught; the
invisible characters themselves are separate signals. Hidden text encoded
with Unicode tag characters and base64 blobs is decoded and scanned too.

Every regex has bounded gaps ({0,40}) - no catastrophic backtracking -
and at most MAX_TEXT characters of a value are scanned.
"""

import base64
import binascii
import re
import unicodedata
from typing import Any, Dict, List, Optional

MAX_TEXT = 100_000
MAX_NODES = 2_000
MAX_DEPTH = 20
SUSPICIOUS = 30
DEFAULT_THRESHOLD = 60
SNIPPET = 80

_F = re.IGNORECASE | re.UNICODE
_FM = _F | re.MULTILINE

# (label, weight, compiled regexes)
PATTERNS = [
    ("instruction_override", 60, [
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip)\b.{0,40}?"
            r"\b(?:previous|prior|above|earlier|preceding|all|any|your|the|system|original)\b.{0,40}?"
            r"\b(?:instructions?|prompts?|rules?|directives?|guidelines?|guardrails?|context|messages?)\b", _F),
        re.compile(
            r"(?:игнорир\w*|проигнорир\w*|забудь\w*|забудьте|не\s+обращай\w*|отмени\w*|пренебреги\w*)"
            r".{0,40}?(?:предыдущ\w*|прошл\w*|выше|вс[её]|ранее|прежн\w*|систем\w*|сво[иё]\w*|ваш\w*)"
            r".{0,40}?(?:инструкц\w*|указани\w*|правил\w*|промпт\w*|команд\w*|ограничени\w*)", _F),
    ]),
    ("role_switch", 40, [
        re.compile(
            r"\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you|you\s+are\s+no\s+longer|pretend\s+(?:that\s+)?you\s+are"
            r"|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|dan\b|developer\s+mode)"
            r"|new\s+(?:system\s+)?instructions?\s*:|developer\s+mode\s+(?:enabled|on))", _F),
        re.compile(r"(?:теперь\s+ты\b|отныне\s+ты\b|ты\s+больше\s+не\b|новые\s+инструкции\s*:|представь,?\s+что\s+ты\b)", _F),
    ]),
    ("system_marker", 40, [
        re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|<</?SYS>>", _F),
        re.compile(r"^\s*(?:system|assistant)\s*:\s*\S", _FM),
        re.compile(r"^\s*#{2,}\s*(?:system|instructions?|new\s+task)\b", _FM),
    ]),
    ("exfil_link", 50, [
        re.compile(r"!\[[^\]\n]{0,100}\]\(\s*https?://[^\s)]{1,300}\?[^\s)]{0,300}=[^\s)]{0,300}\)", _F),
        re.compile(r"<img\b[^>]{0,200}\bsrc\s*=\s*[\"']?https?://[^\"'>\s]{1,300}\?[^\"'>\s]{0,300}=", _F),
    ]),
    ("secret_request", 40, [
        re.compile(
            r"\b(?:reveal|print|show|output|repeat|leak|send|disclose|dump|exfiltrate)\b.{0,40}?"
            r"\b(?:system\s+prompt|your\s+(?:instructions|prompt|rules)|api[\s_-]?keys?|secrets?|passwords?"
            r"|credentials|access\s+tokens?|private\s+keys?)\b", _F),
        re.compile(
            r"(?:покажи|выведи|раскрой|отправь|повтори|сообщи)\w*.{0,40}?"
            r"(?:системн\w*\s+промпт\w*|сво\w*\s+инструкц\w*|api[\s_-]?ключ\w*|ключ\w*\s+api|парол\w*|секрет\w*|токен\w*)", _F),
    ]),
    ("tool_hijack", 20, [
        re.compile(r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function|command)\b", _F),
        re.compile(r"\brm\s+-rf\s+/|\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:ba|z)?sh\b", _F),
    ]),
]

# invisible / smuggling characters
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u180e"))
_ZW_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u180e]")
_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
_TAG_RE = re.compile("[\U000e0000-\U000e007f]+")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

WEIGHTS: Dict[str, int] = {label: w for label, w, _ in PATTERNS}
WEIGHTS.update({"unicode_tags": 60, "zero_width": 30, "bidi_override": 30, "encoded_payload": 60})


def _snippet(s: str) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= SNIPPET else s[: SNIPPET - 1] + "…"


def _verdict(score: int, threshold: int) -> str:
    if score >= threshold:
        return "injection"
    if score >= SUSPICIOUS:
        return "suspicious"
    return "clean"


def _match_patterns(text: str, findings: Dict[str, dict]) -> None:
    for label, weight, regexes in PATTERNS:
        if label in findings:
            continue
        for rx in regexes:
            m = rx.search(text)
            if m:
                findings[label] = {"label": label, "weight": weight, "snippet": _snippet(m.group(0))}
                break


def scan_text(text: Any, threshold: int = DEFAULT_THRESHOLD) -> dict:
    """Scan one text. Returns {verdict, score, findings: [{label, weight, snippet}], truncated}."""
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    truncated = len(text) > MAX_TEXT
    raw = text[:MAX_TEXT]
    findings: Dict[str, dict] = {}

    # hidden channels first, on the raw text
    tags = _TAG_RE.findall(raw)
    if tags:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in "".join(tags) if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        findings["unicode_tags"] = {"label": "unicode_tags", "weight": WEIGHTS["unicode_tags"],
                                    "snippet": _snippet("hidden: " + hidden) if hidden else "hidden tag characters"}
    zw = len(_ZW_RE.findall(raw))
    if zw >= 3:
        findings["zero_width"] = {"label": "zero_width", "weight": WEIGHTS["zero_width"],
                                  "snippet": f"{zw} zero-width characters"}
    bidi = len(_BIDI_RE.findall(raw))
    if bidi:
        findings["bidi_override"] = {"label": "bidi_override", "weight": WEIGHTS["bidi_override"],
                                     "snippet": f"{bidi} bidirectional override characters"}

    # visible text, normalised; tag-encoded text is scanned as well
    clean = unicodedata.normalize("NFKC", _TAG_RE.sub("", raw)).translate(_ZERO_WIDTH)
    clean = _BIDI_RE.sub("", clean)
    _match_patterns(clean, findings)
    if tags:
        _match_patterns("".join(chr(ord(c) - 0xE0000) for c in "".join(tags)), findings)

    # base64 blobs that decode to an instruction
    if "encoded_payload" not in findings:
        for blob in _B64_RE.findall(clean)[:5]:
            try:
                decoded = base64.b64decode(blob[:4000] + "=" * (-len(blob[:4000]) % 4), validate=False)
                inner = decoded.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            sub: Dict[str, dict] = {}
            _match_patterns(inner, sub)
            if any(k in sub for k in ("instruction_override", "role_switch", "system_marker", "secret_request")):
                first = next(iter(sub.values()))
                findings["encoded_payload"] = {"label": "encoded_payload", "weight": WEIGHTS["encoded_payload"],
                                               "snippet": _snippet("base64: " + first["snippet"])}
                break

    score = min(100, sum(f["weight"] for f in findings.values()))
    ordered = sorted(findings.values(), key=lambda f: -f["weight"])
    return {"verdict": _verdict(score, threshold), "score": score, "findings": ordered, "truncated": truncated}


def scan_structure(obj: Any, threshold: int = DEFAULT_THRESHOLD) -> dict:
    """Scan every string value (and string key) of a JSON-like structure.

    Returns the worst verdict/score and the non-clean hits with their paths:
    {verdict, score, path, hits: [{path, verdict, score, findings}]}.
    """
    hits: List[dict] = []
    nodes = 0

    def visit(node: Any, path: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return
        if isinstance(node, str):
            r = scan_text(node, threshold)
            if r["verdict"] != "clean":
                hits.append({"path": path or "$", **r})
        elif isinstance(node, dict):
            for k, v in node.items():
                key = str(k)
                if len(key) > 20:  # an instruction smuggled as a key
                    r = scan_text(key, threshold)
                    if r["verdict"] != "clean":
                        hits.append({"path": (path + "." if path else "") + "<key>", **r})
                visit(v, f"{path}.{key}" if path else key, depth + 1)
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                visit(v, f"{path}[{i}]", depth + 1)

    visit(obj, "", 0)
    hits.sort(key=lambda h: -h["score"])
    worst: Optional[dict] = hits[0] if hits else None
    return {
        "verdict": worst["verdict"] if worst else "clean",
        "score": worst["score"] if worst else 0,
        "path": worst["path"] if worst else None,
        "hits": hits[:20],
    }
