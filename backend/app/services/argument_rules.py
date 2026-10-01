# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Argument-level tool constraints - OWASP Agentic Top 10, ASI02 (tool misuse).

A tool allowlist says WHICH tools an agent may call; these rules say WHAT
it may call them with. Each rule is a constraint that must hold; when it
does not, the rule's effect applies:

    {"tool": "db.query",    "arg": "sql",    "op": "not_matches",
     "value": "(?i)\\b(drop|delete|truncate)\\b",   "effect": "deny"}
    {"tool": "email.send",  "arg": "to",     "op": "domain_in",
     "value": ["corp.example"],                      "effect": "deny"}
    {"tool": "file.*",      "arg": "path",   "op": "starts_with",
     "value": ["/sandbox/"],                         "effect": "deny"}
    {"tool": "payments.*",  "arg": "amount", "op": "max",
     "value": 100,                                   "effect": "require_approval"}

Design choices, all fail-closed:
  - a constrained argument that is missing violates the rule (otherwise the
    rule is bypassed by simply omitting the field)
  - a list value must satisfy the constraint for EVERY element
  - paths are normalised before prefix checks ("/sandbox/../etc" -> "/etc")
  - regex subjects longer than MAX_SUBJECT violate the rule (no hiding a
    forbidden keyword after the first 10k characters)
  - an invalid rule that slipped into storage violates instead of passing
  - patterns are length-limited and nested quantifiers are rejected at save
    time to keep catastrophic backtracking out
"""

import fnmatch
import posixpath
import re
from functools import lru_cache
from typing import Any, List, Optional, Tuple

OPS = {"equals", "in", "not_in", "max", "min", "max_length", "starts_with", "domain_in", "matches", "not_matches"}
LIST_OPS = {"in", "not_in", "starts_with", "domain_in"}
NUMERIC_OPS = {"max", "min", "max_length"}
REGEX_OPS = {"matches", "not_matches"}
EFFECTS = {"deny", "require_approval"}

MAX_RULES = 100
MAX_PATTERN = 300
MAX_SUBJECT = 10_000

# (x+)+, (a*)*, (a|b+){2,} ... - the classic catastrophic-backtracking shapes
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*{]")
_MISSING = object()


class RuleError(ValueError):
    """Invalid argument rule (surfaced to the API as a 422)."""


# ---------------------------------------------------------------------- validation
def _check_pattern(pattern: Any, where: str) -> None:
    if not isinstance(pattern, str) or not pattern:
        raise RuleError(f"{where}: a regular expression string is required")
    if len(pattern) > MAX_PATTERN:
        raise RuleError(f"{where}: regular expression is longer than {MAX_PATTERN} characters")
    if _NESTED_QUANTIFIER.search(pattern):
        raise RuleError(f"{where}: nested quantifiers such as (a+)+ are not allowed (catastrophic backtracking)")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"{where}: invalid regular expression: {exc}") from None


def validate_argument_rules(rules: Any) -> None:
    if not isinstance(rules, list):
        raise RuleError("argument_rules must be a list")
    if len(rules) > MAX_RULES:
        raise RuleError(f"at most {MAX_RULES} argument rules per policy")
    for i, rule in enumerate(rules):
        where = f"argument_rules[{i}]"
        if not isinstance(rule, dict):
            raise RuleError(f"{where}: must be an object")
        for key in ("tool", "arg", "op", "value"):
            if key not in rule:
                raise RuleError(f"{where}: '{key}' is required")
        tool, arg, op, value = rule["tool"], rule["arg"], rule["op"], rule["value"]
        if not isinstance(tool, str) or not tool.strip():
            raise RuleError(f"{where}: 'tool' must be a non-empty string (glob allowed, e.g. payments.*)")
        if (not isinstance(arg, str) or not arg.strip() or arg.startswith(".")
                or arg.endswith(".") or ".." in arg):
            raise RuleError(f"{where}: 'arg' must be a field name or dotted path, e.g. options.recipients")
        if op not in OPS:
            raise RuleError(f"{where}: unknown op '{op}' (allowed: {', '.join(sorted(OPS))})")
        effect = rule.get("effect", "deny")
        if effect not in EFFECTS:
            raise RuleError(f"{where}: effect must be 'deny' or 'require_approval'")
        if op in LIST_OPS:
            ok = (isinstance(value, str) and value.strip()) or (
                isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value))
            if not ok:
                raise RuleError(f"{where}: '{op}' needs a non-empty string or list of strings")
        if op in NUMERIC_OPS:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RuleError(f"{where}: '{op}' needs a number")
            if op == "max_length" and value < 0:
                raise RuleError(f"{where}: 'max_length' cannot be negative")
        if op in REGEX_OPS:
            _check_pattern(value, where)


# ---------------------------------------------------------------------- evaluation
@lru_cache(maxsize=512)
def _regex(pattern: str):
    return re.compile(pattern)


def _get(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _normalise(text: str) -> str:
    if "://" not in text and ("/" in text or ".." in text):
        normalised = posixpath.normpath(text)
        return normalised + "/" if text.endswith("/") and normalised != "/" else normalised
    return text


def _holds_one(op: str, item: Any, expected: Any) -> bool:
    if op == "equals":
        return item == expected
    if op == "in":
        return item in _as_list(expected)
    if op == "not_in":
        return item not in _as_list(expected)
    if op in ("max", "min"):
        number = _number(item)
        if number is None:
            return False
        return number <= expected if op == "max" else number >= expected
    if op == "max_length":
        return len(item if isinstance(item, str) else str(item)) <= expected

    if not isinstance(item, str):
        return False
    if op == "starts_with":
        path = _normalise(item)
        return any(path.startswith(p) or path == p.rstrip("/") for p in _as_list(expected))
    if op == "domain_in":
        if "@" not in item:
            return False
        domain = item.rsplit("@", 1)[1].strip().rstrip(">").rstrip(".").lower()
        allowed = [d.strip().lower().lstrip("@").lstrip(".") for d in _as_list(expected)]
        return any(domain == d or domain.endswith("." + d) for d in allowed)
    if op in REGEX_OPS:
        if len(item) > MAX_SUBJECT:
            return False
        found = _regex(expected).search(item) is not None
        return found if op == "matches" else not found
    return False


def _holds(op: str, actual: Any, expected: Any) -> bool:
    return all(_holds_one(op, item, expected) for item in _as_list(actual))


def _describe(rule: dict) -> str:
    value = repr(rule.get("value"))
    if len(value) > 80:
        value = value[:77] + "..."
    return f"argument '{rule.get('arg')}' must satisfy {rule.get('op')} {value}"


def evaluate_argument_rules(rules: List[dict], tool: Optional[str], input_data: Any) -> Tuple[str, Optional[str]]:
    """Returns ("ok" | "deny" | "approval", human-readable reason or None).
    A deny wins over an approval; the first violated rule of the winning
    effect provides the reason."""
    verdict, detail = "ok", None
    for rule in rules or []:
        if not isinstance(rule, dict) or not fnmatch.fnmatchcase(tool or "", str(rule.get("tool", ""))):
            continue
        actual = _get(input_data if isinstance(input_data, dict) else {}, str(rule.get("arg", "")))
        if actual is _MISSING:
            holds, why = False, f"argument '{rule.get('arg')}' is required by policy but missing"
        else:
            try:
                holds = _holds(rule.get("op"), actual, rule.get("value"))
            except (re.error, TypeError, ValueError):
                holds = False  # a broken stored rule fails closed
            why = _describe(rule)
        if holds:
            continue
        if rule.get("effect", "deny") == "require_approval":
            if verdict == "ok":
                verdict, detail = "approval", why
        else:
            return "deny", why
    return verdict, detail
