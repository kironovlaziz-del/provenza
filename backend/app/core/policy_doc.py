# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Hierarchical policy documents (pure functions; services/hier_policy.py
stores and applies them).

A document is the same shape at every level - organization, team (and its
sub-teams), agent - written as YAML or through the forms:

    limits:
      requests_per_minute: 30      # gateway calls per agent per minute
      max_tokens: 2000             # gateway completion cap
      max_delegation_depth: 2
    models:     {allow: ["gpt-4o-mini", "claude-*"]}
    providers:  {allow: ["openai"]}
    tools:      {allow: ["kb.*"], deny: ["shell.*"], require_approval: ["email.send"]}
    content:    {scan_output: true}
    requests:   {require_approval: true}

Blocked terms are not part of a policy document: they are kept on the
Blocked terms page (services/blocked_terms.py), with their own scopes.

Levels combine so that a lower one can only TIGHTEN what is above it:
  * limits                 the smallest wins
  * allow lists            every level's list must allow the value
                           (a level without one does not restrict)
  * deny / approval lists  all of them apply
  * switches               on anywhere = on
A lower level trying to loosen (a higher limit, a switch turned off, a
model the level above does not allow) has no effect; resolve() reports it
under "ignored" so the editor can say so. Every effective value carries the
level it came from.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional, Sequence, Tuple

MAX_YAML_BYTES = 32 * 1024
MAX_LIST = 500
MAX_ITEM = 200
MAX_NESTING = 10


class PolicyDocError(ValueError):
    def __init__(self, code: str, path: str = "", detail: str = ""):
        super().__init__(f"{code} at {path}: {detail}" if path else code)
        self.code = code
        self.path = path
        self.detail = detail


# (section, key) -> (how levels combine, type, bounds)
FIELDS: Dict[Tuple[str, str], Tuple[str, str, Any]] = {
    ("limits", "requests_per_minute"): ("min", "int", (1, 100_000)),
    ("limits", "max_tokens"): ("min", "int", (1, 1_000_000)),
    ("limits", "max_delegation_depth"): ("min", "int", (0, 10)),
    ("models", "allow"): ("allow", "patterns", None),
    ("providers", "allow"): ("allow", "patterns", None),
    ("tools", "allow"): ("allow", "patterns", None),
    ("tools", "deny"): ("union", "patterns", None),
    ("tools", "require_approval"): ("union", "patterns", None),
    ("content", "scan_output"): ("or", "bool", None),
    ("requests", "require_approval"): ("or", "bool", None),
}
SECTIONS = ["limits", "models", "providers", "tools", "content", "requests"]
assert set(SECTIONS) == {s for s, _ in FIELDS}
TOP_LEVEL = set(SECTIONS) | {"version", "description"}


# ------------------------------------------------------------------- YAML
def _refuse_aliases(yaml, text: str) -> None:
    """No anchors or aliases: a few lines of aliases can expand into
    gigabytes ("billion laughs"), and a policy never needs them. Checked on
    the parser's events, before anything is built from the text."""
    for ev in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(ev, yaml.AliasEvent) or getattr(ev, "anchor", None):
            raise PolicyDocError("policy.yaml_alias", f"line {ev.start_mark.line + 1}",
                                 "anchors and aliases are not allowed")


def parse_yaml(text: str) -> Dict[str, Any]:
    if text is None or not text.strip():
        return {}
    if len(text.encode("utf-8")) > MAX_YAML_BYTES:
        raise PolicyDocError("policy.too_large", "", f"at most {MAX_YAML_BYTES // 1024} KiB")
    import yaml

    # a policy is two levels deep; deeply nested brackets would only exhaust
    # the parser's recursion (a 500) - refuse them before parsing
    depth = deepest = 0
    for ch in text:
        if ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    if deepest > MAX_NESTING:
        raise PolicyDocError("policy.too_deep", "", f"at most {MAX_NESTING} levels of brackets")
    try:
        _refuse_aliases(yaml, text)
        doc = yaml.safe_load(text)
    except PolicyDocError:
        raise
    except RecursionError:
        raise PolicyDocError("policy.too_deep", "", "nested too deeply")
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise PolicyDocError("policy.yaml_syntax", where, str(getattr(e, "problem", "") or e)[:200])
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise PolicyDocError("policy.not_a_mapping", "", "the document must be a mapping (key: value)")
    return doc


def to_yaml(doc: Dict[str, Any]) -> str:
    import yaml

    ordered = {}
    for k in ["version", "description", *SECTIONS]:
        if k in doc:
            v = doc[k]
            if k in SECTIONS:  # keys in the order the schema lists them
                v = {key: v[key] for (sec, key) in FIELDS if sec == k and key in v}
            ordered[k] = v
    return yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, default_flow_style=False) if ordered else ""


# ------------------------------------------------------------------- validation
def _patterns(value: Any, path: str, kind: str) -> List[str]:
    if not isinstance(value, list):
        raise PolicyDocError("policy.expected_list", path)
    if len(value) > MAX_LIST:
        raise PolicyDocError("policy.list_too_long", path, f"at most {MAX_LIST} entries")
    out: List[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise PolicyDocError("policy.expected_text", f"{path}[{i}]")
        item = item.strip()
        if len(item) > MAX_ITEM:
            raise PolicyDocError("policy.text_too_long", f"{path}[{i}]", f"at most {MAX_ITEM} characters")
        if kind == "terms":
            item = item.lower()  # the firewall matches terms case-insensitively
        if item not in out:
            out.append(item)
    return out


def validate(doc: Any) -> Dict[str, Any]:
    """The document, checked and normalized. Unknown keys are errors: a
    misspelt rule that silently applied nothing would be worse."""
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise PolicyDocError("policy.not_a_mapping", "")
    out: Dict[str, Any] = {}
    for key, value in doc.items():
        if key not in TOP_LEVEL:
            raise PolicyDocError("policy.unknown_key", str(key))
        if key == "version":
            if isinstance(value, bool) or value != 1:
                raise PolicyDocError("policy.bad_version", "version", "only version 1 exists")
            out["version"] = 1
            continue
        if key == "description":
            if value is not None and (not isinstance(value, str) or len(value) > 2000):
                raise PolicyDocError("policy.expected_text", "description")
            if value:
                out["description"] = value
            continue
        if value is None:
            continue
        if not isinstance(value, dict):
            raise PolicyDocError("policy.not_a_mapping", key)
        section: Dict[str, Any] = {}
        for sub, v in value.items():
            spec = FIELDS.get((key, sub))
            path = f"{key}.{sub}"
            if spec is None:
                if path == "content.blocked_terms":
                    raise PolicyDocError("policy.blocked_terms_moved", path,
                                         "blocked terms are kept on the Blocked terms page")
                raise PolicyDocError("policy.unknown_key", path)
            if v is None:
                continue
            _, typ, bounds = spec
            if typ == "int":
                if isinstance(v, bool) or not isinstance(v, int):
                    raise PolicyDocError("policy.expected_integer", path)
                lo, hi = bounds
                if not lo <= v <= hi:
                    raise PolicyDocError("policy.out_of_range", path, f"{lo}..{hi}")
                section[sub] = v
            elif typ == "bool":
                if not isinstance(v, bool):
                    raise PolicyDocError("policy.expected_boolean", path)
                section[sub] = v
            else:
                section[sub] = _patterns(v, path, typ)
        if section:
            out[key] = section
    return out


def from_yaml(text: str) -> Dict[str, Any]:
    return validate(parse_yaml(text))


# ------------------------------------------------------------------- resolution
def matches(value: str, patterns: Sequence[str]) -> bool:
    v = (value or "").lower()
    return any(fnmatch.fnmatchcase(v, p.lower()) for p in patterns)


def resolve(layers: Sequence[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """Combine (source, document) levels, top first. Returns
    {"fields": {"section.key": ...}, "ignored": [...]} where a field is
      min:   {"value", "source"}
      or:    {"value", "source"}
      allow: {"constraints": [{"source", "patterns"}]}  - every one must match
      union: {"items": [{"value", "source"}]}"""
    fields: Dict[str, Any] = {}
    ignored: List[Dict[str, Any]] = []
    for source, doc in layers:
        for (section, key), (mode, _typ, _b) in FIELDS.items():
            if key not in (doc.get(section) or {}):
                continue
            v = doc[section][key]
            name = f"{section}.{key}"
            cur = fields.get(name)
            if mode == "min":
                if cur is None or v < cur["value"]:
                    fields[name] = {"value": v, "source": source}
                elif v > cur["value"]:
                    ignored.append({"field": name, "source": source, "value": v,
                                    "because": cur["source"], "kept": cur["value"]})
            elif mode == "or":
                if cur is None or (v and not cur["value"]):
                    fields[name] = {"value": v, "source": source}
                elif cur["value"] and not v:
                    ignored.append({"field": name, "source": source, "value": v,
                                    "because": cur["source"], "kept": True})
            elif mode == "allow":
                cur = fields.setdefault(name, {"constraints": []})
                # entries the levels above do not allow cannot be granted here
                for p in v:
                    if "*" in p or "?" in p or "[" in p:
                        continue
                    blocked_by = next((c for c in cur["constraints"] if not matches(p, c["patterns"])), None)
                    if blocked_by is not None:
                        ignored.append({"field": name, "source": source, "value": p,
                                        "because": blocked_by["source"], "kept": None})
                cur["constraints"].append({"source": source, "patterns": list(v)})
            else:  # union
                cur = fields.setdefault(name, {"items": []})
                have = {i["value"] for i in cur["items"]}
                cur["items"] += [{"value": p, "source": source} for p in v if p not in have]
    return {"fields": fields, "ignored": ignored}


class Effective:
    """Read helpers over resolve()'s output, for the places that enforce it."""

    def __init__(self, resolved: Dict[str, Any]):
        self.fields = resolved.get("fields", {})
        self.ignored = resolved.get("ignored", [])

    def limit(self, name: str) -> Optional[int]:
        f = self.fields.get(name)
        return f["value"] if f else None

    def switch(self, name: str) -> bool:
        f = self.fields.get(name)
        return bool(f and f["value"])

    def source(self, name: str) -> Optional[str]:
        f = self.fields.get(name)
        return f.get("source") if f else None

    def refusing(self, name: str, value: str) -> Optional[str]:
        """For an allow list: the source of the first level that does not
        allow `value`, or None when every level allows it."""
        for c in (self.fields.get(name) or {}).get("constraints", []):
            if not matches(value, c["patterns"]):
                return c["source"]
        return None

    def refusing_any(self, name: str, values: Sequence[str]) -> Optional[str]:
        """Like refusing(), where a level allows the thing when any of its
        names matches (a provider by name or by type)."""
        for c in (self.fields.get(name) or {}).get("constraints", []):
            if not any(matches(v, c["patterns"]) for v in values if v):
                return c["source"]
        return None

    def listed(self, name: str, value: str) -> Optional[str]:
        """For a union list of patterns: the source of an entry matching
        `value`, or None."""
        for item in (self.fields.get(name) or {}).get("items", []):
            if matches(value, [item["value"]]):
                return item["source"]
        return None

    def items(self, name: str) -> List[str]:
        return [i["value"] for i in (self.fields.get(name) or {}).get("items", [])]
