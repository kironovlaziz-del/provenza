# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The input schema of an HTTP tool, checked deeply - the same rules here and in
the egress proxy (proxy/internal/egress/schema.go), tested against the same
vectors (sdk/testdata/schema-vectors.json).

A small, strict subset of JSON Schema:

  validation   type, enum, const, properties, required, additionalProperties
               (true / false / a schema), items (one schema), minItems,
               maxItems, minLength, maxLength, pattern, minimum, maximum,
               exclusiveMinimum, exclusiveMaximum (numbers)
  annotations  title, description, default, examples, format, $schema,
               $comment, deprecated, readOnly, writeOnly - read by nobody

Any other keyword ($ref, anyOf, oneOf, allOf, not, if, patternProperties, ...)
is refused when the tool is saved, and a call against a schema that holds one
is refused too: a check that skipped what it does not know would let through
what the schema meant to stop.

  pattern  RE2 (google-re2 here, regexp in Go): linear time, so no pattern can
           stall the server, and the same meaning in both (\\d is 0-9, $ is the
           end of the text); a pattern searches, it is not anchored
  numbers  integers compared exactly, any other number as a float64 - in both
  strings  lengths in code points
  limits   schema nesting 16, 1000 subschemas, 64 KB; arguments nesting 32
"""

import json
import math
from typing import Any, List, Optional

import re2

ANNOTATIONS = frozenset({"title", "description", "default", "examples", "format", "$schema", "$comment",
                         "deprecated", "readOnly", "writeOnly"})
KEYWORDS = frozenset({"type", "enum", "const", "properties", "required", "additionalProperties", "items",
                      "minItems", "maxItems", "minLength", "maxLength", "pattern", "minimum", "maximum",
                      "exclusiveMinimum", "exclusiveMaximum"})
TYPES = ("string", "integer", "number", "boolean", "object", "array", "null")

MAX_SCHEMA_DEPTH = 16
MAX_SUBSCHEMAS = 1000
MAX_SCHEMA_BYTES = 64 * 1024
MAX_VALUE_DEPTH = 32
MAX_PATTERN = 512
MAX_COUNT = 1_000_000          # minLength, maxItems, ...: a sane upper bound
MAX_PROBLEMS = 20

_RE2 = re2.Options()
_RE2.log_errors = False
_compiled: dict = {}


def _pattern(p: str):
    rx = _compiled.get(p)
    if rx is None:
        rx = re2.compile(p, _RE2)
        if len(_compiled) < 512:
            _compiled[p] = rx
    return rx


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and not (isinstance(v, float) and not math.isfinite(v))


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_COUNT


def json_equal(a: Any, b: Any) -> bool:
    """Equality of JSON values: true is not 1, 1 is 1.0."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_number(a) and _is_number(b):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


# ---------------------------------------------------------------- the schema


def schema_problems(schema: Any) -> List[str]:
    """Why `schema` is not a schema this check understands ([] = it is)."""
    try:
        size = len(json.dumps(schema, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError):
        return ["the schema is not plain JSON"]
    if size > MAX_SCHEMA_BYTES:
        return [f"the schema is larger than {MAX_SCHEMA_BYTES // 1024} KB"]
    problems: List[str] = []
    count = [0]
    _check_schema(schema, "", 0, problems, count)
    return problems[:MAX_PROBLEMS]


def _check_schema(s: Any, at: str, depth: int, problems: List[str], count: list) -> None:
    where = at or "the schema"
    count[0] += 1
    if count[0] > MAX_SUBSCHEMAS:
        if count[0] == MAX_SUBSCHEMAS + 1:
            problems.append(f"the schema has more than {MAX_SUBSCHEMAS} parts")
        return
    if depth > MAX_SCHEMA_DEPTH:
        problems.append(f"{where} is nested deeper than {MAX_SCHEMA_DEPTH}")
        return
    if not isinstance(s, dict):
        problems.append(f"{where} is not an object")
        return
    for key, v in s.items():
        if key in ANNOTATIONS:
            continue
        if key not in KEYWORDS:
            problems.append(f"{where}: '{key}' is not supported")
            continue
        if key == "type":
            names = v if isinstance(v, list) else [v]
            if not names or any(n not in TYPES for n in names) or len(set(map(str, names))) != len(names):
                problems.append(f"{where}: type must be one of {', '.join(TYPES)}, or a list of them")
        elif key == "enum":
            if not isinstance(v, list) or not v:
                problems.append(f"{where}: enum must be a non-empty list")
        elif key == "properties":
            if not isinstance(v, dict):
                problems.append(f"{where}: properties must be an object")
            else:
                for name, sub in v.items():
                    _check_schema(sub, f"{at}.{name}" if at else name, depth + 1, problems, count)
        elif key == "required":
            if not isinstance(v, list) or not all(isinstance(n, str) for n in v) or len(set(v)) != len(v):
                problems.append(f"{where}: required must be a list of distinct names")
        elif key == "additionalProperties":
            if not isinstance(v, bool):
                _check_schema(v, f"{at}.*" if at else "*", depth + 1, problems, count)
        elif key == "items":
            _check_schema(v, f"{at}[]" if at else "[]", depth + 1, problems, count)
        elif key in ("minItems", "maxItems", "minLength", "maxLength"):
            if not _is_count(v):
                problems.append(f"{where}: {key} must be an integer from 0 to {MAX_COUNT}")
        elif key == "pattern":
            if not isinstance(v, str) or len(v) > MAX_PATTERN:
                problems.append(f"{where}: pattern must be a string of at most {MAX_PATTERN} characters")
            else:
                try:
                    _pattern(v)
                except re2.error:
                    problems.append(f"{where}: pattern is not a regular expression this check runs "
                                    f"(RE2: no look-around, no back-references)")
        elif key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if not _is_number(v):
                problems.append(f"{where}: {key} must be a number")
        # const: any JSON value


# ---------------------------------------------------------------- a value


def _type_ok(v: Any, name: str) -> bool:
    if name == "string":
        return isinstance(v, str)
    if name == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if name == "number":
        return _is_number(v)
    if name == "boolean":
        return isinstance(v, bool)
    if name == "object":
        return isinstance(v, dict)
    if name == "array":
        return isinstance(v, list)
    return v is None   # null


def _label(at: str) -> str:
    return f"argument '{at}'" if at else "the arguments"


def value_problems(schema: Any, value: Any) -> List[str]:
    """Why `value` does not match `schema` ([] = it does). A schema this check
    does not understand is a problem too - the call is refused, not waved through."""
    problems: List[str] = []
    _check_value(schema, value, "", 0, problems)
    return problems[:MAX_PROBLEMS]


def _check_value(s: Any, v: Any, at: str, depth: int, problems: List[str]) -> None:
    if len(problems) >= MAX_PROBLEMS:
        return
    if depth > MAX_VALUE_DEPTH or depth > MAX_SCHEMA_DEPTH:
        problems.append(f"{_label(at)} is nested too deeply")
        return
    if not isinstance(s, dict):
        problems.append(f"the schema of {_label(at)} is not an object")
        return
    unknown = [k for k in s if k not in KEYWORDS and k not in ANNOTATIONS]
    if unknown:
        problems.append(f"the schema of {_label(at)} uses '{unknown[0]}', which is not supported")
        return
    if "type" in s:
        names = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if any(n not in TYPES for n in names):
            problems.append(f"the schema of {_label(at)} has an unknown type")
            return
        if not any(_type_ok(v, n) for n in names):
            problems.append(f"{_label(at)} is not of type {s['type']}")
            return
    if "enum" in s and not (isinstance(s["enum"], list) and any(json_equal(v, e) for e in s["enum"])):
        problems.append(f"{_label(at)} is not one of the allowed values")
    if "const" in s and not json_equal(v, s["const"]):
        problems.append(f"{_label(at)} is not the allowed value")

    if isinstance(v, str):
        n = len(v)
        if _is_count(s.get("minLength")) and n < s["minLength"]:
            problems.append(f"{_label(at)} is shorter than {s['minLength']} characters")
        if _is_count(s.get("maxLength")) and n > s["maxLength"]:
            problems.append(f"{_label(at)} is longer than {s['maxLength']} characters")
        if "pattern" in s:
            p = s["pattern"]
            try:
                ok = isinstance(p, str) and len(p) <= MAX_PATTERN and _pattern(p).search(v) is not None
            except re2.error:
                ok = False
            if not ok:
                problems.append(f"{_label(at)} does not match the pattern")
    elif _is_number(v):
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if key in s:
                if not _is_number(s[key]):
                    problems.append(f"the schema of {_label(at)}: {key} is not a number")
                elif _num_fails(key, v, s[key]):
                    problems.append(f"{_label(at)} is out of range ({key} {s[key]})")
    elif isinstance(v, list):
        if _is_count(s.get("minItems")) and len(v) < s["minItems"]:
            problems.append(f"{_label(at)} has fewer than {s['minItems']} items")
        if _is_count(s.get("maxItems")) and len(v) > s["maxItems"]:
            problems.append(f"{_label(at)} has more than {s['maxItems']} items")
        if "items" in s:
            for i, item in enumerate(v):
                _check_value(s["items"], item, f"{at}[{i}]", depth + 1, problems)
    elif isinstance(v, dict):
        props = s.get("properties") if isinstance(s.get("properties"), dict) else {}
        required = s.get("required") if isinstance(s.get("required"), list) else []
        for name in required:
            if isinstance(name, str) and name not in v:
                problems.append(f"missing argument '{at + '.' if at else ''}{name}'")
        extra = s.get("additionalProperties", True)
        for name in sorted(v):
            sub_at = f"{at}.{name}" if at else name
            if name in props:
                _check_value(props[name], v[name], sub_at, depth + 1, problems)
            elif extra is False:
                problems.append(f"unexpected argument '{sub_at}'")
            elif isinstance(extra, dict):
                _check_value(extra, v[name], sub_at, depth + 1, problems)


def _num_fails(key: str, v: Any, bound: Any) -> bool:
    """Exact comparison: integers as integers, an integer against a float as
    Python compares them (Go: big.Float of the integer and of the float64)."""
    if key == "minimum":
        return v < bound
    if key == "maximum":
        return v > bound
    if key == "exclusiveMinimum":
        return v <= bound
    return v >= bound


def value_depth_ok(v: Any, limit: int = MAX_VALUE_DEPTH) -> bool:
    """The arguments are not nested deeper than `limit` (checked even without a schema)."""
    stack = [(v, 0)]
    while stack:
        x, d = stack.pop()
        if d > limit:
            return False
        if isinstance(x, dict):
            stack.extend((y, d + 1) for y in x.values())
        elif isinstance(x, list):
            stack.extend((y, d + 1) for y in x)
    return True
