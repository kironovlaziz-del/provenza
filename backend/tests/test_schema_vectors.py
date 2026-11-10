# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
sdk/testdata/schema-vectors.json: the deep check of HTTP tool arguments
(app/pvp/schema_check.py) and the form body - the egress proxy
(proxy/internal/egress/schema_test.go) answers the same.
"""

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.pvp.http_tools import argument_problems, build_request
from app.pvp.schema_check import json_equal, schema_problems

V = json.loads((Path(__file__).resolve().parents[2] / "sdk" / "testdata" / "schema-vectors.json").read_text("utf-8"))


def _value(v):
    if isinstance(v, str) and v.startswith("DEEP"):
        out = "leaf"
        for _ in range(int(v[4:])):
            out = {"x": out}
        return out
    return v


@pytest.mark.parametrize("group", V["groups"], ids=[g["name"] for g in V["groups"]])
def test_values(group):
    for case in group["cases"]:
        problems = argument_problems(group["schema"], _value(case["value"]), "https://api.example/x")
        assert (not problems) == case["valid"], (case, problems)


def test_schemas_refused_and_accepted():
    for s in V["schemas_refused"]:
        assert schema_problems(s), s
    for s in V["schemas_accepted"]:
        assert schema_problems(s) == [], (s, schema_problems(s))


def test_form_bodies():
    for case in V["form"]:
        tool = SimpleNamespace(method="POST", url="https://api.example/x", body_encoding="form")
        problems = argument_problems(None, case["arguments"], tool.url, "form")
        assert bool(problems) == case["refused"], (case, problems)
        if not problems:
            assert build_request(tool, case["arguments"])[2].decode("ascii") == case["body"]


def test_json_equality_tells_true_from_one():
    assert json_equal(1, 1.0) and not json_equal(True, 1) and not json_equal([1], [True])
    assert json_equal({"a": [1, None]}, {"a": [1.0, None]}) and not json_equal({"a": 1}, {"a": 1, "b": 2})


def test_a_pattern_cannot_stall_the_check():
    """(a+)+$ against a long run of a's and a b: exponential in a backtracking engine, linear in RE2."""
    schema = {"type": "object", "properties": {"s": {"type": "string", "pattern": "^(a+)+$"}}}
    started = time.monotonic()
    assert argument_problems(schema, {"s": "a" * 100_000 + "b"}, "https://api.example/x")
    assert time.monotonic() - started < 2


def test_a_schema_too_large_or_too_deep_is_refused():
    deep = {"type": "string"}
    for _ in range(20):
        deep = {"type": "object", "properties": {"x": deep}}
    assert schema_problems(deep)
    wide = {"type": "object", "properties": {f"p{i}": {"type": "string", "description": "x" * 100} for i in range(1000)}}
    assert schema_problems(wide)
