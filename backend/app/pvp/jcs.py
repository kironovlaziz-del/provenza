# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
RFC 8785 JSON Canonicalization Scheme (JCS) - for the TRACE export only.

PVP's own signatures keep Provenza's canonical form (app/core/agent_signing.py:
sorted keys, ASCII with \\uXXXX escapes). TRACE hashes and signs JCS, which
differs in three ways, all implemented here without a dependency:

  - strings are UTF-8, escaping only what JSON requires (quote, backslash,
    U+0000..U+001F, the short forms \\b \\f \\n \\r \\t, else \\u00xx lowercase);
  - object members are sorted by their names' UTF-16 code units (not code
    points: U+1F600 sorts before U+FB33);
  - numbers use the ECMAScript Number-to-String algorithm (shortest
    round-trip digits; exponent form below 1e-6 and from 1e21 up).

I-JSON limits apply: integers within +-(2^53 - 1), no NaN / Infinity, no
lone surrogates. Anything else raises ValueError.
"""

import json
import math
from decimal import Decimal
from typing import Any

MAX_SAFE = 2 ** 53 - 1


def _number(x: Any) -> str:
    if isinstance(x, int):
        if abs(x) > MAX_SAFE:
            raise ValueError(f"integer outside the I-JSON range: {x}")
        return str(x)
    if not math.isfinite(x):
        raise ValueError("NaN and Infinity have no JSON form")
    if x == 0:
        return "0"  # also -0
    sign = "-" if x < 0 else ""
    # shortest round-trip digits (Python's repr is that), as digits + exponent
    _, digits, exp = Decimal(repr(abs(x))).as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    s = "".join(map(str, digits))
    k, n = len(s), exp + len(s)  # value = 0.s * 10^n
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e = n - 1
    mantissa = s[0] + ("." + s[1:] if k > 1 else "")
    return f"{sign}{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"


def _string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("lone surrogate in a string") from exc
    return json.dumps(s, ensure_ascii=False)


def _serialize(v: Any, out: list) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, (int, float)):
        out.append(_number(v))
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise ValueError("object member names must be strings")
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda name: name.encode("utf-16-be", "surrogatepass"))):
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _serialize(v[k], out)
        out.append("}")
    else:
        raise ValueError(f"not a JSON value: {type(v).__name__}")


def canonicalize(value: Any) -> bytes:
    out: list = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")
