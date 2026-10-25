# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A strict decoder for the CBOR (RFC 8949) WebAuthn uses: attestation objects
and COSE keys. Only what those contain is accepted - unsigned and negative
integers, byte and text strings, arrays, maps, false / true / null - with
definite lengths, at most MAX_DEPTH levels and MAX_ITEMS items. Anything
else (indefinite lengths, tags, floats, other simple values, duplicate map
keys, trailing bytes) is refused, so two parsers cannot read one input two
ways.
"""

from typing import Any, Tuple

MAX_DEPTH = 8
MAX_ITEMS = 1000


class CBORError(ValueError):
    pass


def _length(data: bytes, pos: int, info: int) -> Tuple[int, int]:
    if info < 24:
        return info, pos
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if info not in sizes:
        raise CBORError("indefinite or reserved length")
    n = sizes[info]
    if pos + n > len(data):
        raise CBORError("truncated")
    value = int.from_bytes(data[pos:pos + n], "big")
    if (n == 1 and value < 24) or (n > 1 and value < 1 << (8 * n // 2)):
        raise CBORError("non-minimal length")
    return value, pos + n


def _item(data: bytes, pos: int, depth: int, budget: list) -> Tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise CBORError("too deep")
    budget[0] -= 1
    if budget[0] < 0:
        raise CBORError("too many items")
    if pos >= len(data):
        raise CBORError("truncated")
    head = data[pos]
    major, info = head >> 5, head & 0x1F
    pos += 1
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if info not in simple:
            raise CBORError("unsupported simple value or float")
        return simple[info], pos
    value, pos = _length(data, pos, info)
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if pos + value > len(data):
            raise CBORError("truncated")
        raw = data[pos:pos + value]
        if major == 2:
            return raw, pos + value
        try:
            return raw.decode("utf-8"), pos + value
        except UnicodeDecodeError:
            raise CBORError("invalid text string")
    if major == 4:
        out = []
        for _ in range(value):
            item, pos = _item(data, pos, depth + 1, budget)
            out.append(item)
        return out, pos
    if major == 5:
        out = {}
        for _ in range(value):
            key, pos = _item(data, pos, depth + 1, budget)
            if not isinstance(key, (int, str)):
                raise CBORError("map key must be an integer or a text string")
            if key in out:
                raise CBORError("duplicate map key")
            out[key], pos = _item(data, pos, depth + 1, budget)
        return out, pos
    raise CBORError("tags are not supported")


def loads(data: bytes) -> Any:
    """One CBOR item filling `data` exactly."""
    value, pos = _item(bytes(data), 0, 0, [MAX_ITEMS])
    if pos != len(data):
        raise CBORError("trailing bytes")
    return value


def load_prefix(data: bytes) -> Tuple[Any, int]:
    """One CBOR item at the start of `data` and the number of bytes it used
    (authenticator data carries a COSE key followed by extensions)."""
    return _item(bytes(data), 0, 0, [MAX_ITEMS])
