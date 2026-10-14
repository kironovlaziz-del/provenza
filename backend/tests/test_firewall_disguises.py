# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The Prompt Firewall against disguised secrets (core/text_normalize.py):
what is undone, that it is masked where it stands in the original, and that
ordinary text is left alone.
"""

import base64
import time

import pytest

from app.core.text_normalize import encoded_runs, normalize, original_span
from app.services import prompt_firewall as pf

KEY = "sk-proj-" + "a1b2c3d4e5" * 3


@pytest.mark.parametrize("text,flag", [
    ("write to j o h n @ e x a m p l e . c o m", "deobfuscated:email"),
    ("john (at) example [dot] com", "deobfuscated:email"),
    ("john [at] example (dot) com", "deobfuscated:email"),
    ("john at example dot com", "deobfuscated:email"),
    (f"key {KEY[:5]}\u200b{KEY[5:]}", "deobfuscated:api_key"),                # a zero-width space inside
    ("ＡＫＩＡ１２３４５６７８９０ＡＢＣＤＥＦ", "deobfuscated:api_key"),          # full-width
    ("decode " + base64.b64encode(b"card 4111 1111 1111 1111").decode(), "decoded:base64:credit_card"),
    ("hex " + "john@example.com".encode().hex(), "decoded:hex:email"),
])
def test_disguised_secrets_are_masked(text, flag):
    r = pf.scan(text)
    assert not r.blocked and flag in r.flags, r.flags
    assert "[MASKED:" in r.masked_text


def test_masked_in_the_original_where_it_stands():
    text = "before j o h n @ e x a m p l e . c o m after"
    r = pf.scan(text)
    assert r.masked_text == "before [MASKED:EMAIL] after"


def test_a_disguised_type_set_to_block_blocks():
    cfg = pf.default_config()
    cfg.actions["EMAIL"] = "block"
    r = pf.scan("john (at) example [dot] com", pii=cfg)
    assert r.blocked and "blocked_pii:email" in r.flags and "deobfuscated:email" in r.flags


def test_a_blocked_term_in_base64_blocks():
    hidden = base64.b64encode(b"the Project Titan launch plan").decode()
    r = pf.scan(f"summarize {hidden}", ["Project Titan"])
    assert r.blocked and "decoded:base64" in r.flags


@pytest.mark.parametrize("text", [
    "Привет! Я живу в Ташкенте, встреча в 10:30.",
    "Salom, ertaga soat 9 da uchrashamiz.",
    "def f(a, b): return a.b(c.d)",
    "See https://docs.example.com/a/b/c for details.",
    "The quick brown fox jumps over the lazy dog " * 5,
    "Version 1.2.3.4 of the tool, build 2026-10-14.",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",                     # long but not base64 of anything readable
])
def test_ordinary_text_is_left_alone(text):
    r = pf.scan(text, pii=pf.PiiConfig(actions={"EMAIL": "mask", "CREDIT_CARD": "mask", "API_KEY": "mask"}))
    assert not any(f.startswith(("deobfuscated:", "decoded:")) for f in r.flags), r.flags


def test_russian_and_uzbek_words_keep_their_letters():
    norm, _ = normalize("Привет, как дела? Toshkent shahri")
    assert norm == "Привет, как дела? Toshkent shahri"
    norm, _ = normalize("pаssword")                         # Cyrillic "а" inside a Latin word
    assert norm == "password"


def test_spans_point_into_the_original():
    text = "x j\u200bo h n @ a . b y"
    norm, spans = normalize(text)
    start = norm.index("j")
    s, e = original_span(spans, start, start + 1)
    assert text[s:e] == "j"


def test_encoded_runs_are_bounded():
    blob = " ".join(base64.b64encode(f"hello world number {i:04d}".encode()).decode() for i in range(100))
    assert len(list(encoded_runs(blob))) == 32


def test_undoing_disguises_stays_fast_on_a_long_prompt():
    # the normalization pass alone: the whole scan's time is mostly the NER model's,
    # and on a CI runner under coverage that is no measure of this code
    text = ("j o h n @ e x a m p l e . c o m " + "lorem ipsum dolor sit amet " * 20) * 200   # ~120 KB
    t = time.monotonic()
    norm, spans = normalize(text)
    list(encoded_runs(text))
    assert time.monotonic() - t < 3
    assert len(spans) == len(norm) and "john@example.com" in norm
