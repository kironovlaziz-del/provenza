# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Curated base models are pinned to a commit; source files carry no invisible characters."""

import re
from pathlib import Path

from app.services import transformer_models as tm


def test_every_curated_model_is_pinned_to_a_full_commit():
    curated = {m["id"] for m in tm.CPU_SAFE_MODELS + tm.GPU_ADDITIONAL_MODELS + tm.GENERATION_MODELS}
    assert curated == set(tm.PINNED_REVISIONS)
    for model_id in curated:
        assert re.fullmatch(r"[0-9a-f]{40}", tm.pinned_revision(model_id)), model_id


def test_free_form_model_is_not_pinned():
    assert tm.pinned_revision("someone/some-model") is None


def test_no_invisible_or_bidi_characters_in_backend_source():
    # Trojan-source hygiene: such characters are written as \\u escapes instead.
    bad = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u180e]")
    app = Path(__file__).resolve().parents[1] / "app"
    hits = [f"{p.relative_to(app)}:{i}" for p in app.rglob("*.py")
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if bad.search(line)]
    assert not hits, hits
