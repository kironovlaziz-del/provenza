# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Source files carry no invisible or bidi characters (Trojan Source)."""

import re
from pathlib import Path


def test_no_invisible_or_bidi_characters_in_backend_source():
    # Trojan-source hygiene: such characters are written as \\u escapes instead.
    bad = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u180e]")
    app = Path(__file__).resolve().parents[1] / "app"
    hits = [f"{p.relative_to(app)}:{i}" for p in app.rglob("*.py")
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if bad.search(line)]
    assert not hits, hits
