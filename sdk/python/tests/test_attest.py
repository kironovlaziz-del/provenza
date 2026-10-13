# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""provenza.attest: where the workload's token comes from."""

import pytest

from provenza import attest


def test_token_file(tmp_path, monkeypatch):
    path = tmp_path / "token"
    path.write_text("eyJ.token.sig\n")
    assert attest.token_file(str(path)) == "eyJ.token.sig"
    monkeypatch.setenv("PROVENZA_ATTESTATION_TOKEN_FILE", str(path))
    assert attest.token_file() == "eyJ.token.sig"


def test_github_actions_needs_its_job(monkeypatch):
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)
    with pytest.raises(RuntimeError, match="id-token: write"):
        attest.github_actions()
