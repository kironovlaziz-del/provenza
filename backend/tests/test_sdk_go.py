# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The Go SDK (sdk/go) against this server and the Python SDK - the same
cross-language proof as tests/test_sdk_js.py:

  1. A Python-written identity file is loaded by the Go Agent; the Go code
     governs a call under a check issued by THIS server; the record it builds
     and signs is accepted by THIS server (Unicode, astral characters and floats
     like 1e-7 in input and output).
  2. A Go standalone audit log verifies with the Python SDK's verifier.

Needs the go command (Go >= 1.27, or a Go that downloads it); skipped otherwise.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll

ROOT = Path(__file__).resolve().parents[2]
GO = ROOT / "sdk" / "go"
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from provenza import identity as ids  # noqa: E402
from provenza.audit_log import verify  # noqa: E402
from provenza.crypto import Keys  # noqa: E402

INPUT = {"query": "café АБ \U0001F600 € <&>", "ratio": 1e-7, "small": 0.00001, "n": 3,
         "nested": {"z": [1.5, None, True], "דּ": "x", "\U0001F600": "y"}}


@pytest.fixture(scope="module")
def xlang(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("needs the go command")
    binary = tmp_path_factory.mktemp("go") / "xlang"
    build = subprocess.run(["go", "build", "-o", str(binary), "./internal/xlang"], cwd=GO, capture_output=True,
                           text=True, timeout=600)
    # a Go SDK that does not build is a failure, never a skip - a skip would hide it in CI
    assert build.returncode == 0, f"the Go SDK does not build: {build.stderr[-500:]}"
    return binary


def _run(binary, *args) -> str:
    out = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout


@pytest.mark.asyncio
async def test_a_go_signed_record_is_accepted_by_this_server(client, admin_token, tmp_path, xlang):
    enrolled = await enroll(client, admin_token, name="go-bot", capabilities=("read",), allowed_tools=("db.read",))
    identity = tmp_path / "go-bot.json"
    ids.save(ids.Identity(keys=Keys(enrolled["private_key"], enrolled["public_key"]), server="http://test",
                          agent_id=enrolled["id"], api_key=enrolled["api_key"], name="go-bot"), identity)

    check = await client.post("/api/v1/agents/actions/check",
                              json={"agent_id": enrolled["id"], "tool_name": "db.read", "input": INPUT},
                              headers=auth_headers(admin_token))
    assert check.status_code == 200 and check.json()["decision"] == "allowed", check.text

    body = json.loads(_run(xlang, "record", json.dumps({
        "server": "http://test", "identity": str(identity), "check": check.json(), "tool": "db.read",
        "input": INPUT, "output": {"rows": [1, 2], "note": "é\U0001F600", "p": 0.0001}})))
    assert body["signature"] and body["check_id"] == check.json()["check_id"]

    r = await client.post("/api/v1/agents/actions/record", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text            # hashes and signature agree across languages


def test_a_go_audit_log_verifies_with_the_python_sdk(tmp_path, xlang):
    out = json.loads(_run(xlang, "standalone", str(tmp_path / "go-solo.json")))
    assert verify(Path(out["log"]), out["pub"]) == []
    assert len(Path(out["log"]).read_text().splitlines()) == 3
