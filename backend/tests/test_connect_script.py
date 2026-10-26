# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""GET /api/v1/agent-enrollment/connect.sh: the one command of Agents -> Connect."""

import shutil
import subprocess

import pytest

URL = "/api/v1/agent-enrollment/connect.sh"


async def test_the_script_names_this_server(client):
    r = await client.get(URL, headers={"Host": "provenza.example.com"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/x-shellscript")
    body = r.text
    assert 'SERVER="http://provenza.example.com"' in body
    assert "gemini-cli claude-code cursor openai" in body
    assert "sha256sum -c" in body and "provenza-proxy\" enroll" in body and "provenza-proxy\" connect" in body
    # the token reaches enroll through the environment, never its command line
    assert 'PROVENZA_ENROLL_TOKEN="$TOKEN"' in body and "--token" not in body


async def test_a_host_that_could_break_the_script_is_refused(client):
    for host in ('evil.example.com";rm -rf ~;"', "a b", "$(id)"):
        r = await client.get(URL, headers={"Host": host})
        assert r.status_code == 400


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
async def test_the_script_is_valid_sh_and_checks_its_arguments(client, tmp_path):
    script = tmp_path / "connect.sh"
    script.write_text((await client.get(URL, headers={"Host": "p.example"})).text)
    assert subprocess.run(["sh", "-n", str(script)]).returncode == 0
    for args, why in ((["gemini-cli"], "usage"), (["vim", "pvz_enr_x"], "unknown client"),
                      (["gemini-cli", "secret"], "pvz_enr_")):
        r = subprocess.run(["sh", str(script), *args], capture_output=True, text=True, timeout=30)
        assert r.returncode != 0 and why in r.stderr, (args, r.stderr)
