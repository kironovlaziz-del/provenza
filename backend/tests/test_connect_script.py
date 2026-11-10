# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""GET /api/v1/agent-enrollment/connect.sh: the one command of Agents -> Connect."""

import hashlib
import http.server
import os
import shutil
import subprocess
import threading

import pytest

from app.api.connect_script import SCRIPT_PS1

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


# ---------------------------------------------------------------- Windows (connect.ps1)

URL_PS1 = "/api/v1/agent-enrollment/connect.ps1"
PWSH = shutil.which("pwsh")


async def test_the_powershell_script_names_this_server(client):
    r = await client.get(URL_PS1, headers={"Host": "provenza.example.com"})
    # irm hands text back only for a text type
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert "$Server = 'https://provenza.example.com'" in body or "$Server = 'http://provenza.example.com'" in body
    assert "'gemini-cli','claude-code','cursor','openai'" in body
    assert "@SERVER@" not in body and "@CLIENTS_PS@" not in body
    assert "Get-FileHash" in body and "provenza-proxy-windows-$Arch.exe" in body
    # the token reaches enroll through the environment, never its command line
    assert "$env:PROVENZA_ENROLL_TOKEN = $Token" in body and "--token" not in body
    # it runs in the user's own session: a throw, never an exit that would close the window
    assert "exit " not in body.replace("# throw, not exit: this runs in the user's own PowerShell session, which exit would close", "")


async def test_a_host_that_could_break_the_powershell_script_is_refused(client):
    for host in ("evil.example.com';calc;'", 'a"b', "a b", "$(id)", "`id`"):
        r = await client.get(URL_PS1, headers={"Host": host})
        assert r.status_code == 400, host


def _render(server: str) -> str:
    return SCRIPT_PS1.replace("@SERVER@", server).replace("@CLIENTS_PS@", "'gemini-cli','claude-code','cursor','openai'")


@pytest.mark.skipif(PWSH is None, reason="needs pwsh")
def test_the_powershell_script_parses_and_checks_its_arguments(tmp_path):
    script = tmp_path / "connect.ps1"
    script.write_text(_render("https://p.example"))
    parse = ("$e=$null;$t=$null;[void][Management.Automation.Language.Parser]::ParseFile("
             f"'{script}',[ref]$t,[ref]$e); exit $e.Count")
    assert subprocess.run([PWSH, "-NoProfile", "-Command", parse], timeout=60).returncode == 0
    for args, why in ((["-Client", "cursor"], "usage"), (["-Client", "vim", "-Token", "pvz_enr_x"], "unknown client"),
                      (["-Client", "cursor", "-Token", "secret"], "pvz_enr_")):
        r = subprocess.run([PWSH, "-NoProfile", "-File", str(script), *args], capture_output=True, text=True, timeout=60)
        assert r.returncode != 0 and why in (r.stderr + r.stdout), (args, r.stderr, r.stdout)


class _Dist(http.server.BaseHTTPRequestHandler):
    files: dict = {}

    def do_GET(self):  # noqa: N802
        name = self.path.rsplit("/", 1)[-1]
        if name in self.files:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.files[name])
        else:
            self.send_error(404)

    def log_message(self, *a):
        pass


def _run_ps1(tmp_path, sums: str | None, binary: bytes = b"#!/bin/sh\nexit 0\n"):
    """connect.ps1 against a stand-in server: pwsh on Linux with the Windows variables set."""
    name = "provenza-proxy-windows-amd64.exe"
    _Dist.files = {name: binary}
    if sums is not None:
        _Dist.files["SHA256SUMS"] = sums.encode()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Dist)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        script = tmp_path / "connect.ps1"
        script.write_text(_render(f"http://127.0.0.1:{srv.server_port}"))
        env = {**os.environ, "OS": "Windows_NT", "PROCESSOR_ARCHITECTURE": "AMD64",
               "LOCALAPPDATA": str(tmp_path / "local"), "COMPUTERNAME": "pc"}
        env.pop("PROCESSOR_ARCHITEW6432", None)
        return subprocess.run([PWSH, "-NoProfile", "-File", str(script), "-Client", "cursor", "-Token", "pvz_enr_x"],
                              capture_output=True, text=True, timeout=120, env=env)
    finally:
        srv.shutdown()


@pytest.mark.skipif(PWSH is None, reason="needs pwsh")
def test_the_powershell_script_checks_what_it_downloaded(tmp_path):
    name = "provenza-proxy-windows-amd64.exe"
    binary = b"#!/bin/sh\nexit 0\n"
    good = hashlib.sha256(binary).hexdigest()
    # a wrong checksum: refused, nothing installed
    r = _run_ps1(tmp_path, f"{'0' * 64}  {name}\n", binary)
    assert r.returncode != 0 and "checksum mismatch" in r.stdout + r.stderr
    assert not (tmp_path / "local" / "provenza" / "provenza-proxy.exe").exists()
    # no checksum for this file: refused
    r = _run_ps1(tmp_path, f"{good}  another-file\n", binary)
    assert r.returncode != 0 and "publishes no checksum" in r.stdout + r.stderr
    # no checksum list at all: refused
    r = _run_ps1(tmp_path, None, binary)
    assert r.returncode != 0 and "could not download" in r.stdout + r.stderr
    # the right one, in sha256sum's text and binary forms: installed, and the next step (enroll) is reached
    for form in (f"{good}  {name}\n", f"{good.upper()} *{name}\n"):
        r = _run_ps1(tmp_path, form, binary)
        assert (tmp_path / "local" / "provenza" / "provenza-proxy.exe").read_bytes() == binary, r.stderr
        assert "Enrolling the agent" in r.stdout
        (tmp_path / "local" / "provenza" / "provenza-proxy.exe").unlink()
    # run again over an installed one (on Windows it may be held by a running agent mode): the old
    # file is put aside, the new one installed, and the next run takes the old one away
    exe = tmp_path / "local" / "provenza" / "provenza-proxy.exe"
    for expect_old in (0, 1):
        r = _run_ps1(tmp_path, f"{good}  {name}\n", binary)
        assert exe.read_bytes() == binary and "Enrolling the agent" in r.stdout, r.stderr
        assert len(list(exe.parent.glob("provenza-proxy.exe.old-*"))) == expect_old, (expect_old, r.stdout, r.stderr)


def test_the_powershell_script_is_plain_ascii():
    """Windows PowerShell 5.1 reads a file without a byte-order mark in the system's code page."""
    SCRIPT_PS1.encode("ascii")
