"""Egress sensor downloads (app/api/sensor_download.py): the installer, unit
and binaries the production image builds, served without authentication so
a host with no credentials yet (and no Go) can install the sensor."""

from app.core.config import settings

BASE = "/api/v1/egress-sensor/download"


async def test_serves_known_files_without_auth(client, tmp_path, monkeypatch):
    (tmp_path / "install.sh").write_text("#!/usr/bin/env bash\necho hi\n")
    (tmp_path / "provenza-sensor-linux-amd64").write_bytes(b"\x7fELF fake")
    monkeypatch.setattr(settings, "SENSOR_DIST_DIR", str(tmp_path))

    r = await client.get(f"{BASE}/install.sh")
    assert r.status_code == 200, r.text
    assert r.text.startswith("#!/usr/bin/env bash")
    assert r.headers["content-type"].startswith("text/x-shellscript")

    r = await client.get(f"{BASE}/provenza-sensor-linux-amd64")
    assert r.status_code == 200
    assert r.content == b"\x7fELF fake"
    assert "attachment" in r.headers.get("content-disposition", "")


async def test_only_listed_names(client, tmp_path, monkeypatch):
    (tmp_path / "secret.txt").write_text("nope")
    monkeypatch.setattr(settings, "SENSOR_DIST_DIR", str(tmp_path))
    for name in ("secret.txt", "..%2F..%2Fetc%2Fpasswd", "install.sh.bak"):
        r = await client.get(f"{BASE}/{name}")
        assert r.status_code == 404, name


async def test_missing_build_says_why(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SENSOR_DIST_DIR", str(tmp_path / "absent"))
    r = await client.get(f"{BASE}/install.sh")
    assert r.status_code == 404
    assert "not built" in r.text


async def test_serves_the_agent_for_every_system(client, tmp_path, monkeypatch):
    """The endpoint agent for Windows and macOS, and the scripts the
    Ingestion Sources page gives as the install command."""
    names = [
        "provenza-agent-linux-amd64", "provenza-agent-darwin-arm64",
        "provenza-agent-darwin-amd64", "provenza-agent-windows-amd64.exe",
        "provenza-agent-windows-arm64.exe",
    ]
    for n in names:
        (tmp_path / n).write_bytes(b"bin " + n.encode())
    (tmp_path / "install-agent.sh").write_text("#!/bin/sh\n")
    (tmp_path / "install-agent.ps1").write_text("param()\n")
    monkeypatch.setattr(settings, "SENSOR_DIST_DIR", str(tmp_path))

    for n in names:
        r = await client.get(f"{BASE}/{n}")
        assert r.status_code == 200, n
        assert r.content == b"bin " + n.encode()
        assert "attachment" in r.headers.get("content-disposition", "")
    r = await client.get(f"{BASE}/install-agent.sh")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/x-shellscript")
    # irm in PowerShell returns text only for a text type
    r = await client.get(f"{BASE}/install-agent.ps1")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    # no Windows binary without .exe, no other systems
    for n in ("provenza-agent-windows-amd64", "provenza-agent-freebsd-amd64"):
        assert (await client.get(f"{BASE}/{n}")).status_code == 404, n


async def test_serves_the_proxy_for_windows(client, tmp_path, monkeypatch):
    """provenza-proxy for Windows (its enroll and connect commands): .exe names only."""
    names = ["provenza-proxy-windows-amd64.exe", "provenza-proxy-windows-arm64.exe"]
    for n in names:
        (tmp_path / n).write_bytes(b"bin " + n.encode())
    monkeypatch.setattr(settings, "SENSOR_DIST_DIR", str(tmp_path))
    for n in names:
        r = await client.get(f"{BASE}/{n}")
        assert r.status_code == 200 and r.content == b"bin " + n.encode(), n
    for n in ("provenza-proxy-windows-amd64", "provenza-proxy-windows-386.exe"):
        assert (await client.get(f"{BASE}/{n}")).status_code == 404, n
