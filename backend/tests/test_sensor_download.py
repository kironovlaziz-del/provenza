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
