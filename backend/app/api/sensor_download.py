# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress sensor downloads: the installer, the systemd unit and the sensor
binaries, served by the control plane itself.

    GET /api/v1/egress-sensor/download/install.sh
    GET /api/v1/egress-sensor/download/provenza-sensor-linux-amd64
    GET /api/v1/egress-sensor/download/provenza-sensor-linux-arm64
    GET /api/v1/egress-sensor/download/provenzasensor.service
    GET /api/v1/egress-sensor/download/SHA256SUMS
    GET /api/v1/egress-sensor/download/provenza-proxy-linux-{amd64,arm64}
    GET /api/v1/egress-sensor/download/provenza-agent-linux-{amd64,arm64}
    GET /api/v1/egress-sensor/download/provenza-agent-darwin-{amd64,arm64}
    GET /api/v1/egress-sensor/download/provenza-agent-windows-{amd64,arm64}.exe
    GET /api/v1/egress-sensor/download/install-agent.sh   (macOS, Linux)
    GET /api/v1/egress-sensor/download/install-agent.ps1  (Windows)

The production image builds them from this checkout (deploy/backend.Dockerfile,
stage "sensor"), so a host always gets the sensor that matches its control
plane, with no dependency on GitHub. The one-line install command on the
Runtime page fetches install.sh from here; install.sh fetches the binary and
the unit from here too and checks them against SHA256SUMS.

No authentication: nothing here is secret (the same files are in the public
repository), and the host asking for them has no credentials yet. Only the
names below can be read; nothing else in the directory is reachable.
"""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.core.config import settings

router = APIRouter()

# requested name -> (file name, media type). The path is built from the file
# name stored here, never from the request: nothing else can be reached.
FILES = {
    "install.sh": ("install.sh", "text/x-shellscript; charset=utf-8"),
    "provenzasensor.service": ("provenzasensor.service", "text/plain; charset=utf-8"),
    "SHA256SUMS": ("SHA256SUMS", "text/plain; charset=utf-8"),
    "provenza-sensor-linux-amd64": ("provenza-sensor-linux-amd64", "application/octet-stream"),
    "provenza-sensor-linux-arm64": ("provenza-sensor-linux-arm64", "application/octet-stream"),
    # the egress proxy and the endpoint agent (the image's "edge" stage), for other hosts
    "provenza-proxy-linux-amd64": ("provenza-proxy-linux-amd64", "application/octet-stream"),
    "provenza-proxy-linux-arm64": ("provenza-proxy-linux-arm64", "application/octet-stream"),
    "provenza-agent-linux-amd64": ("provenza-agent-linux-amd64", "application/octet-stream"),
    "provenza-agent-linux-arm64": ("provenza-agent-linux-arm64", "application/octet-stream"),
    # the endpoint agent for workstations, and the scripts that install it
    # as a service (Ingestion Sources shows the command)
    "provenza-agent-darwin-amd64": ("provenza-agent-darwin-amd64", "application/octet-stream"),
    "provenza-agent-darwin-arm64": ("provenza-agent-darwin-arm64", "application/octet-stream"),
    "provenza-agent-windows-amd64.exe": ("provenza-agent-windows-amd64.exe", "application/octet-stream"),
    "provenza-agent-windows-arm64.exe": ("provenza-agent-windows-arm64.exe", "application/octet-stream"),
    "install-agent.sh": ("install-agent.sh", "text/x-shellscript; charset=utf-8"),
    "install-agent.ps1": ("install-agent.ps1", "text/plain; charset=utf-8"),
}


@router.get("/{name}", summary="Egress sensor installer, unit and binaries")
async def download(name: str):
    entry = FILES.get(name)
    if entry is None:
        raise HTTPException(status_code=404, detail="no such file")
    filename, media = entry
    path = Path(settings.SENSOR_DIST_DIR) / filename
    if not path.is_file():
        # A development install runs the backend from source: there is no
        # built sensor to hand out. sensor/install.sh from the repository
        # builds it locally instead.
        raise HTTPException(
            status_code=404,
            detail="sensor files are not built into this installation "
                   "(production image only; from the repository: sudo sensor/install.sh)",
        )
    return FileResponse(
        path,
        media_type=media,
        filename=filename if media == "application/octet-stream" else None,
        headers={"Cache-Control": "no-cache"},
    )
