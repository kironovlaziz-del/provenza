# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The one command of Agents -> Connect:

    f=$(mktemp) && curl -fsSL https://<provenza>/api/v1/agent-enrollment/connect.sh -o "$f" && sh "$f" <client> <pvz_enr_...>

GET /api/v1/agent-enrollment/connect.sh is this script, with this server's
address in it. On the agent's machine, as the agent's user, it

  1. downloads provenza-proxy from this server and checks it against the
     server's SHA256SUMS (/api/v1/egress-sensor/download/);
  2. enrolls the agent with the one-time token: its keys are made there and
     never leave the machine (provenza-proxy enroll);
  3. connects the client: agent mode as a service of that user, and
     Provenza's MCP endpoint in the client's configuration (provenza-proxy connect).

No authentication: nothing in it is secret; the token is the credential.
"""

import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

router = APIRouter()

CLIENTS = ("gemini-cli", "claude-code", "cursor", "openai")
_HOST = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")

SCRIPT = r"""#!/bin/sh
# Provenza: connect an AI client on this machine as an agent (Agents -> Connect).
#   f=$(mktemp) && curl -fsSL @SERVER@/api/v1/agent-enrollment/connect.sh -o "$f" && sh "$f" <client> <token>
# Run it as the user the client runs as. The agent's keys are made here and
# never leave this machine.
set -eu
SERVER="@SERVER@"
CLIENTS="@CLIENTS@"
CLIENT="${1:-}"
TOKEN="${2:-}"
say() { printf '%s\n' "$*"; }
die() { printf 'x %s\n' "$*" >&2; exit 1; }

[ -n "$CLIENT" ] && [ -n "$TOKEN" ] || die "usage: sh connect.sh <client> <token> - copy the whole command from Agents -> Connect"
case " $CLIENTS " in *" $CLIENT "*) ;; *) die "unknown client '$CLIENT': one of $CLIENTS" ;; esac
case "$TOKEN" in pvz_enr_*) ;; *) die "the token starts with pvz_enr_ (copy the whole command from Agents -> Connect)" ;; esac
[ "$(id -u)" != 0 ] || say "! running as root: the agent and its keys will belong to root - run it as the client's user"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/amd64) ARCH=amd64 ;;
  Linux/aarch64|Linux/arm64) ARCH=arm64 ;;
  *) die "this command supports Linux on amd64 and arm64 for now ($(uname -s) $(uname -m))" ;;
esac
command -v curl >/dev/null || die "curl is required"
command -v sha256sum >/dev/null || die "sha256sum is required"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
BASE="$SERVER/api/v1/egress-sensor/download"
BIN="provenza-proxy-linux-$ARCH"
say "-> Downloading provenza-proxy from $SERVER"
curl -fsSL --proto '=https,http' "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || die "could not download $BASE/SHA256SUMS"
curl -fsSL --proto '=https,http' "$BASE/$BIN" -o "$TMP/$BIN" || die "could not download $BASE/$BIN"
( cd "$TMP" && grep " $BIN\$" SHA256SUMS | sha256sum -c --quiet - ) || die "checksum mismatch: the download is not what $SERVER published"
DEST="$HOME/.local/bin"
mkdir -p "$DEST"
install -m 0755 "$TMP/$BIN" "$DEST/provenza-proxy"
say "  ok $DEST/provenza-proxy"

say "-> Enrolling the agent (its keys are made on this machine)"
PROVENZA_ENROLL_TOKEN="$TOKEN" "$DEST/provenza-proxy" enroll --server "$SERVER" --name "$CLIENT@$(uname -n)"
unset TOKEN

say "-> Connecting $CLIENT"
"$DEST/provenza-proxy" connect "$CLIENT"
case ":$PATH:" in *":$DEST:"*) ;; *) say "  (provenza-proxy is in $DEST, which is not on your PATH)" ;; esac
"""


@router.get("/connect.sh", summary="The one command of Agents -> Connect")
async def connect_script(request: Request):
    scheme, host = request.url.scheme, request.headers.get("host", "")
    if scheme not in ("http", "https") or not _HOST.match(host):
        raise HTTPException(status_code=400, detail="bad host")
    body = SCRIPT.replace("@SERVER@", f"{scheme}://{host}").replace("@CLIENTS@", " ".join(CLIENTS))
    return PlainTextResponse(body, media_type="text/x-shellscript; charset=utf-8",
                             headers={"Cache-Control": "no-cache"})
