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

On Windows the same, in PowerShell (GET .../connect.ps1; provenza-proxy-windows-*.exe):

    & ([scriptblock]::Create((irm "https://<provenza>/api/v1/agent-enrollment/connect.ps1"))) -Client <client> -Token <pvz_enr_...>

A script block, so no execution policy is changed; the agent's files are the
signed-in user's own (%LOCALAPPDATA%\\provenza, %USERPROFILE%\\.config\\provenza).

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

SCRIPT_PS1 = r"""# Provenza: connect an AI client on this machine as an agent (Agents -> Connect).
#   & ([scriptblock]::Create((irm "@SERVER@/api/v1/agent-enrollment/connect.ps1"))) -Client <client> -Token <token>
# Run it in PowerShell as the user the client runs as (not as administrator). The
# agent's keys are made here and never leave this machine.
param(
  [string]$Client = '',
  [string]$Token = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Server = '@SERVER@'
$Clients = @(@CLIENTS_PS@)
function Say($m) { Write-Host $m }
# throw, not exit: this runs in the user's own PowerShell session, which exit would close

if (-not $Client -or -not $Token) { throw 'usage: connect.ps1 -Client <client> -Token <token> - copy the whole command from Agents -> Connect' }
if ($Clients -notcontains $Client) { throw "unknown client '$Client': one of $($Clients -join ' ')" }
if (-not $Token.StartsWith('pvz_enr_')) { throw 'the token starts with pvz_enr_ (copy the whole command from Agents -> Connect)' }
if ($env:OS -ne 'Windows_NT') { throw 'this command is for Windows; on Linux use connect.sh' }
try {
  $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if ($me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say '! running as administrator: the agent and its keys will belong to this account - run it as the client''s user'
  }
} catch { }   # only a warning: not worth stopping for

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
  'AMD64' { $Arch = 'amd64' }
  'ARM64' { $Arch = 'arm64' }
  default { throw "this command supports Windows on amd64 and arm64 for now ($arch)" }
}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('provenza-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  $Base = "$Server/api/v1/egress-sensor/download"
  $Bin = "provenza-proxy-windows-$Arch.exe"
  Say "-> Downloading provenza-proxy from $Server"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/SHA256SUMS" -OutFile (Join-Path $Tmp 'SHA256SUMS')
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Bin" -OutFile (Join-Path $Tmp $Bin)
  } catch { throw "could not download from $Base ($($_.Exception.Message))" }
  $want = $null
  foreach ($line in Get-Content (Join-Path $Tmp 'SHA256SUMS')) {
    $f = $line.Trim() -split '\s+', 2
    if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq $Bin) { $want = $f[0]; break }
  }
  if (-not $want) { throw "$Server publishes no checksum for $Bin" }
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Tmp $Bin)).Hash
  if ($got -ne $want.ToUpperInvariant()) { throw "checksum mismatch: the download is not what $Server published" }

  $Dest = Join-Path $env:LOCALAPPDATA 'provenza'
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  $Exe = Join-Path $Dest 'provenza-proxy.exe'
  # an agent mode of this very file that is still running holds it: stop it, connect starts it again
  Get-Process -Name 'provenza-proxy' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $Exe } | Stop-Process -Force -ErrorAction SilentlyContinue
  Move-Item -Force -LiteralPath (Join-Path $Tmp $Bin) -Destination $Exe
  Say "  ok $Exe"

  Say '-> Enrolling the agent (its keys are made on this machine)'
  # the token reaches enroll through the environment, never its command line
  $env:PROVENZA_ENROLL_TOKEN = $Token
  try {
    & $Exe enroll --server $Server --name "$Client@$env:COMPUTERNAME"
    if ($LASTEXITCODE -ne 0) { throw 'enrolling failed (see above)' }
  } finally {
    Remove-Item Env:PROVENZA_ENROLL_TOKEN -ErrorAction SilentlyContinue
    $Token = $null
  }

  Say "-> Connecting $Client"
  & $Exe connect $Client
  if ($LASTEXITCODE -ne 0) { throw 'connecting failed (see above)' }
  if (($env:Path -split ';') -notcontains $Dest) { Say "  (provenza-proxy is in $Dest, which is not on your PATH)" }
} finally {
  Remove-Item -Recurse -Force -LiteralPath $Tmp -ErrorAction SilentlyContinue
}
"""


@router.get("/connect.sh", summary="The one command of Agents -> Connect")
async def connect_script(request: Request):
    scheme, host = request.url.scheme, request.headers.get("host", "")
    if scheme not in ("http", "https") or not _HOST.match(host):
        raise HTTPException(status_code=400, detail="bad host")
    body = SCRIPT.replace("@SERVER@", f"{scheme}://{host}").replace("@CLIENTS@", " ".join(CLIENTS))
    return PlainTextResponse(body, media_type="text/x-shellscript; charset=utf-8",
                             headers={"Cache-Control": "no-cache"})


@router.get("/connect.ps1", summary="The one command of Agents -> Connect, for Windows")
async def connect_script_windows(request: Request):
    scheme, host = request.url.scheme, request.headers.get("host", "")
    if scheme not in ("http", "https") or not _HOST.match(host):
        raise HTTPException(status_code=400, detail="bad host")
    clients = ",".join(f"'{c}'" for c in CLIENTS)
    body = SCRIPT_PS1.replace("@SERVER@", f"{scheme}://{host}").replace("@CLIENTS_PS@", clients)
    # irm hands text back only for a text type
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8",
                             headers={"Cache-Control": "no-cache"})
