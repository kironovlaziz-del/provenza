#!/bin/sh
# Provenza endpoint agent: install on macOS or Linux in one command.
#
#   f=$(mktemp) && curl -fsSL https://provenza.example.com/api/v1/egress-sensor/download/install-agent.sh -o "$f" \
#     && sudo sh "$f" --server https://provenza.example.com
#
# It downloads the agent for this machine from your Provenza, checks it
# against SHA256SUMS next to it, asks for the Ingestion Source key (input
# hidden, so the key stays out of the shell history and the process list)
# and runs "provenza-agent install": a LaunchDaemon on macOS, a systemd
# service on Linux. Run it again to upgrade; the key is then not needed.
#
# Unattended (Jamf, MDM, Ansible): --key-file PATH or PROVENZA_KEY=... in the
# environment.
#
# Flags:
#   --server URL      your Provenza (required)
#   --key-file PATH   read the key from this file
#   --key KEY         the key itself - it stays in the shell history; prefer the prompt
#   --agent-id ID     the name this machine is listed under (default: the host name)
#   --discovery       also discover network services (DNS, gateway, mDNS, LLMNR)
#   --uninstall       remove the agent (add --purge to remove its configuration too)
set -eu

SERVER="" KEY="${PROVENZA_KEY:-}" KEY_FILE="" AGENT_ID="" DISCOVERY=0 UNINSTALL=0 PURGE=0

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) [ $# -ge 2 ] || die "--server needs a value"; SERVER=$2; shift 2 ;;
    --key) [ $# -ge 2 ] || die "--key needs a value"; KEY=$2; shift 2 ;;
    --key-file) [ $# -ge 2 ] || die "--key-file needs a value"; KEY_FILE=$2; shift 2 ;;
    --agent-id) [ $# -ge 2 ] || die "--agent-id needs a value"; AGENT_ID=$2; shift 2 ;;
    --discovery) DISCOVERY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root: sudo sh $0 ..."

if [ "$UNINSTALL" = 1 ]; then
  command -v provenza-agent >/dev/null 2>&1 || [ -x /usr/local/bin/provenza-agent ] || die "the agent is not installed"
  if [ "$PURGE" = 1 ]; then exec /usr/local/bin/provenza-agent uninstall --purge; fi
  exec /usr/local/bin/provenza-agent uninstall
fi

[ -n "$SERVER" ] || die "--server is required (https://your-provenza)"
SERVER=${SERVER%/}

case "$(uname -s)" in
  Darwin) os=darwin; config="/Library/Application Support/Provenza Agent/config.json" ;;
  Linux) os=linux; config=/etc/provenza-agent/config.json ;;
  *) die "unsupported system $(uname -s): macOS and Linux only (Windows: install-agent.ps1)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported processor $(uname -m): amd64 and arm64 only" ;;
esac

if [ -n "$KEY_FILE" ]; then
  [ -r "$KEY_FILE" ] || die "cannot read $KEY_FILE"
  KEY=$(tr -d ' \r\n' <"$KEY_FILE")
fi
if [ -z "$KEY" ] && [ ! -f "$config" ]; then
  [ -r /dev/tty ] || die "no key: use --key-file PATH or PROVENZA_KEY for an unattended install"
  printf 'Ingestion Source key (Settings -> Ingestion Sources, type Endpoint agent): ' >/dev/tty
  stty -echo </dev/tty 2>/dev/null || true
  IFS= read -r KEY </dev/tty || true
  stty echo </dev/tty 2>/dev/null || true
  printf '\n' >/dev/tty
  [ -n "$KEY" ] || die "no key given"
fi

name="provenza-agent-$os-$arch"
base="$SERVER/api/v1/egress-sensor/download"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "-> downloading $name from $SERVER"
curl -fsSL -o "$tmp/$name" "$base/$name" || die "download failed: $base/$name"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
expected=$(awk -v n="$name" '$2 == n { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$name is not in SHA256SUMS: is your Provenza up to date?"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$name" | awk '{ print $1 }')
else
  actual=$(shasum -a 256 "$tmp/$name" | awk '{ print $1 }')
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $name: not installed"
echo "   checksum ok"
chmod 755 "$tmp/$name"
# a file saved by a browser carries the quarantine flag; curl sets none, but be sure
[ "$os" = darwin ] && xattr -d com.apple.quarantine "$tmp/$name" 2>/dev/null || true

set -- install --server "$SERVER"
[ -n "$AGENT_ID" ] && set -- "$@" --agent-id "$AGENT_ID"
[ "$DISCOVERY" = 1 ] && set -- "$@" --discovery

echo "-> installing"
if [ -n "$KEY" ]; then
  printf '%s\n' "$KEY" | "$tmp/$name" "$@" --key -
elif [ -f "$config" ]; then
  "$tmp/$name" install   # an upgrade: the configuration and the key stay
else
  die "no key given"
fi
