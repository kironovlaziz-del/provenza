#!/usr/bin/env bash
# Provenza egress sensor: one-command install on a Linux host.
#
#   sudo ./install.sh --url https://provenza.example.com
#
# What it does:
#   1. Verifies the host can run the sensor (kernel, cgroup v2, tools).
#   2. Builds the eBPF program (needs clang >= 14 + llvm) and the Go binary.
#   3. Installs the binary, the systemd unit and the config directory.
#   4. Optionally enrolls this host with the control plane if --key was
#      given; otherwise prints the two follow-up commands.
#   5. Starts provenzasensor.service and prints the attached hooks.
#
# Flags:
#   --url URL             control plane URL (required)
#   --key pvz_sensor_...  enrollment key from the UI; skip to enroll later
#   --no-service          install only, do not enable/start the unit
#   --force               continue despite host warnings (low mem, no cgroup v2)
#   --yes, -y             non-interactive: like --force, plus no enrollment prompt
#   -h, --help            this help
#
# Idempotent: re-running rebuilds and reinstalls, but does not touch
# /etc/provenza-sensor/sensor.json or the key file once written.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="" KEY="" NO_SERVICE=0 FORCE=0 ASSUME_YES=0

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'
else B="" G="" Y="" R="" N=""; fi
step() { printf '%s→ %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url)        URL=${2:?}; shift 2 ;;
    --key)        KEY=${2:?}; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --force)      FORCE=1; shift ;;
    --yes|-y)     ASSUME_YES=1; shift ;;
    -h|--help)    usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[ -n "$URL" ] || die "--url is required (the address you open in the browser)"

# ---------------------------------------------------------------- root check
if [ "$(id -u)" -ne 0 ]; then
  die "run as root: sudo ./install.sh --url $URL [--key pvz_sensor_...]"
fi

# ---------------------------------------------------------------- host checks
step "Checking the host"

# Kernel: BPF + cgroup v2 + tracing. Hard requirements, not fixable here.
kern_major=$(uname -r | cut -d. -f1)
kern_minor=$(uname -r | cut -d. -f2)
if [ "$kern_major" -lt 5 ] || { [ "$kern_major" -eq 5 ] && [ "$kern_minor" -lt 10 ]; }; then
  warn "kernel $(uname -r) is older than 5.10; BPF LSM and some hooks may be unavailable"
  [ "$FORCE" = 1 ] || [ "$ASSUME_YES" = 1 ] || die "rerun with --force to continue anyway"
fi

if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
  warn "cgroup v2 is not mounted at /sys/fs/cgroup"
  warn "the sensor attaches its programs to cgroups; without v2 it cannot work"
  [ "$FORCE" = 1 ] || [ "$ASSUME_YES" = 1 ] || die "rerun with --force to continue anyway (not recommended)"
fi
ok "kernel $(uname -r), cgroup v2 present"

# Tools: clang for the eBPF program, go for the binary.
command -v clang >/dev/null || die "clang is required: apt install clang llvm"
clang_major=$(clang --version | head -1 | grep -oE '[0-9]+' | head -1)
if [ "${clang_major:-0}" -lt 14 ]; then
  warn "clang $clang_major < 14; the eBPF object may not compile"
  [ "$FORCE" = 1 ] || [ "$ASSUME_YES" = 1 ] || die "upgrade clang or rerun with --force"
fi
command -v go >/dev/null || die "go is required: https://go.dev/dl/"
ok "clang $(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1), go $(go version | awk '{print $3}')"

# Presence of the bpffs mount point the daemon will pin to.
[ -d /sys/fs/bpf ] || { warn "/sys/fs/bpf missing"; [ "$FORCE" = 1 ] || [ "$ASSUME_YES" = 1 ] || die "rerun with --force to continue"; }

# ---------------------------------------------------------------- build
step "Building the eBPF program"
make -C "$HERE" bpf 2>&1 | tail -3

step "Building provenza-sensor"
make -C "$HERE" build 2>&1 | tail -3

# ---------------------------------------------------------------- install
step "Installing the binary and the systemd unit"
make -C "$HERE" install 2>&1 | tail -5

# systemd sees the freshly written unit only after a daemon-reload.
systemctl daemon-reload
ok "binary at /usr/local/bin/provenza-sensor, unit at /etc/systemd/system/provenzasensor.service"

# ---------------------------------------------------------------- enroll
if [ -n "$KEY" ]; then
  step "Enrolling with $URL"
  /usr/local/bin/provenza-sensor enroll --url "$URL" --key "$KEY" --no-restart
  ok "credentials written to /etc/provenza-sensor/"
else
  warn "no --key given; run this after registering the sensor in the UI:"
  warn "  sudo provenza-sensor enroll --url $URL --key pvz_sensor_..."
fi

# ---------------------------------------------------------------- start
if [ "$NO_SERVICE" = 1 ]; then
  warn "--no-service: not enabling or starting provenzasensor.service"
  exit 0
fi

step "Starting provenzasensor.service"
systemctl enable --now provenzasensor.service
sleep 3

if ! systemctl is-active --quiet provenzasensor.service; then
  journalctl -u provenzasensor -n 30 --no-pager >&2
  die "provenzasensor.service did not start"
fi
ok "provenzasensor.service is active"

# ---------------------------------------------------------------- smoke
step "Checking the attached hooks"
if command -v jq >/dev/null; then
  /usr/local/bin/provenza-sensor status --json | jq '{hooks: .hooks.attached, warnings, errors}' || true
else
  /usr/local/bin/provenza-sensor status | sed -n '/Hooks/,/^$/p' || true
fi

cat <<SUMMARY

  Sensor installed and running.
  - config:  /etc/provenza-sensor/sensor.json
  - status:  sudo provenza-sensor status
  - logs:    sudo journalctl -u provenzasensor -f

  Next: in the UI (Runtime → Workloads) point a workload at the
  cgroup(s) this host serves, and the sensor will start governing them.

SUMMARY
