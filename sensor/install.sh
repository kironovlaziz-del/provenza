#!/usr/bin/env bash
# Provenza egress sensor: install on this host in one command.
#
#   sudo ./sensor/install.sh --url https://provenza.example.com
#
# Then register the sensor once:
#   open https://provenza.example.com/runtime -> Register sensor -> copy the key
#   sudo provenza-sensor enroll --url https://provenza.example.com --key pvz_sensor_...
#
# Or do both in one go, if you already have the key:
#   sudo ./sensor/install.sh --url https://provenza.example.com --key pvz_sensor_...
#
# Without the repository (the command the Runtime page gives you): the
# control plane serves this script, the binary and the unit, and the script
# checks them against the control plane's SHA256SUMS:
#   curl -fsSL https://provenza.example.com/api/v1/egress-sensor/download/install.sh -o install-sensor.sh
#   sudo bash install-sensor.sh --url https://provenza.example.com --key pvz_sensor_...
#
# The sensor needs Linux 5.15+, cgroup v2, BPF and BTF. The BPF object is
# embedded in the binary, so clang is only needed if you build from source.
#
# Flags:
#   --url URL         control plane URL (required for enroll, optional to just prepare)
#   --key KEY         sensor key (pvz_sensor_...); if given, enroll and start
#   --cgroup-root P   cgroup v2 mount (default /sys/fs/cgroup)
#   --binary PATH     use this provenza-sensor binary instead of building or downloading
#   --uninstall       detach the sensor and remove files
#   --yes             non-interactive
#   --force           continue despite host warnings
set -euo pipefail

URL=""
KEY=""
CGROUP_ROOT="/sys/fs/cgroup"
PIN_DIR="/sys/fs/bpf/provenza"
STATE_DIR="/var/lib/provenza-sensor"
RUN_SOCKET="/run/provenza-sensor/run.sock"
RUN_GROUP="provenza"
BIN_SRC=""
ASSUME_YES=0
FORCE=0
UNINSTALL=0

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
step() { printf '%s-> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
confirm() {
  local def=${2:-y} ans
  [ "$ASSUME_YES" = 1 ] && { [ "$def" = y ]; return; }
  printf '%s? %s%s [%s]: ' "$B" "$1" "$N" "$([ "$def" = y ] && echo Y/n || echo y/N)" >/dev/tty
  IFS= read -r ans </dev/tty || true
  ans=${ans:-$def}
  [[ "$ans" =~ ^[YyДд] ]]
}
usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL=${2:?}; shift 2 ;;
    --key) KEY=${2:?}; shift 2 ;;
    --cgroup-root) CGROUP_ROOT=${2:?}; shift 2 ;;
    --pin-dir) PIN_DIR=${2:?}; shift 2 ;;
    --state-dir) STATE_DIR=${2:?}; shift 2 ;;
    --run-socket) RUN_SOCKET=${2:?}; shift 2 ;;
    --run-group) RUN_GROUP=${2:?}; shift 2 ;;
    --binary) BIN_SRC=${2:?}; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
DL_DIR=""

# The binary for this machine and the systemd unit, from the control plane
# (GET /api/v1/egress-sensor/download/), checked against its SHA256SUMS.
fetch_from_control_plane() {
  local arch base f
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "no sensor build for $(uname -m) (amd64 and arm64 only)" ;;
  esac
  command -v curl >/dev/null || die "curl is required to download the sensor"
  command -v sha256sum >/dev/null || die "sha256sum is required to check the download"
  base="${URL%/}/api/v1/egress-sensor/download"
  DL_DIR=$(mktemp -d)
  trap 'rm -rf "$DL_DIR"' EXIT
  step "downloading the sensor from $base"
  for f in SHA256SUMS "provenza-sensor-linux-$arch" provenzasensor.service; do
    curl -fsSL --proto '=https,http' --max-time 300 -o "$DL_DIR/$f" "$base/$f" \
      || die "could not download $base/$f (is the control plane's backend image up to date?)"
  done
  ( cd "$DL_DIR" && grep -E " (provenza-sensor-linux-$arch|provenzasensor.service)\$" SHA256SUMS | sha256sum -c --quiet - ) \
    || die "checksum mismatch: the downloaded files do not match the control plane's SHA256SUMS"
  mv "$DL_DIR/provenza-sensor-linux-$arch" "$DL_DIR/provenza-sensor"
  chmod 0755 "$DL_DIR/provenza-sensor"
  ok "linux/$arch binary and unit, checksums match"
}

[ "$(id -u)" = 0 ] || die "run as root: sudo $0 ..."

# ---------------------------------------------------------------- uninstall

if [ "$UNINSTALL" = 1 ]; then
  step "uninstall"
  if command -v provenza-sensor >/dev/null 2>&1; then
    provenza-sensor --uninstall || warn "provenza-sensor --uninstall returned non-zero"
  fi
  systemctl disable --now provenzasensor 2>/dev/null || true
  rm -f /etc/systemd/system/provenzasensor.service
  rm -f /etc/tmpfiles.d/provenza-sensor.conf
  rm -rf /etc/provenza-sensor "$STATE_DIR" /run/provenza-sensor
  systemctl daemon-reload
  ok "removed"
  exit 0
fi

# ---------------------------------------------------------------- preflight

step "checking the host"

os_id=""
[ -r /etc/os-release ] && . /etc/os-release && os_id="${ID:-}"
ok "os: ${PRETTY_NAME:-unknown}"

kv=$(uname -r | cut -d. -f1-2)
kmaj=${kv%.*}; kmin=${kv#*.}
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -lt 15 ]; }; then
  warn "kernel $kv is older than 5.15; the sensor's BPF programs (ring buffer, cgroup socket hooks) may not load"
  [ "$FORCE" = 1 ] || confirm "Continue anyway?" n || die "aborted"
fi
ok "kernel: $kv"

if [ ! -f "$CGROUP_ROOT/cgroup.controllers" ]; then
  die "$CGROUP_ROOT is not a cgroup v2 mount (cgroup.controllers not found)"
fi
ok "cgroup v2: $CGROUP_ROOT"

if [ ! -r /sys/kernel/btf/vmlinux ]; then
  warn "no BTF at /sys/kernel/btf/vmlinux; the BPF programs may not load"
  [ "$FORCE" = 1 ] || confirm "Continue anyway?" n || die "aborted"
fi

if [ -n "$BIN_SRC" ]; then
  [ -x "$BIN_SRC" ] || die "--binary $BIN_SRC is not executable"
  BIN="$BIN_SRC"
elif [ -x "$SELF_DIR/provenza-sensor" ]; then
  BIN="$SELF_DIR/provenza-sensor"
elif [ -n "$URL" ]; then
  # the build that matches the control plane; no Go needed on this host
  fetch_from_control_plane
  BIN="$DL_DIR/provenza-sensor"
elif command -v go >/dev/null 2>&1 && [ -f "$SELF_DIR/cmd/provenza-sensor/main.go" ]; then
  step "building from source (go build)"
  ( cd "$SELF_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.version=dev' -o ./provenza-sensor ./cmd/provenza-sensor )
  BIN="$SELF_DIR/provenza-sensor"
else
  die "no binary found: pass --url (downloads it from the control plane), --binary PATH, or run 'make build' in this directory"
fi
ok "binary: $BIN"

UNIT_SRC="$SELF_DIR/packaging/provenzasensor.service"
if [ ! -f "$UNIT_SRC" ]; then
  [ -n "$URL" ] || die "packaging/provenzasensor.service not found next to this script: pass --url to download it"
  [ -f "$DL_DIR/provenzasensor.service" ] || fetch_from_control_plane
  UNIT_SRC="$DL_DIR/provenzasensor.service"
fi

# ---------------------------------------------------------------- install

step "creating the run group"
if getent group "$RUN_GROUP" >/dev/null 2>&1; then
  ok "group $RUN_GROUP exists"
else
  groupadd --system "$RUN_GROUP"
  ok "created group $RUN_GROUP"
fi

step "installing the binary"
install -m 0755 "$BIN" /usr/local/bin/provenza-sensor
ok "/usr/local/bin/provenza-sensor"

step "installing tmpfiles.d entry"
install -d -m 0755 /etc/tmpfiles.d
cat > /etc/tmpfiles.d/provenza-sensor.conf <<'TMPF'
# Parent for run cgroups created by the Provenza egress sensor daemon.
d /sys/fs/cgroup/provenza-run 0755 root root -
TMPF
systemd-tmpfiles --create /etc/tmpfiles.d/provenza-sensor.conf
ok "/etc/tmpfiles.d/provenza-sensor.conf"

step "installing systemd unit"
install -d -m 0755 /etc/provenza-sensor "$STATE_DIR" /run/provenza-sensor
install -m 0644 "$UNIT_SRC" /etc/systemd/system/provenzasensor.service
systemctl daemon-reload
ok "/etc/systemd/system/provenzasensor.service"

# ---------------------------------------------------------------- enroll

if [ -n "$URL" ] && [ -n "$KEY" ]; then
  step "enrolling with the control plane"
  provenza-sensor enroll --url "$URL" --key "$KEY" \
    --cgroup-root "$CGROUP_ROOT" --pin-dir "$PIN_DIR" \
    --state-dir "$STATE_DIR" --run-socket "$RUN_SOCKET" --run-group "$RUN_GROUP" \
    --no-restart
  systemctl enable --now provenzasensor
  ok "sensor running"
  echo
  echo "  Check it:  systemctl status provenzasensor"
  echo "  In the UI: ${URL%/}/runtime"
  exit 0
fi

step "prepared - waiting for a sensor key"
systemctl enable provenzasensor >/dev/null
ok "unit enabled (not started yet)"
echo
echo "  ${B}One step left:${N} open ${B}${URL:-<your control plane>}/runtime${N}, click"
echo "  ${B}Register sensor${N}, copy the key, and run on this host:"
echo
if [ -n "$URL" ]; then
  echo "    sudo provenza-sensor enroll --url $URL --key pvz_sensor_..."
else
  echo "    sudo provenza-sensor enroll --url https://your-domain --key pvz_sensor_..."
fi
echo "    sudo systemctl start provenzasensor"
echo
