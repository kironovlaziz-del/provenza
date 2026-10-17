#!/usr/bin/env bash
# Provenza installer: a working control plane on your server in one command.
#
#   git clone https://github.com/kironovlaziz-del/provenza.git && cd provenza && sudo ./install.sh
#
# or, without cloning first (read the script before piping it into a shell):
#
#   curl -fsSL https://raw.githubusercontent.com/kironovlaziz-del/provenza/main/install.sh | sudo bash
#
# It checks the host and installs Podman if it is missing, asks for the domain
# and the first administrator, generates every secret, builds the images and
# starts the stack as rootful Podman containers managed by systemd (Quadlet
# units from deploy/quadlet/: PostgreSQL, Redis, migrations, API, worker,
# scheduler, web UI, Caddy with automatic HTTPS, Prometheus, Grafana,
# Alertmanager), creates the administrator and schedules a daily backup.
#
# Unattended:
#   PROVENZA_ADMIN_PASSWORD=... ./install.sh --yes --domain app.example.com \
#     --org "Example Inc" --admin-email admin@example.com [--admin-name "Jane Admin"] \
#     [--no-backup] [--force] [--sensor|--no-sensor]
#   (--force: go on despite host warnings - low memory or disk, ports 80/443 taken)
#
# Run it again at any time: an existing configuration (deploy/.env) is kept,
# and an existing administrator is left unchanged. A stack still running on
# Docker is moved with deploy/scripts/migrate-from-docker.sh instead.

set -euo pipefail

REPO_URL="${PROVENZA_REPO:-https://github.com/kironovlaziz-del/provenza.git}"
INSTALL_DIR="${PROVENZA_DIR:-/opt/provenza}"
MIN_RAM_MB=3500
MIN_DISK_GB=10
READY_TIMEOUT=${PROVENZA_READY_TIMEOUT:-900}   # seconds; the first build alone can take several minutes

DOMAIN="" ORG="" ADMIN_EMAIL="" ADMIN_NAME="" ASSUME_YES=0 FORCE=0 BACKUP=1
SENSOR_MODE=ask   # ask | yes | no
ARGS=("$@")

# ---------------------------------------------------------------- output (before lib.sh exists)

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
step() { printf '%s→ %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

ask() {  # ask VAR "Question" [default]
  local __var=$1 __q=$2 __def=${3:-} __ans
  if [ "$ASSUME_YES" = 1 ] && [ -n "$__def" ]; then printf -v "$__var" '%s' "$__def"; return; fi
  [ "$ASSUME_YES" = 1 ] && die "--yes needs a value for: $__q"
  if [ -n "$__def" ]; then printf '%s? %s%s [%s]: ' "$B" "$__q" "$N" "$__def" >/dev/tty; else printf '%s? %s%s: ' "$B" "$__q" "$N" >/dev/tty; fi
  IFS= read -r __ans </dev/tty || true
  printf -v "$__var" '%s' "${__ans:-$__def}"
}
confirm() {  # confirm "Question" [y|n]
  local def=${2:-y} ans
  [ "$ASSUME_YES" = 1 ] && { [ "$def" = y ]; return; }
  printf '%s? %s%s [%s]: ' "$B" "$1" "$N" "$([ "$def" = y ] && echo Y/n || echo y/N)" >/dev/tty
  IFS= read -r ans </dev/tty || true
  ans=${ans:-$def}
  [[ "$ans" =~ ^[YyДд] ]]
}

# A host warning (memory, disk, ports): go on with --force, else ask (--yes alone stops).
accept_warning() { [ "$FORCE" = 1 ] || confirm "Continue anyway?" n; }

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=${2:?}; shift 2 ;;
    --org) ORG=${2:?}; shift 2 ;;
    --admin-email) ADMIN_EMAIL=${2:?}; shift 2 ;;
    --admin-name) ADMIN_NAME=${2:?}; shift 2 ;;
    --dir) INSTALL_DIR=${2:?}; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-backup|--no-cron) BACKUP=0; shift ;;
    --sensor) SENSOR_MODE=yes; shift ;;
    --no-sensor) SENSOR_MODE=no; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------- root
# Rootful Podman and systemd units: the installer runs as root.

SELF="${BASH_SOURCE[0]:-$0}"
if [ "$(id -u)" != 0 ]; then
  [ -f "$SELF" ] || die "run it as root: curl -fsSL .../install.sh | sudo bash"
  command -v sudo >/dev/null || die "run as root"
  exec sudo --preserve-env=PROVENZA_ADMIN_PASSWORD,PROVENZA_DIR,PROVENZA_REPO,PROVENZA_READY_TIMEOUT \
    bash "$SELF" "${ARGS[@]}"
fi

# ---------------------------------------------------------------- bootstrap
# Piped from curl, or copied alone: fetch the repository, then run from it.

SELF_DIR=$(cd "$(dirname "$SELF")" 2>/dev/null && pwd || pwd)
if [ ! -d "$SELF_DIR/deploy/quadlet" ]; then
  if ! command -v git >/dev/null; then
    command -v apt-get >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git >/dev/null
    command -v git >/dev/null || die "git is required (apt install git)"
  fi
  step "Getting Provenza into $INSTALL_DIR"
  if [ -d "$INSTALL_DIR/.git" ]; then
    ok "already there - using it"
  else
    git clone --depth 50 "$REPO_URL" "$INSTALL_DIR" || die "could not clone $REPO_URL into $INSTALL_DIR (try --dir)"
  fi
  exec bash "$INSTALL_DIR/install.sh" "${ARGS[@]}"
fi

# shellcheck source=deploy/scripts/lib.sh
. "$SELF_DIR/deploy/scripts/lib.sh"
DEPLOY="$DEPLOY_DIR"
cd "$DEPLOY"

printf '\n%sProvenza installer%s\n\n' "$B" "$N"

# ---------------------------------------------------------------- 1. host

step "Checking this server"
[ "$(uname -s)" = Linux ] || die "Linux is required"
[ -d /run/systemd/system ] || die "systemd is not running: Provenza's services are systemd units"

install_podman() {
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq podman netavark aardvark-dns openssl git >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q podman netavark aardvark-dns openssl git >/dev/null
  else
    die "install Podman 4.4+ with netavark and aardvark-dns, then run the installer again"
  fi
}
need_podman=0
command -v podman >/dev/null || need_podman=1
# Ubuntu's podman does not pull in netavark/aardvark-dns by itself
if command -v dpkg >/dev/null && ! dpkg -s netavark aardvark-dns >/dev/null 2>&1; then need_podman=1; fi
if [ "$need_podman" = 1 ]; then
  confirm "Install Podman (with netavark and aardvark-dns) from the distribution's packages?" y \
    || die "Podman 4.4+ is required"
  step "Installing Podman"
  install_podman || die "could not install Podman"
fi
require_podman
ok "Podman $PODMAN_VERSION (Quadlet, netavark)"
command -v openssl >/dev/null || die "openssl is required (apt install openssl)"

# A stack still on Docker is moved, not installed over
if command -v docker >/dev/null && docker ps -q --filter label=com.docker.compose.project=provenza 2>/dev/null | grep -q .; then
  die "Provenza is running on Docker here. Move it with: sudo $DEPLOY/scripts/migrate-from-docker.sh (see docs/self-hosting.md)"
fi

ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$ram_mb" -gt 0 ] && [ "$ram_mb" -lt "$MIN_RAM_MB" ]; then
  warn "${ram_mb} MB RAM: 4 GB is the minimum"
  accept_warning || exit 1
else
  ok "${ram_mb} MB RAM"
fi
store=$(podman info --format '{{.Store.GraphRoot}}' 2>/dev/null || echo /var/lib/containers)
mkdir -p "$store" 2>/dev/null || true
disk_gb=$({ df -Pk "$store" 2>/dev/null || df -Pk / 2>/dev/null || true; } | awk 'NR==2 {print int($4/1048576)}')
if [ "${disk_gb:-0}" -lt "$MIN_DISK_GB" ]; then
  warn "${disk_gb:-?} GB free for containers: images and data need at least ${MIN_DISK_GB} GB"
  accept_warning || exit 1
else
  ok "${disk_gb} GB free disk"
fi

# ---------------------------------------------------------------- 2. configuration

step "Configuration"
if [ -f .env ]; then
  ok "existing configuration found (deploy/.env) - keeping its secrets"
  DOMAIN=$(env_get PROVENZA_DOMAIN)
  ok "domain: $DOMAIN"
else
  [ -n "$DOMAIN" ] || ask DOMAIN "Domain for Provenza (DNS must point to this server; 'localhost' for a trial)"
  DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z' | sed 's#^https\{0,1\}://##; s#/.*$##')
  [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "not a domain name: $DOMAIN"
  ./scripts/init-env.sh "$DOMAIN" >/dev/null
  ok "secrets generated into deploy/.env (mode 600)"
fi

if [ "$DOMAIN" != localhost ]; then
  resolved=$({ getent ahosts "$DOMAIN" 2>/dev/null || true; } | awk '{print $1}' | sort -u | tr '\n' ' ')
  if [ -z "$resolved" ]; then
    warn "$DOMAIN does not resolve yet: HTTPS certificates are issued once its DNS record points here"
  else
    ok "$DOMAIN resolves to $resolved"
  fi
fi
for port in "$(v=$(env_get HTTP_PORT); echo "${v:-80}")" "$(v=$(env_get HTTPS_PORT); echo "${v:-443}")"; do
  if command -v ss >/dev/null && ss -ltnH "sport = :$port" 2>/dev/null | grep -q . && ! container_running caddy; then
    warn "port $port is already in use (another web server?). Stop it, or set HTTP_PORT/HTTPS_PORT in deploy/.env"
    accept_warning || exit 1
  fi
done

[ -n "$ORG" ] || ask ORG "Organization name" "My Company"
[ -n "$ADMIN_EMAIL" ] || ask ADMIN_EMAIL "Administrator e-mail"
[[ "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "not an e-mail address: $ADMIN_EMAIL"
[ -n "$ADMIN_NAME" ] || ask ADMIN_NAME "Administrator name" "Administrator"
SLUG=$(printf '%s' "$ORG" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]\{1,\}/-/g; s/^-//; s/-$//' | cut -c1-50)
[ -n "$SLUG" ] || SLUG=org

if [ -z "${PROVENZA_ADMIN_PASSWORD:-}" ]; then
  [ "$ASSUME_YES" = 1 ] && die "--yes needs PROVENZA_ADMIN_PASSWORD in the environment"
  while :; do
    printf '%s? Administrator password (12+ characters)%s: ' "$B" "$N" >/dev/tty
    IFS= read -rs p1 </dev/tty; printf '\n' >/dev/tty
    printf '%s? Repeat the password%s: ' "$B" "$N" >/dev/tty
    IFS= read -rs p2 </dev/tty; printf '\n' >/dev/tty
    if [ "${#p1}" -lt 12 ]; then warn "at least 12 characters"; continue; fi
    if [ "$p1" != "$p2" ]; then warn "the passwords do not match"; continue; fi
    break
  done
  PROVENZA_ADMIN_PASSWORD=$p1
  unset p1 p2
fi
[ "${#PROVENZA_ADMIN_PASSWORD}" -ge 12 ] || die "the administrator password needs at least 12 characters"
export PROVENZA_ADMIN_PASSWORD

# ---------------------------------------------------------------- 3. stack

step "Building the images (the first build takes a few minutes)"
build_images || die "the build failed - see the output above"
pull_images || die "could not pull the PostgreSQL, Redis, Caddy or monitoring images"
ok "images ready: $(image_ref backend), $(image_ref web)"

step "Installing the systemd units"
./scripts/units.sh install | sed 's/^/  /'

step "Starting the stack"
# A running stack picks up new images and units; a stopped one just starts
if container_running backend; then
  systemctl restart provenza-migrate.service --no-block
  systemctl restart provenza-frontend.service provenza-caddy.service --no-block
fi
systemctl start provenza.target --no-block
if ! wait_ready "$READY_TIMEOUT" postgres redis backend worker frontend caddy; then
  die "the services did not become ready in time: provenza status, provenza logs backend"
fi
ok "migrations applied; API, workers, web UI and HTTPS proxy are up"

step "Creating the administrator"
backend_run -e PROVENZA_ADMIN_PASSWORD -- create-admin \
  --org "$ORG" --slug "$SLUG" --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" | sed 's/^/    /' \
  || die "could not create the administrator: journalctl -u provenza-backend -n 50"
unset PROVENZA_ADMIN_PASSWORD

# ---------------------------------------------------------------- 4. backups

# The Docker-era cron line (docker compose exec ...) no longer works
if [ -n "${SUDO_USER:-}" ] && command -v crontab >/dev/null \
   && crontab -u "$SUDO_USER" -l 2>/dev/null | grep -Fq "$DEPLOY && ./scripts/backup.sh"; then
  crontab -u "$SUDO_USER" -l | grep -Fv "$DEPLOY && ./scripts/backup.sh" | crontab -u "$SUDO_USER" -
  ok "removed the old backup line from $SUDO_USER's crontab (the systemd timer replaces it)"
fi
if [ "$BACKUP" = 1 ]; then
  if systemctl is-enabled --quiet provenza-backup.timer 2>/dev/null; then
    ok "daily backup already scheduled (systemctl list-timers provenza-backup.timer)"
  elif confirm "Schedule a daily database backup (03:15, kept 14 days)?" y; then
    systemctl enable --now provenza-backup.timer >/dev/null 2>&1
    ok "daily backup scheduled (systemctl list-timers provenza-backup.timer)"
  fi
fi

url="https://$DOMAIN"

# ---------------------------------------------------------------- 5. sensor

SENSOR_INSTALLED=0
if [ "$SENSOR_MODE" = yes ] || { [ "$SENSOR_MODE" = ask ] && [ "$ASSUME_YES" = 0 ] && confirm "Install the egress sensor on this host as well?" n; }; then
  step "Installing the egress sensor on this host"
  if [ -x "$ROOT_DIR/sensor/install.sh" ]; then
    SENSOR_BIN="$ROOT_DIR/sensor/provenza-sensor"
    if [ ! -x "$SENSOR_BIN" ]; then
      # The BPF object is embedded in the repo; clang is only needed to
      # rebuild it. Installing go + make lets us build the daemon here.
      if ! command -v go >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1; then
        step "Installing sensor build tools (go, make)"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go make >/dev/null 2>&1 || warn "could not install go/make"
      fi
      if command -v go >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
        step "Building the sensor binary"
        ( cd "$ROOT_DIR/sensor" && make build >/dev/null 2>&1 ) || warn "sensor build failed"
      fi
    fi
    if [ -x "$SENSOR_BIN" ]; then
      if "$ROOT_DIR/sensor/install.sh" --binary "$SENSOR_BIN" --url "$url" --yes; then
        SENSOR_INSTALLED=1
      else
        warn "sensor install returned non-zero - see the output above"
      fi
    else
      warn "sensor binary not found and cannot be built (install go + make, then: sudo $ROOT_DIR/sensor/install.sh --url $url)"
    fi
  else
    warn "sensor/install.sh not found in $ROOT_DIR - skipping"
  fi
fi

# ---------------------------------------------------------------- done

cat <<EOF

${G}${B}✓ Provenza is running at $url${N}

  Organization: $SLUG
  Administrator: $ADMIN_EMAIL
  Manage it: provenza status | logs <service> | restart | upgrade   (provenza help)
EOF

if [ "$SENSOR_INSTALLED" = 1 ]; then
  cat <<EOF

The egress sensor is installed on this host and enabled, waiting for a key.
  1. Open $url/runtime, click ${B}Register sensor${N}, copy the key (${B}pvz_sensor_...${N}).
  2. On this host, run:
       ${B}sudo provenza-sensor enroll --url $url --key pvz_sensor_...${N}
       ${B}sudo systemctl start provenzasensor${N}
EOF
else
  cat <<EOF

To govern egress on any Linux host (this one or another), install the sensor:
  ${B}git clone https://github.com/kironovlaziz-del/provenza.git /tmp/provenza${N}
  ${B}cd /tmp/provenza/sensor && sudo ./install.sh --url $url${N}
then open $url/runtime, click Register sensor, and run:
  ${B}sudo provenza-sensor enroll --url $url --key pvz_sensor_...${N}
  ${B}sudo systemctl start provenzasensor${N}
EOF
fi

cat <<EOF

Next steps
  1. Sign in at $url and follow the setup checklist on the dashboard.
  2. My profile → turn on two-factor sign-in.
  3. Agents → create an enrollment token, then on the agent's host:
       pip install provenza
  4. ${B}Back up deploy/.env now${N} (off this server): without its ENCRYPTION_KEY
     no backup can be read.

Upgrade later with provenza upgrade - see docs/self-hosting.md.
EOF
