#!/usr/bin/env bash
# Provenza installer: a working control plane on your server in one command.
#
#   git clone https://github.com/kironovlaziz-del/provenza.git && cd provenza && ./install.sh
#
# or, without cloning first (read the script before piping it into a shell):
#
#   curl -fsSL https://raw.githubusercontent.com/kironovlaziz-del/provenza/main/install.sh | bash
#
# It checks the host, asks for the domain and the first administrator,
# generates every secret, builds and starts the stack (deploy/docker-compose.yml:
# PostgreSQL, Redis, migrations, API, workers, web UI, Caddy with automatic
# HTTPS), creates the administrator and schedules a daily backup.
#
# Unattended:
#   PROVENZA_ADMIN_PASSWORD=... ./install.sh --yes --domain app.example.com \
#     --org "Example Inc" --admin-email admin@example.com [--admin-name "Jane Admin"] \
#     [--no-cron] [--force] [--sensor|--no-sensor]
#   (--force: go on despite host warnings - low memory or disk, ports 80/443 taken)
#
# Run it again at any time: an existing configuration (deploy/.env) is kept,
# and an existing administrator is left unchanged.

set -euo pipefail

REPO_URL="${PROVENZA_REPO:-https://github.com/kironovlaziz-del/provenza.git}"
INSTALL_DIR="${PROVENZA_DIR:-/opt/provenza}"
MIN_RAM_MB=3500
MIN_DISK_GB=10
READY_TIMEOUT=${PROVENZA_READY_TIMEOUT:-900}   # seconds; the first build alone can take several minutes

DOMAIN="" ORG="" ADMIN_EMAIL="" ADMIN_NAME="" ASSUME_YES=0 FORCE=0 CRON=1
SENSOR_MODE=ask   # ask | yes | no

# ---------------------------------------------------------------- output

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
step() { printf '%s→ %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

# Prompts read from the terminal, so `curl ... | bash` still asks.
tty_in() { if [ -r /dev/tty ]; then cat /dev/tty; else cat; fi; }
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

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=${2:?}; shift 2 ;;
    --org) ORG=${2:?}; shift 2 ;;
    --admin-email) ADMIN_EMAIL=${2:?}; shift 2 ;;
    --admin-name) ADMIN_NAME=${2:?}; shift 2 ;;
    --dir) INSTALL_DIR=${2:?}; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-cron) CRON=0; shift ;;
    --sensor) SENSOR_MODE=yes; shift ;;
    --no-sensor) SENSOR_MODE=no; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------- bootstrap
# Piped from curl, or copied alone: fetch the repository, then run from it.

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)
if [ ! -f "$SELF_DIR/deploy/docker-compose.yml" ]; then
  command -v git >/dev/null || die "git is required (apt install git)"
  step "Getting Provenza into $INSTALL_DIR"
  if [ -d "$INSTALL_DIR/.git" ]; then
    ok "already there - using it"
  else
    git clone --depth 50 "$REPO_URL" "$INSTALL_DIR" || die "could not clone $REPO_URL into $INSTALL_DIR (try --dir or sudo)"
  fi
  exec bash "$INSTALL_DIR/install.sh" "$@"
fi
ROOT=$SELF_DIR
DEPLOY="$ROOT/deploy"
cd "$DEPLOY"
compose() { docker compose "$@"; }

printf '\n%sProvenza installer%s\n\n' "$B" "$N"

# ---------------------------------------------------------------- 1. host

step "Checking this server"
[ "$(uname -s)" = Linux ] || warn "not Linux: the stack is tested on Ubuntu 22.04+ / Debian 12+"
command -v docker >/dev/null || die "Docker is not installed: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker is not reachable: start it, and run as root or as a user in the docker group"
compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing: install the docker-compose-plugin package"
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), Compose $(compose version --short 2>/dev/null)"
command -v openssl >/dev/null || die "openssl is required (apt install openssl)"

ram_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$ram_mb" -gt 0 ] && [ "$ram_mb" -lt "$MIN_RAM_MB" ]; then
  warn "${ram_mb} MB RAM: 4 GB is the minimum"
  accept_warning || exit 1
else
  ok "${ram_mb} MB RAM"
fi
# Docker's data directory is often unreadable for a non-root user: fall back to /
docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)
disk_gb=$({ df -Pk "${docker_root:-/}" 2>/dev/null || df -Pk / 2>/dev/null || true; } | awk 'NR==2 {print int($4/1048576)}')
if [ "${disk_gb:-0}" -lt "$MIN_DISK_GB" ]; then
  warn "${disk_gb:-?} GB free for Docker: images and data need at least ${MIN_DISK_GB} GB"
  accept_warning || exit 1
else
  ok "${disk_gb} GB free disk"
fi

# ---------------------------------------------------------------- 2. configuration

step "Configuration"
if [ -f .env ]; then
  ok "existing configuration found (deploy/.env) - keeping its secrets"
  DOMAIN=$(sed -n 's/^PROVENZA_DOMAIN=//p' .env | head -n1)
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
for port in 80 443; do
  if command -v ss >/dev/null && ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
    if ! compose ps --services --status running 2>/dev/null | grep -qx caddy; then
      warn "port $port is already in use (another web server?). Stop it, or set HTTP_PORT/HTTPS_PORT in deploy/.env"
      accept_warning || exit 1
    fi
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

step "Building and starting the stack (the first build takes a few minutes)"
compose build --pull 2>&1 | sed 's/^/    /' | tail -n 5 || die "the build failed - see the output above"
compose up -d || die "the stack did not start: docker compose logs"
ok "containers started"

step "Waiting for the database migrations and the services"
health() { local id; id=$(compose ps -q "$1" 2>/dev/null); [ -n "$id" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null; }
deadline=$(( $(date +%s) + READY_TIMEOUT ))
while :; do
  migrate_id=$(compose ps -a -q migrate 2>/dev/null || true)
  migrate_state=$([ -n "$migrate_id" ] && docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$migrate_id" || true)
  if [[ "$migrate_state" == exited* ]] && [ "$migrate_state" != "exited 0" ]; then
    compose logs --tail 40 migrate >&2
    die "the database migrations failed (log above)"
  fi
  if [ "$(health backend)" = healthy ] && [ "$(health frontend)" = healthy ] && [ "$(health caddy)" = running ]; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || { compose ps >&2; die "the services did not become healthy in time: docker compose logs backend"; }
  sleep 5
done
ok "migrations applied; API, workers, web UI and HTTPS proxy are up"

step "Creating the administrator"
compose run --rm -T -e PROVENZA_ADMIN_PASSWORD backend create-admin \
  --org "$ORG" --slug "$SLUG" --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" | sed 's/^/    /' \
  || die "could not create the administrator: docker compose logs backend"
unset PROVENZA_ADMIN_PASSWORD

# ---------------------------------------------------------------- 4. backups

if [ "$CRON" = 1 ] && command -v crontab >/dev/null; then
  line="15 3 * * * cd $DEPLOY && ./scripts/backup.sh >> backups/backup.log 2>&1"
  if crontab -l 2>/dev/null | grep -Fq "$DEPLOY && ./scripts/backup.sh"; then
    ok "daily backup already scheduled"
  elif confirm "Schedule a daily database backup (03:15, kept 14 days)?" y; then
    mkdir -p backups
    { crontab -l 2>/dev/null || true; echo "$line"; } | crontab -
    ok "daily backup scheduled (crontab -l)"
  fi
fi

# ---------------------------------------------------------------- done

url="https://$DOMAIN"

# ---------------------------------------------------------------- 5. sensor

SENSOR_INSTALLED=0
if [ "$SENSOR_MODE" = yes ] || { [ "$SENSOR_MODE" = ask ] && [ "$ASSUME_YES" = 0 ] && confirm "Install the egress sensor on this host as well?" n; }; then
  step "Installing the egress sensor on this host"
  if [ -x "$INSTALL_DIR/sensor/install.sh" ]; then
    SENSOR_BIN="$INSTALL_DIR/sensor/provenza-sensor"
    if [ ! -x "$SENSOR_BIN" ]; then
      # The BPF object is embedded in the repo; clang is only needed to
      # rebuild it. Installing go + make lets us build the daemon here.
      if ! command -v go >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1; then
        step "Installing sensor build tools (go, make)"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
          golang-go make >/dev/null 2>&1 || warn "could not install go/make"
      fi
      if command -v go >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
        step "Building the sensor binary"
        ( cd "$INSTALL_DIR/sensor" && make build >/dev/null 2>&1 ) || warn "sensor build failed"
      fi
    fi
    if [ -x "$SENSOR_BIN" ]; then
      if sudo "$INSTALL_DIR/sensor/install.sh" --binary "$SENSOR_BIN" --url "$url" --yes; then
        SENSOR_INSTALLED=1
      else
        warn "sensor install returned non-zero - see the output above"
      fi
    else
      warn "sensor binary not found and cannot be built (install go + make, then: sudo $INSTALL_DIR/sensor/install.sh --url $url)"
    fi
  else
    warn "sensor/install.sh not found in $INSTALL_DIR - skipping"
  fi
fi

# ---------------------------------------------------------------- done

cat <<EOF

${G}${B}✓ Provenza is running at $url${N}

  Organization: $SLUG
  Administrator: $ADMIN_EMAIL
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

Upgrade later with ./upgrade.sh - see docs/self-hosting.md.
EOF
