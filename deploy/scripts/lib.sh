# shellcheck shell=bash disable=SC2034
# Shared helpers for the Provenza scripts (install.sh, upgrade.sh and
# deploy/scripts/*). Source it; it defines functions and variables only.
#
# The stack runs as rootful Podman containers managed by systemd through
# Quadlet: the templates in deploy/quadlet/ are rendered into
# /etc/containers/systemd by deploy/scripts/units.sh.

DEPLOY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ROOT_DIR=$(dirname "$DEPLOY_DIR")
UNIT_DIR=${PROVENZA_UNIT_DIR:-/etc/containers/systemd}
SYSTEMD_DIR=/etc/systemd/system
RUNTIME_DIR="$DEPLOY_DIR/.runtime"
QUADLET_MIN=4.4   # the first Podman release with Quadlet

VOLUMES=(pg-data redis-data app-data beat-state caddy-data caddy-config prom-data grafana-data alertmanager-data)

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
step() { printf '%s→ %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

require_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...): the stack is rootful Podman managed by systemd"; }

# A value from deploy/.env, without sourcing it (the last assignment wins).
env_get() { sed -n "s/^$1=//p" "$DEPLOY_DIR/.env" 2>/dev/null | tail -n1; }

# The locally built images. A bare prefix ("provenza") is a local image name,
# which Podman stores under localhost/.
image_ref() {  # image_ref backend|web
  local prefix tag first
  prefix=$(env_get PROVENZA_IMAGE_PREFIX); prefix=${prefix:-provenza}
  tag=$(env_get PROVENZA_VERSION); tag=${tag:-local}
  first=${prefix%%/*}
  case "$first" in
    *.*|*:*|localhost) ;;
    *) prefix="localhost/$prefix" ;;
  esac
  printf '%s/%s:%s' "$prefix" "$1" "$tag"
}

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

quadlet_bin() {
  local p
  for p in /usr/libexec/podman/quadlet /usr/lib/podman/quadlet; do
    [ -x "$p" ] && { printf '%s' "$p"; return 0; }
  done
  return 1
}

# Podman with Quadlet, netavark networking and systemd.
require_podman() {
  command -v podman >/dev/null || die "Podman is not installed (install.sh installs it: apt install podman netavark aardvark-dns)"
  local v backend
  v=$(podman version --format '{{.Client.Version}}' 2>/dev/null || podman --version | awk '{print $NF}')
  version_ge "$v" "$QUADLET_MIN" || die "Podman $v is too old: Quadlet needs $QUADLET_MIN+ (Ubuntu 24.04+, Debian 13+, RHEL/Rocky 9.3+, Fedora)"
  quadlet_bin >/dev/null || die "the Quadlet generator is missing (podman package without /usr/libexec/podman/quadlet)"
  [ -d /run/systemd/system ] || die "systemd is not running: Quadlet units need systemd"
  backend=$(podman info --format '{{.Host.NetworkBackend}}' 2>/dev/null || true)
  [ "$backend" = netavark ] || die "Podman uses the '${backend:-?}' network backend; netavark is required for container DNS (apt install netavark aardvark-dns; see docs/self-hosting.md)"
  PODMAN_VERSION=$v
}

# A one-off backend container with the same settings as the services:
#   backend_run [podman run options] -- command args...
backend_run() {
  local opts=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do opts+=("$1"); shift; done
  [ "${1:-}" = -- ] || die "backend_run: missing -- before the command"
  shift
  local domain; domain=$(env_get PROVENZA_DOMAIN)
  podman run --rm --network provenza_data \
    --env-file "$DEPLOY_DIR/.env" \
    -e ENVIRONMENT=production -e POSTGRES_HOST=postgres -e POSTGRES_PORT=5432 \
    -e REDIS_HOST=redis -e REDIS_PORT=6379 -e "CORS_ORIGINS=https://$domain" \
    -v provenza_app-data:/app/data \
    --read-only --tmpfs /tmp:size=512m --cap-drop=all --security-opt=no-new-privileges \
    "${opts[@]}" "$(image_ref backend)" "$@"
}

# Build the two application images from this checkout.
build_images() {  # build_images [extra podman build args]
  local log; log=$(mktemp)
  podman build --pull=newer "$@" -t "$(image_ref backend)" -f "$DEPLOY_DIR/backend.Dockerfile" "$ROOT_DIR" >"$log" 2>&1 \
    || { tail -n 30 "$log" >&2; rm -f "$log"; return 1; }
  podman build --pull=newer "$@" -t "$(image_ref web)" -f "$DEPLOY_DIR/frontend.Dockerfile" "$ROOT_DIR" >"$log" 2>&1 \
    || { tail -n 30 "$log" >&2; rm -f "$log"; return 1; }
  rm -f "$log"
}

# Pull the third-party images named in the templates, so no unit pulls at start.
# Can a process in a container signal another in the same container? On some
# hosts AppArmor's container profile denies it (containers-default older than
# the kernel's signal mediation): pg_ctl cannot stop the server it started
# during PostgreSQL's first start, and tini cannot pass on a stop.
signals_ok() {
  podman run --rm --network none --entrypoint sh "$(image_ref backend)" -c 'sleep 30 & p=$!; kill "$p" || exit 1; wait "$p"; exit 0' \
    >/dev/null 2>&1
}

pull_images() {
  local img
  for img in $(sed -n 's/^Image=//p' "$DEPLOY_DIR"/quadlet/*.container | grep -v '^@' | sort -u); do
    podman image exists "$img" || podman pull -q "$img" >/dev/null || return 1
  done
}

container_running() { [ "$(podman container inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
# Healthy, or running when the container has no health check.
container_ready() {
  container_running "$1" || return 1
  local hc; hc=$(podman container inspect -f '{{if .Config.Healthcheck}}yes{{end}}' "$1" 2>/dev/null || true)
  [ -z "$hc" ] && return 0
  podman healthcheck run "$1" >/dev/null 2>&1
}
unit_failed() { [ "$(systemctl show -p ActiveState --value "$1" 2>/dev/null)" = failed ]; }

# Wait until the named containers are ready; fails early if the migrations failed.
wait_ready() {  # wait_ready timeout name...
  local timeout=$1 name pending; shift
  local deadline=$(( $(date +%s) + timeout ))
  while :; do
    if unit_failed provenza-migrate.service; then
      journalctl -u provenza-migrate.service -n 40 --no-pager >&2 || true
      warn "the database migrations failed (log above)"
      return 1
    fi
    pending=""
    for name in "$@"; do container_ready "$name" || pending="$pending $name"; done
    [ -z "$pending" ] && return 0
    if [ "$(date +%s)" -ge "$deadline" ]; then
      warn "not ready in time:$pending"
      podman ps -a --filter name='^(postgres|redis|migrate|backend|worker|beat|frontend|caddy)$' \
        --format '    {{.Names}}\t{{.Status}}' >&2 || true
      return 1
    fi
    sleep 5
  done
}

# Run git as the owner of the checkout, so a root script never leaves
# root-owned files in someone else's repository.
git_as_owner() {
  local owner; owner=$(stat -c %U "$ROOT_DIR/.git" 2>/dev/null || echo root)
  if [ "$owner" = root ] || [ "$(id -un)" = "$owner" ]; then
    git -C "$ROOT_DIR" "$@"
  else
    runuser -u "$owner" -- git -C "$ROOT_DIR" "$@"
  fi
}

# Is this commit the published release? A release (.github/workflows/release.yml)
# publishes release.json - its tag, commit and tree - signed by the release
# workflow. A checkout whose tag points at another commit than that record
# is not the released code: say so loudly. Warns, never stops (docs/releases.md).
release_check() {  # release_check <commit>
  local commit tag repo tmp rec
  commit=$(git_as_owner rev-parse --verify --quiet "$1^{commit}" 2>/dev/null) || {
    printf '    (not a git checkout: the release record is not checked)\n'; return 0; }
  tag=$(git_as_owner tag --points-at "$commit" --list 'v[0-9]*' 2>/dev/null | sort -V | tail -n1)
  if [ -z "$tag" ]; then
    printf '    (%s is not a tagged release, so there is no published record to check it against)\n' \
      "$(git_as_owner rev-parse --short "$commit")"
    return 0
  fi
  repo=$(git_as_owner remote get-url origin 2>/dev/null \
         | sed -nE 's#^(https://github\.com/|git@github\.com:)([^/]+/[^/]+)$#\2#p' | sed 's/\.git$//')
  if [ -z "$repo" ]; then warn "$tag: the repository is not on GitHub - its release record is not checked"; return 0; fi
  command -v curl >/dev/null || { warn "$tag: curl is missing - the release record is not checked"; return 0; }
  tmp=$(mktemp -d)
  if ! curl -fsSL --max-time 20 -o "$tmp/release.json" "https://github.com/$repo/releases/download/$tag/release.json" 2>/dev/null; then
    warn "$tag: no published release record (release.json) was found - this code is not checked against one"
    rm -rf "$tmp"; return 0
  fi
  rec=$(sed -nE 's/^ *"commit": *"([0-9a-f]{40})".*/\1/p' "$tmp/release.json" | head -n1)
  if [ "$rec" != "$commit" ]; then
    warn "THIS IS NOT THE RELEASED CODE: $tag here is commit $commit, the published release $tag is ${rec:-unreadable}."
    warn "Find out where this checkout came from before going on (docs/releases.md)."
    rm -rf "$tmp"; return 0
  fi
  if command -v gh >/dev/null && gh attestation verify "$tmp/release.json" --repo "$repo" >/dev/null 2>&1; then
    ok "$tag is the published release, and its record is signed by the release workflow"
  else
    ok "$tag is the published release (commit ${commit:0:12})"
    printf '    its signature: gh release download %s -p release.json -R %s && gh attestation verify release.json -R %s\n' \
      "$tag" "$repo" "$repo"
  fi
  rm -rf "$tmp"
  return 0
}
