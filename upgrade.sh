#!/usr/bin/env bash
# Upgrade a Provenza installation made with install.sh.
#
#   ./upgrade.sh                 # to the latest commit of the current branch
#   ./upgrade.sh --version v1.4  # to a tag (or any commit)
#
#   1. fetch the code and build the new images while the old version serves
#   2. keep the running images as :rollback
#   3. close the door (stop Caddy: nothing changes data any more) and back up
#   4. start the new version: its migrations run first
#   5. anything unhealthy -> roll back: the old code and images, and the
#      database from that backup if the migrations had already changed it
#
# Downtime is step 3 to 4: usually under a minute. Options: --yes (no
# questions), --force (upgrade over local changes to tracked files).

set -euo pipefail

READY_TIMEOUT=${PROVENZA_READY_TIMEOUT:-600}
VERSION="" ASSUME_YES=0 FORCE=0

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
step() { printf '%s→ %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  local ans
  printf '%s? %s%s [Y/n]: ' "$B" "$1" "$N" >/dev/tty
  IFS= read -r ans </dev/tty || true
  [[ "${ans:-y}" =~ ^[YyДд] ]]
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION=${2:?}; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPLOY="$ROOT/deploy"
cd "$DEPLOY"
[ -f .env ] || die "deploy/.env not found - install first with ./install.sh"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
compose() { docker compose "$@"; }

prefix=$(sed -n 's/^PROVENZA_IMAGE_PREFIX=//p' .env | head -n1); prefix=${prefix:-provenza}
tag=$(sed -n 's/^PROVENZA_VERSION=//p' .env | head -n1); tag=${tag:-local}
IMAGES=("$prefix/backend" "$prefix/web")

health() { local id; id=$(compose ps -q "$1" 2>/dev/null); [ -n "$id" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null; }
wait_healthy() {
  local deadline=$(( $(date +%s) + READY_TIMEOUT )) m
  while :; do
    m=$(compose ps -a -q migrate 2>/dev/null || true)
    if [ -n "$m" ]; then
      m=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$m" 2>/dev/null || true)
      [[ "$m" == exited* ]] && [ "$m" != "exited 0" ] && { compose logs --tail 30 migrate >&2; return 1; }
    fi
    [ "$(health backend)" = healthy ] && [ "$(health frontend)" = healthy ] && [ "$(health worker)" = healthy ] && return 0
    [ "$(date +%s)" -lt "$deadline" ] || { compose ps >&2; return 1; }
    sleep 5
  done
}
db_revision() { { compose run --rm -T --no-deps backend alembic current 2>/dev/null || true; } | awk '/^[0-9a-f]+/ {print $1}' | tail -n1; }

printf '\n%sProvenza upgrade%s\n\n' "$B" "$N"

# ---------------------------------------------------------------- 1. code

step "Fetching the new version"
cd "$ROOT"
if [ "$FORCE" = 0 ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  git status --short --untracked-files=no >&2
  die "tracked files were changed on this server (above). Keep them elsewhere, or run with --force"
fi
prev=$(git rev-parse HEAD)
branch=$(git symbolic-ref --quiet --short HEAD || true)
git fetch --tags --quiet origin || die "could not reach the repository"
if [ -n "$VERSION" ]; then
  target=$(git rev-parse --verify --quiet "$VERSION^{commit}") || die "no such version: $VERSION"
else
  [ -n "$branch" ] || die "not on a branch: pass --version"
  target=$(git rev-parse "origin/$branch")
fi
if [ "$target" = "$prev" ]; then ok "already at $(git describe --tags --always "$prev")"; exit 0; fi
git merge-base --is-ancestor "$prev" "$target" || warn "$(git describe --tags --always "$target") is not ahead of the running version (a downgrade?)"
echo "    $(git describe --tags --always "$prev") -> $(git describe --tags --always "$target")"
git --no-pager log --oneline --no-decorate "$prev..$target" | head -n 15 | sed 's/^/      /'
confirm "Upgrade now?" || exit 1

if [ -n "$VERSION" ]; then git checkout --quiet --detach "$target"; else git merge --quiet --ff-only "$target"; fi
code_back() { cd "$ROOT"; if [ -n "$branch" ]; then git checkout --quiet "$branch" && git reset --quiet --keep "$prev"; else git checkout --quiet --detach "$prev"; fi; cd "$DEPLOY"; }
ok "code updated"

# ---------------------------------------------------------------- 2. images

cd "$DEPLOY"
step "Building the new images (the running version keeps serving)"
for img in "${IMAGES[@]}"; do
  docker image inspect "$img:$tag" >/dev/null 2>&1 && docker image tag "$img:$tag" "$img:rollback"
done
if ! compose build --pull 2>&1 | sed 's/^/    /' | tail -n 5; then
  for img in "${IMAGES[@]}"; do docker image inspect "$img:rollback" >/dev/null 2>&1 && docker image tag "$img:rollback" "$img:$tag"; done
  code_back
  die "the build failed - nothing was changed, the old version is still running"
fi
ok "images built"

# ---------------------------------------------------------------- 3. backup

step "Stopping outside access and backing up"
rev_before=$(db_revision)
compose stop caddy >/dev/null
if ! ./scripts/backup.sh | sed 's/^/    /'; then
  compose start caddy >/dev/null
  for img in "${IMAGES[@]}"; do docker image inspect "$img:rollback" >/dev/null 2>&1 && docker image tag "$img:rollback" "$img:$tag"; done
  code_back
  die "the backup failed - upgrade cancelled, the old version is serving again"
fi
backup_dir=$(sed -n 's/^BACKUP_DIR=//p' .env | head -n1); backup_dir=${backup_dir:-./backups}
dump=$({ ls -t "$backup_dir"/provenza-*.dump 2>/dev/null || true; } | head -n1)
ok "backup: $dump"

# ---------------------------------------------------------------- 4. start

step "Starting the new version (migrations run first)"
if compose up -d --remove-orphans >/dev/null && wait_healthy; then
  compose up -d caddy >/dev/null
  ok "upgraded to $(cd "$ROOT" && git describe --tags --always HEAD), database at $(db_revision)"
  printf '\n%s✓ Upgrade complete%s - the previous images are kept as :rollback until the next upgrade.\n' "$G$B" "$N"
  exit 0
fi

# ---------------------------------------------------------------- 5. roll back

warn "the new version did not become healthy - rolling back"
compose logs --tail 30 backend >&2 || true
for img in "${IMAGES[@]}"; do docker image inspect "$img:rollback" >/dev/null 2>&1 && docker image tag "$img:rollback" "$img:$tag"; done
code_back
rev_after=$(db_revision)
data_note="the database was not changed"
if [ -n "$dump" ] && [ "$rev_after" != "$rev_before" ]; then
  warn "the migrations had changed the database ($rev_before -> $rev_after): restoring $dump"
  PROVENZA_RESTORE_CONFIRM=restore ./scripts/restore.sh "$dump" | sed 's/^/    /'
  data_note="the database was restored from the pre-upgrade backup, taken with outside access closed"
else
  compose up -d >/dev/null
fi
wait_healthy || die "the rollback did not come up either - see docker compose logs; the backup is $dump"
compose up -d caddy >/dev/null
die "upgrade failed and was rolled back to $(cd "$ROOT" && git describe --tags --always "$prev"); $data_note"
