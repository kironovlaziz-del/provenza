#!/usr/bin/env bash
# Upgrade a Provenza installation made with install.sh (run as root).
#
#   sudo ./upgrade.sh                 # to the latest commit of the current branch
#   sudo ./upgrade.sh --version v1.4  # to a tag (or any commit)
#
#   1. fetch the code and build the new images while the old version serves
#   2. keep the running images as :rollback
#   3. close the door (stop Caddy: nothing changes data any more) and back up
#   4. start the new version: its migrations run first
#   5. anything unhealthy -> roll back: the old code, units and images, and
#      the database from that backup if the migrations had already changed it
#
# Downtime is step 3 to 4: usually under a minute. Options: --yes (no
# questions), --force (upgrade over local changes to tracked files).

set -euo pipefail

READY_TIMEOUT=${PROVENZA_READY_TIMEOUT:-600}
VERSION="" ASSUME_YES=0 FORCE=0

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/scripts/lib.sh
. "$ROOT/deploy/scripts/lib.sh"

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
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

require_root
cd "$DEPLOY_DIR"
[ -f .env ] || die "deploy/.env not found - install first with ./install.sh"
require_podman
systemctl cat provenza-backend.service >/dev/null 2>&1 || die "the Provenza units are not installed - run ./install.sh"

IMAGES=("$(image_ref backend)" "$(image_ref web)")
rollback_ref() { printf '%s:rollback' "${1%:*}"; }
keep_images()    { local i; for i in "${IMAGES[@]}"; do podman image exists "$i" && podman tag "$i" "$(rollback_ref "$i")"; done; return 0; }
restore_images() { local i; for i in "${IMAGES[@]}"; do podman image exists "$(rollback_ref "$i")" && podman tag "$(rollback_ref "$i")" "$i"; done; return 0; }

db_revision() { { backend_run -- alembic current 2>/dev/null || true; } | awk '/^[0-9a-f]+/ {print $1}' | tail -n1; }
# The new (or, rolling back, the old) version: migrations first - restarting
# them restarts the API, worker and scheduler, which require them.
start_version() {
  systemctl restart provenza-migrate.service --no-block
  systemctl restart provenza-frontend.service --no-block
  systemctl start provenza.target --no-block
  wait_ready "$READY_TIMEOUT" backend worker frontend
}

printf '\n%sProvenza upgrade%s\n\n' "$B" "$N"

# ---------------------------------------------------------------- 1. code

step "Fetching the new version"
if [ "$FORCE" = 0 ] && [ -n "$(git_as_owner status --porcelain --untracked-files=no)" ]; then
  git_as_owner status --short --untracked-files=no >&2
  die "tracked files were changed on this server (above). Keep them elsewhere, or run with --force"
fi
prev=$(git_as_owner rev-parse HEAD)
branch=$(git_as_owner symbolic-ref --quiet --short HEAD || true)
git_as_owner fetch --tags --quiet origin || die "could not reach the repository"
if [ -n "$VERSION" ]; then
  target=$(git_as_owner rev-parse --verify --quiet "$VERSION^{commit}") || die "no such version: $VERSION"
else
  [ -n "$branch" ] || die "not on a branch: pass --version"
  target=$(git_as_owner rev-parse "origin/$branch")
fi
if [ "$target" = "$prev" ]; then ok "already at $(git_as_owner describe --tags --always "$prev")"; exit 0; fi
git_as_owner merge-base --is-ancestor "$prev" "$target" || warn "$(git_as_owner describe --tags --always "$target") is not ahead of the running version (a downgrade?)"
echo "    $(git_as_owner describe --tags --always "$prev") -> $(git_as_owner describe --tags --always "$target")"
git_as_owner --no-pager log --oneline --no-decorate "$prev..$target" | head -n 15 | sed 's/^/      /'
confirm "Upgrade now?" || exit 1

if [ -n "$VERSION" ]; then git_as_owner checkout --quiet --detach "$target"; else git_as_owner merge --quiet --ff-only "$target"; fi
code_back() {
  if [ -n "$branch" ]; then git_as_owner checkout --quiet "$branch" && git_as_owner reset --quiet --keep "$prev"
  else git_as_owner checkout --quiet --detach "$prev"; fi
  "$DEPLOY_DIR/scripts/units.sh" install >/dev/null
}
ok "code updated"

# ---------------------------------------------------------------- 2. images

step "Building the new images (the running version keeps serving)"
keep_images
if ! build_images; then
  restore_images
  code_back
  die "the build failed - nothing was changed, the old version is still running"
fi
pull_images || warn "could not pull a third-party image; the ones already here are used"
ok "images built"

# ---------------------------------------------------------------- 3. backup

step "Stopping outside access and backing up"
rev_before=$(db_revision)
systemctl stop provenza-caddy.service
if ! ./scripts/backup.sh | sed 's/^/    /'; then
  systemctl start provenza-caddy.service
  restore_images
  code_back
  die "the backup failed - upgrade cancelled, the old version is serving again"
fi
backup_dir=$(env_get BACKUP_DIR); backup_dir=${backup_dir:-./backups}
dump=$({ ls -t "$backup_dir"/provenza-*.dump 2>/dev/null || true; } | head -n1)
ok "backup: $dump"

# ---------------------------------------------------------------- 4. start

step "Starting the new version (migrations run first)"
"$DEPLOY_DIR/scripts/units.sh" install | sed 's/^/  /'
if start_version; then
  systemctl start provenza-caddy.service
  ok "upgraded to $(git_as_owner describe --tags --always HEAD), database at $(db_revision)"
  printf '\n%s✓ Upgrade complete%s - the previous images are kept as :rollback until the next upgrade.\n' "$G$B" "$N"
  exit 0
fi

# ---------------------------------------------------------------- 5. roll back

warn "the new version did not become healthy - rolling back"
journalctl -u provenza-backend.service -n 30 --no-pager >&2 || true
restore_images
code_back
rev_after=$(db_revision)
data_note="the database was not changed"
if [ -n "$dump" ] && [ "$rev_after" != "$rev_before" ]; then
  warn "the migrations had changed the database ($rev_before -> $rev_after): restoring $dump"
  PROVENZA_RESTORE_CONFIRM=restore ./scripts/restore.sh "$dump" | sed 's/^/    /'
  data_note="the database was restored from the pre-upgrade backup, taken with outside access closed"
fi
start_version || die "the rollback did not come up either - see ./scripts/units.sh status; the backup is $dump"
systemctl start provenza-caddy.service
die "upgrade failed and was rolled back to $(git_as_owner describe --tags --always "$prev"); $data_note"
