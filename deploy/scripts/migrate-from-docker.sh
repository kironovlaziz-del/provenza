#!/usr/bin/env bash
# Move a running Docker compose installation of Provenza to rootful Podman
# (Quadlet units), keeping all data. Run as root from the checkout:
#
#   sudo ./deploy/scripts/migrate-from-docker.sh [--yes]
#
#   1. build the images and install the units while Docker keeps serving
#   2. stop the application, take a pg_dump (kept in backups/)
#   3. stop the Docker containers (kept, with restart disabled) and copy every
#      Docker volume into the Podman volume of the same name
#   4. start the stack under systemd and wait until it is healthy
#   5. anything wrong -> the Podman services stop and the Docker containers
#      start again; Docker volumes are never modified
#
# Downtime is step 2 to 4: a few minutes. Afterwards, once you are sure,
# remove the Docker containers and volumes (the script prints the commands).

set -euo pipefail
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ASSUME_YES=0 FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1; shift ;;
    --force) FORCE=1; shift ;;   # copy even into non-empty Podman volumes
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  local ans; printf '%s? %s%s [y/N]: ' "$B" "$1" "$N" >/dev/tty
  IFS= read -r ans </dev/tty || true
  [[ "$ans" =~ ^[YyДд] ]]
}

require_root
cd "$DEPLOY_DIR"
[ -f .env ] || die "deploy/.env not found"
command -v docker >/dev/null || die "docker is not installed: nothing to migrate"
PROJECT=provenza
dc_ids() {  # dc_ids [service...] -> container ids of the compose project
  local s
  if [ $# -eq 0 ]; then docker ps -aq --filter "label=com.docker.compose.project=$PROJECT"; return; fi
  for s in "$@"; do docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$s"; done
}
[ -n "$(dc_ids postgres)" ] || die "no Docker container of the '$PROJECT' compose project with a postgres service"
require_podman

pg_user=$(env_get POSTGRES_USER); pg_user=${pg_user:-provenza}
pg_db=$(env_get POSTGRES_DB); pg_db=${pg_db:-provenza}

printf '\n%sProvenza: Docker -> Podman%s\n\n' "$B" "$N"

# ---------------------------------------------------------------- 1. prepare

step "Building the images and installing the units (Docker keeps serving)"
build_images || die "the build failed - nothing was changed"
pull_images || die "could not pull the PostgreSQL, Redis, Caddy or monitoring images"
./scripts/units.sh install | sed 's/^/  /'

for v in "${VOLUMES[@]}"; do
  systemctl start "provenza-$v-volume.service"
  dst=$(podman volume inspect "provenza_$v" --format '{{.Mountpoint}}')
  if [ -n "$(ls -A "$dst" 2>/dev/null)" ] && [ "$FORCE" = 0 ]; then
    die "the Podman volume provenza_$v is not empty ($dst). Already migrated? (--force copies over it)"
  fi
done
ok "Podman volumes created and empty"

confirm "Stop Provenza on Docker and move it to Podman now (a few minutes of downtime)?" || exit 1

# ---------------------------------------------------------------- 2. dump

step "Stopping the application and taking a database dump"
app=$(dc_ids caddy backend worker beat frontend prometheus grafana alertmanager)
[ -z "$app" ] || docker stop $app >/dev/null
backup_dir=$(env_get BACKUP_DIR); backup_dir=${backup_dir:-./backups}
mkdir -p "$backup_dir"
dump="$backup_dir/provenza-$(date -u +%Y%m%d-%H%M%S)-docker.dump"
( umask 077; docker exec "$(dc_ids postgres | head -n1)" pg_dump -U "$pg_user" -d "$pg_db" --format=custom --no-owner > "$dump" )
[ -s "$dump" ] || { docker start $app >/dev/null; die "the dump is empty - Docker started again, nothing was changed"; }
ok "dump: $dump ($(du -h "$dump" | cut -f1))"

# ---------------------------------------------------------------- 3. move

all=$(dc_ids)
docker_back() {
  warn "rolling back to Docker"
  systemctl stop provenza.target 2>/dev/null || true
  docker update --restart=unless-stopped $all >/dev/null 2>&1 || true
  docker start $all >/dev/null || true
}

step "Stopping Docker and copying the volumes"
docker stop $all >/dev/null
docker update --restart=no $all >/dev/null   # stays down after a reboot
for v in "${VOLUMES[@]}"; do
  src=$(docker volume inspect "${PROJECT}_$v" --format '{{.Mountpoint}}' 2>/dev/null || true)
  if [ -z "$src" ]; then warn "no Docker volume ${PROJECT}_$v - skipped"; continue; fi
  dst=$(podman volume inspect "provenza_$v" --format '{{.Mountpoint}}')
  cp -a "$src/." "$dst/" || { docker_back; die "copying ${PROJECT}_$v failed - Docker is serving again"; }
  ok "$v ($(du -sh "$dst" | cut -f1))"
done

# ---------------------------------------------------------------- 4. start

step "Starting Provenza under systemd"
systemctl start provenza.target --no-block
if ! wait_ready 600 postgres redis backend worker frontend caddy; then
  docker_back
  die "the Podman stack did not become healthy - Docker is serving again with the unchanged volumes"
fi
ok "all services are up"

# The Docker-era backup line in the invoking user's crontab no longer works
if [ -n "${SUDO_USER:-}" ] && crontab -u "$SUDO_USER" -l 2>/dev/null | grep -Fq "$DEPLOY_DIR && ./scripts/backup.sh"; then
  crontab -u "$SUDO_USER" -l | grep -Fv "$DEPLOY_DIR && ./scripts/backup.sh" | crontab -u "$SUDO_USER" -
  ok "removed the old backup line from $SUDO_USER's crontab"
fi
systemctl enable --now provenza-backup.timer >/dev/null 2>&1 && ok "daily backup: provenza-backup.timer (03:15)"

cat <<EOF

${G}${B}✓ Provenza now runs on Podman${N} (systemctl status provenza.target)

The Docker containers are stopped (restart disabled) and the Docker volumes
are untouched. To go back while nothing new matters:
  systemctl stop provenza.target && systemctl disable provenza.target
  docker update --restart=unless-stopped \$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT)
  docker start \$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT)

Once you are sure (after a reboot test, say a week later):
  docker rm \$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT)
  docker volume rm $(printf "${PROJECT}_%s " "${VOLUMES[@]}")
  systemctl disable --now docker.service docker.socket   # if nothing else uses Docker
EOF
