#!/usr/bin/env bash
# Render and manage the Provenza systemd units (rootful Podman Quadlet).
#
#   sudo ./scripts/units.sh install    # render deploy/quadlet/* into /etc/containers/systemd
#                                      # (+ provenza.target, the backup timer), reload systemd
#   sudo ./scripts/units.sh start|stop|restart|status
#   ./scripts/units.sh render DIR      # only write the rendered units into DIR (no root; CI)
#
# Run `install` again after editing deploy/.env (domain, ports, memory limits,
# passwords), then `restart`. The rendered units hold no secrets: passwords
# reach PostgreSQL, Redis and Grafana through deploy/.runtime/*.env (mode 600),
# written from deploy/.env.

set -euo pipefail
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

render() {  # render SRC DST
  local domain http https
  domain=$(env_get PROVENZA_DOMAIN); [ -n "$domain" ] || die "PROVENZA_DOMAIN is not set in deploy/.env"
  http=$(env_get HTTP_PORT); https=$(env_get HTTPS_PORT)
  local pg_user pg_db
  pg_user=$(env_get POSTGRES_USER); pg_db=$(env_get POSTGRES_DB)
  sed -e "s|@DEPLOY@|$DEPLOY_DIR|g" \
      -e "s|@DOMAIN@|$domain|g" \
      -e "s|@HTTP_PORT@|${http:-80}|g" \
      -e "s|@HTTPS_PORT@|${https:-443}|g" \
      -e "s|@PG_USER@|${pg_user:-provenza}|g" \
      -e "s|@PG_DB@|${pg_db:-provenza}|g" \
      -e "s|@POSTGRES_MEMORY@|$(v=$(env_get POSTGRES_MEMORY); echo "${v:-1g}")|g" \
      -e "s|@BACKEND_MEMORY@|$(v=$(env_get BACKEND_MEMORY); echo "${v:-2g}")|g" \
      -e "s|@WORKER_MEMORY@|$(v=$(env_get WORKER_MEMORY); echo "${v:-2g}")|g" \
      -e "s|@FRONTEND_MEMORY@|$(v=$(env_get FRONTEND_MEMORY); echo "${v:-512m}")|g" \
      -e "s|@REDIS_MAXMEMORY@|$(v=$(env_get REDIS_MAXMEMORY); echo "${v:-256mb}")|g" \
      -e "s|@BACKEND_IMAGE@|$(image_ref backend)|g" \
      -e "s|@WEB_IMAGE@|$(image_ref web)|g" \
      "$1" > "$2"
  if grep -q '@[A-Z_]*@' "$2"; then die "unrendered placeholder in $2: $(grep -o '@[A-Z_]*@' "$2" | head -n1)"; fi
}

render_all() {  # render_all DIR
  local f
  mkdir -p "$1"
  for f in "$DEPLOY_DIR"/quadlet/*; do render "$f" "$1/$(basename "$f")"; done
}

# The systemd service each Quadlet file becomes.
service_of() {
  local b; b=$(basename "$1")
  case "$b" in
    *.container) echo "${b%.container}.service" ;;
    *.volume) echo "${b%.volume}-volume.service" ;;
    *.network) echo "${b%.network}-network.service" ;;
  esac
}

write_runtime_env() {
  local pw redis grafana alert
  pw=$(env_get POSTGRES_PASSWORD); redis=$(env_get REDIS_PASSWORD); grafana=$(env_get GRAFANA_PASSWORD)
  alert=$(env_get ALERTMANAGER_SECRET)
  [ -n "$pw" ] && [ -n "$redis" ] || die "POSTGRES_PASSWORD and REDIS_PASSWORD must be set in deploy/.env"
  [ -n "$grafana" ] || die "GRAFANA_PASSWORD must be set in deploy/.env"
  [ -n "$alert" ] || die "ALERTMANAGER_SECRET must be set in deploy/.env (./scripts/init-env.sh generates it)"
  ( umask 077
    mkdir -p "$RUNTIME_DIR"; chmod 700 "$RUNTIME_DIR"
    printf 'POSTGRES_USER=%s\nPOSTGRES_PASSWORD=%s\nPOSTGRES_DB=%s\n' \
      "$(v=$(env_get POSTGRES_USER); echo "${v:-provenza}")" "$pw" \
      "$(v=$(env_get POSTGRES_DB); echo "${v:-provenza}")" > "$RUNTIME_DIR/postgres.env"
    printf 'REDIS_PASSWORD=%s\nREDISCLI_AUTH=%s\n' "$redis" "$redis" > "$RUNTIME_DIR/redis.env"
    printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$grafana" > "$RUNTIME_DIR/grafana.env"
    printf '%s' "$alert" > "$RUNTIME_DIR/alertmanager-secret"
  )
  chmod 600 "$RUNTIME_DIR"/*.env
  # Alertmanager runs as nobody (65534) and reads it as its Bearer token
  chown 65534:65534 "$RUNTIME_DIR/alertmanager-secret"
  chmod 400 "$RUNTIME_DIR/alertmanager-secret"
}

install_units() {
  require_root
  [ -f "$DEPLOY_DIR/.env" ] || die "deploy/.env not found: create it with ./scripts/init-env.sh <domain>"
  local tmp f n stale=()
  tmp=$(mktemp -d)
  render_all "$tmp/quadlet"
  mkdir -p "$tmp/systemd"
  for f in "$DEPLOY_DIR"/systemd/*; do render "$f" "$tmp/systemd/$(basename "$f")"; done

  # Keep a copy of whatever is replaced (hand-made units included)
  mkdir -p "$UNIT_DIR"
  if compgen -G "$UNIT_DIR/provenza-*" >/dev/null; then
    local bak items=("${UNIT_DIR#/}")
    bak=/root/provenza-units-$(date +%Y%m%d-%H%M%S).tar
    for f in "$SYSTEMD_DIR"/provenza*; do [ -e "$f" ] && items+=("${f#/}"); done
    tar -cf "$bak" -C / "${items[@]}"
    ok "previous units saved to $bak"
    for f in "$UNIT_DIR"/provenza-*; do
      [ -e "$tmp/quadlet/$(basename "$f")" ] || stale+=("$f")
    done
  fi
  [ ${#stale[@]} -eq 0 ] || { rm -f "${stale[@]}"; ok "removed units no longer in the repository: ${stale[*]##*/}"; }

  write_runtime_env
  install -m 644 "$tmp"/quadlet/* "$UNIT_DIR/"
  install -m 644 "$tmp"/systemd/* "$SYSTEMD_DIR/"
  rm -rf "$tmp"
  systemctl daemon-reload

  # Quadlet drops an invalid file silently: check every unit was generated
  local missing=()
  for f in "$DEPLOY_DIR"/quadlet/*; do
    n=$(service_of "$f")
    systemctl cat "$n" >/dev/null 2>&1 || missing+=("$n")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    QUADLET_UNIT_DIRS="$UNIT_DIR" "$(quadlet_bin)" -dryrun 2>&1 >/dev/null | grep -v '/usr/share/containers/systemd' | tail -n 20 >&2 || true
    die "Quadlet did not generate: ${missing[*]}"
  fi
  systemctl enable provenza.target >/dev/null 2>&1
  # Docker's FORWARD DROP would cut the site off from outside (forward.sh)
  systemctl enable provenza-forward.service >/dev/null 2>&1
  systemctl restart provenza-forward.service
  ok "$("$DEPLOY_DIR/scripts/forward.sh" apply)"
  ln -sfn "$DEPLOY_DIR/scripts/provenza" /usr/local/bin/provenza
  ok "$(ls "$DEPLOY_DIR"/quadlet | wc -l) Quadlet units in $UNIT_DIR, provenza.target enabled, /usr/local/bin/provenza"
}

cmd=${1:-}
case "$cmd" in
  render) [ -n "${2:-}" ] || die "usage: units.sh render DIR"; render_all "$2"; echo "rendered into $2" ;;
  install) install_units ;;
  start|stop|restart) require_root; systemctl "$cmd" provenza.target ;;
  status)
    systemctl list-units 'provenza-*' --all --no-pager --no-legend | awk '{printf "  %-40s %s %s\n", $1, $3, $4}'
    podman ps -a --filter name='^(postgres|redis|migrate|backend|worker|beat|frontend|caddy|prometheus|grafana|alertmanager)$' \
      --format '  {{.Names}}\t{{.Status}}' 2>/dev/null || true
    ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
