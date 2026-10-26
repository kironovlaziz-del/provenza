#!/usr/bin/env bash
# A public demo organization on this installation, made again every night:
#
#   provenza demo enable [--slug demo] [--email demo@<domain>] [--password provenza-demo]
#   provenza demo reset        make it again now
#   provenza demo status
#   provenza demo disable      stop the nightly reset and delete the demo organization
#
# The demo is its own organization ("Acme Bank (Provenza demo)"): it sees
# nothing of the others, and they see nothing of it. Visitors sign in as its
# viewer - an auditor, which reads everything and changes nothing - with the
# e-mail and password you publish. That login cannot change its own password,
# second factor or passkeys (DEMO_ACCOUNTS in deploy/.env), so one visitor
# cannot lock the others out.
#
# Every night at 04:20 (provenza-demo.timer) the organization is deleted and
# made again by backend/scripts/demo_seed.py: agents that enroll with their
# own keys, a signed delegation chain, allowed, denied and held actions, a
# refused capability escalation, Shadow AI findings. Only an organization the
# script made itself is ever deleted.

set -Eeuo pipefail
trap 'printf "demo.sh: failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib.sh"

SERVICE=provenza-demo.service
TIMER=provenza-demo.timer

usage() { sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0; }

env_set() {  # env_set KEY VALUE: in deploy/.env, replaced or added
  local f="$DEPLOY_DIR/.env"
  if grep -q "^$1=" "$f"; then sed -i "s|^$1=.*|$1=$2|" "$f"; else printf '%s=%s\n' "$1" "$2" >>"$f"; fi
}

seed() {  # seed [demo_seed.py args]
  container_running backend || die "the stack is not running (provenza start)"
  backend_run -v "$ROOT_DIR/sdk/python/src:/sdk:ro,z" -e PYTHONPATH=/sdk \
    -e "PROVENZA_DEMO_EMAIL=$(env_get PROVENZA_DEMO_EMAIL)" \
    -e "PROVENZA_DEMO_PASSWORD=$(env_get PROVENZA_DEMO_PASSWORD)" \
    -- python scripts/demo_seed.py --api http://backend:8000 --slug "$(env_get PROVENZA_DEMO_SLUG)" "$@"
}

write_units() {
  cat >"$SYSTEMD_DIR/$SERVICE" <<EOF
# Provenza: the public demo organization made again (deploy/scripts/demo.sh)
[Unit]
Description=Provenza demo reset
Requires=provenza-backend.service
After=provenza-backend.service

[Service]
Type=oneshot
ExecStart=$DEPLOY_DIR/scripts/demo.sh reset
EOF
  cat >"$SYSTEMD_DIR/$TIMER" <<'EOF'
# Provenza: the demo organization, fresh every night
[Unit]
Description=Nightly Provenza demo reset

[Timer]
OnCalendar=*-*-* 04:20:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  chmod 644 "$SYSTEMD_DIR/$SERVICE" "$SYSTEMD_DIR/$TIMER"
  systemctl daemon-reload
}

cmd_enable() {
  local slug email password domain
  slug=$(env_get PROVENZA_DEMO_SLUG); email=$(env_get PROVENZA_DEMO_EMAIL); password=$(env_get PROVENZA_DEMO_PASSWORD)
  domain=$(env_get PROVENZA_DOMAIN)
  while [ $# -gt 0 ]; do
    case "$1" in
      --slug) slug=${2:?}; shift 2 ;;
      --email) email=${2:?}; shift 2 ;;
      --password) password=${2:?}; shift 2 ;;
      -h|--help) usage ;;
      *) die "unknown option: $1" ;;
    esac
  done
  slug=${slug:-demo}; email=${email:-demo@$domain}; password=${password:-provenza-demo}
  email=$(printf '%s' "$email" | tr '[:upper:]' '[:lower:]')
  [ "${#password}" -ge 12 ] || die "the password must have at least 12 characters"
  # written into deploy/.env with sed: keep them to plain characters
  printf '%s\n%s\n%s\n' "$slug" "$email" "$password" | grep -qvE '^[A-Za-z0-9@._+:!#%^*=?~-]+$' \
    && die "the slug, e-mail and password may use letters, digits and @._+:!#%^*=?~- only"

  step "Demo organization '$slug'"
  env_set PROVENZA_DEMO_SLUG "$slug"
  env_set PROVENZA_DEMO_EMAIL "$email"
  env_set PROVENZA_DEMO_PASSWORD "$password"
  if [ "$(env_get DEMO_ACCOUNTS)" != "$email" ]; then
    env_set DEMO_ACCOUNTS "$email"
    systemctl restart provenza-backend.service
    wait_ready 180 backend || die "the backend did not come back (provenza logs backend)"
  fi
  ok "the viewer $email cannot change its own account (DEMO_ACCOUNTS)"
  seed
  write_units
  systemctl enable --now "$TIMER" >/dev/null 2>&1
  ok "fresh every night at 04:20 ($TIMER)"
  echo
  echo "  Sign in at https://$domain"
  echo "    Organization: $slug"
  echo "    E-mail:       $email"
  echo "    Password:     $password"
}

cmd_status() {
  local slug; slug=$(env_get PROVENZA_DEMO_SLUG)
  [ -n "$slug" ] || { echo "the demo is not enabled (provenza demo enable)"; return 0; }
  echo "organization '$slug', viewer $(env_get PROVENZA_DEMO_EMAIL)"
  systemctl list-timers "$TIMER" --no-pager --no-legend 2>/dev/null | sed 's/^/  next: /' || true
  journalctl -u "$SERVICE" -n 3 --no-pager -o cat 2>/dev/null | sed 's/^/  /' || true
}

cmd_disable() {
  systemctl disable --now "$TIMER" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/$SERVICE" "$SYSTEMD_DIR/$TIMER"
  systemctl daemon-reload
  if [ -n "$(env_get PROVENZA_DEMO_SLUG)" ]; then
    seed --delete
  fi
  env_set DEMO_ACCOUNTS ""
  sed -i '/^PROVENZA_DEMO_\(SLUG\|EMAIL\|PASSWORD\)=/d' "$DEPLOY_DIR/.env"
  systemctl restart provenza-backend.service
  ok "demo disabled and its organization deleted"
}

require_root
[ -f "$DEPLOY_DIR/.env" ] || die "deploy/.env not found"
cmd=${1:-}
[ $# -gt 0 ] && shift
case "$cmd" in
  enable)  cmd_enable "$@" ;;
  reset)   [ -n "$(env_get PROVENZA_DEMO_SLUG)" ] || die "the demo is not enabled: provenza demo enable"; seed ;;
  status)  cmd_status ;;
  disable) cmd_disable ;;
  *) usage ;;
esac
