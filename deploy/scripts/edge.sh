#!/usr/bin/env bash
# The edge services of this host, set up without manual steps:
#
#   provenza edge setup [--org SLUG] [--no-proxy] [--no-agent] [--sensor] [--sensor-guard]
#   provenza edge refresh      after an upgrade: new binaries, units and hashes; nothing new is created
#   provenza edge status
#
# - the egress proxy (provenza-proxy.service, 127.0.0.1:8443): the way agents
#   reach external APIs with credentials sealed to it; it follows the signed
#   policy on its own ("policy": {"mode": "enforce", "pin": "tofu"}: it
#   trusts the first release the administrators sign, then only what
#   follows from it, whatever the server says);
# - the endpoint agent (provenza-agent.service): reports AI tools, agents and
#   local models on this host (Discovery -> Devices);
# - with --sensor, the egress sensor installed by sensor/install.sh gets its
#   key and starts;
# - with --sensor-guard, the proxy runs through the sensor, which lets it out
#   only while it runs this exact binary with this exact configuration
#   (sensor.json proxy_binaries / proxy_configs, kept up to date by refresh).
#
# The binaries come from the backend image (built from this checkout, no Go
# here). Their keys are made in the database by the backend
# (scripts/edge_keys.py) and written straight into their files (mode 600):
# never shown, never typed. What already exists is kept: a key file, a
# configuration you edited. Run it again at any time.
#
# The proxy binary's and configuration's SHA-256 are added to the next
# signed policy release (Policies -> Signed policy), for sensors that follow
# the signed policy; they take effect when the administrators sign it.

set -euo pipefail
# shellcheck source=deploy/scripts/lib.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/lib.sh"

PROXY_ETC=/etc/provenza-proxy
AGENT_ETC=/etc/provenza-agent
PROXY_STATE=/var/lib/provenza-proxy
PROXY_BIN=/usr/local/bin/provenza-proxy
AGENT_BIN=/usr/local/bin/provenza-agent
SENSOR_BIN=/usr/local/bin/provenza-sensor
SENSOR_ETC=/etc/provenza-sensor
EDGE_CONF=/etc/provenza-edge.conf
PROXY_LISTEN=127.0.0.1:8443
UNIT_SRC="$DEPLOY_DIR/edge"

ORG="" WANT_PROXY=1 WANT_AGENT=1 WANT_SENSOR=0 SENSOR_GUARD=""
CHANGED_PROXY=0 CHANGED_AGENT=0 CHANGED_SENSOR=0

usage() { sed -n '2,/^set -e/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0; }

conf_get() { sed -n "s/^$1=//p" "$EDGE_CONF" 2>/dev/null | tail -n1; }
conf_set() {
  touch "$EDGE_CONF"; chmod 644 "$EDGE_CONF"
  if grep -q "^$1=" "$EDGE_CONF"; then sed -i "s|^$1=.*|$1=$2|" "$EDGE_CONF"; else echo "$1=$2" >>"$EDGE_CONF"; fi
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "no build of the proxy and the agent for $(uname -m) (amd64 and arm64 only)" ;;
  esac
}

sha() { sha256sum "$1" | awk '{print $1}'; }

# ---------------------------------------------------------------- binaries

# From the backend image built from this checkout, checked against its SHA256SUMS.
extract_binaries() {  # sets EDGE_DIST
  local img cid a
  img=$(image_ref backend); a=$(arch)
  podman image exists "$img" || die "the backend image $img is not built yet: install or upgrade first"
  EDGE_DIST=$(mktemp -d)
  cid=$(podman create "$img" true)
  for f in SHA256SUMS "provenza-proxy-linux-$a" "provenza-agent-linux-$a"; do
    if ! podman cp "$cid:/app/sensor-dist/$f" "$EDGE_DIST/$f" 2>/dev/null; then
      podman rm -f "$cid" >/dev/null
      die "$f is not in the backend image: rebuild it (provenza upgrade, or provenza rebuild)"
    fi
  done
  podman rm -f "$cid" >/dev/null
  ( cd "$EDGE_DIST" && grep -E " provenza-(proxy|agent)-linux-$a\$" SHA256SUMS | sha256sum -c --quiet - ) \
    || die "the binaries do not match the image's SHA256SUMS"
}

install_bin() {  # install_bin src dest -> 0 when it changed
  if [ -f "$2" ] && cmp -s "$1" "$2"; then return 1; fi
  install -m 0755 "$1" "$2.new" && mv -f "$2.new" "$2"
  return 0
}

# ---------------------------------------------------------------- keys

# Keys this host still needs, made by the backend and written into $1.
make_keys() {  # make_keys outdir [edge-keys flags...]
  local out=$1; shift
  [ $# -gt 0 ] || return 0
  container_running postgres || die "the stack is not running (provenza start)"
  chown 10001:10001 "$out"; chmod 700 "$out"
  backend_run -v "$out:/out:Z" -- edge-keys --host "$(hostname -s)" --out /out ${ORG:+--org "$ORG"} "$@" \
    | sed 's/^/    /' || die "could not make the keys (provenza logs backend)"
}

# ---------------------------------------------------------------- the proxy

server_url() {
  local d; d=$(env_get PROVENZA_DOMAIN)
  [ -n "$d" ] || die "PROVENZA_DOMAIN is not set in deploy/.env"
  local p; p=$(env_get HTTPS_PORT); p=${p:-443}
  if [ "$p" = 443 ]; then echo "https://$d"; else echo "https://$d:$p"; fi
}

write_proxy_config() {
  [ -f "$PROXY_ETC/proxy.json" ] && return 0
  cat >"$PROXY_ETC/proxy.json" <<EOF
{
  "server_url": "$(server_url)",
  "proxy_key_file": "$PROXY_ETC/proxy.key",
  "listen": "$PROXY_LISTEN",
  "state_dir": "$PROXY_STATE",
  "policy": {"mode": "enforce", "pin": "tofu"}
}
EOF
  chown root:provenza-proxy "$PROXY_ETC/proxy.json"; chmod 640 "$PROXY_ETC/proxy.json"
  CHANGED_PROXY=1
  ok "$PROXY_ETC/proxy.json: follows the signed policy (trusts the first release you sign)"
}

# sensor.json without policy.pin: the sensor lets the proxy out by its own lists.
sensor_guard_possible() {
  [ -x "$SENSOR_BIN" ] && [ -f "$SENSOR_ETC/sensor.json" ] && command -v python3 >/dev/null || return 1
  python3 - "$SENSOR_ETC/sensor.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
sys.exit(1 if (c.get("policy") or {}).get("pin") else 0)
PY
}

# The proxy's user, binary and configuration in sensor.json; 0 when it changed.
sensor_pin_proxy() {
  python3 - "$SENSOR_ETC/sensor.json" "$(sha "$PROXY_BIN")" "$(sha "$PROXY_ETC/proxy.json")" <<'PY'
import json, os, sys
path, binary, config = sys.argv[1:4]
c = json.load(open(path))
before = json.dumps(c, sort_keys=True)
c["proxy_users"] = sorted(set(c.get("proxy_users") or []) | {"provenza-proxy"})
c["proxy_binaries"] = [binary]   # the one installed: an older binary is gone
c["proxy_configs"] = [config]
if json.dumps(c, sort_keys=True) == before:
    sys.exit(1)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(c, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
}

write_proxy_unit() {
  local exec_start="$PROXY_BIN -config $PROXY_ETC/proxy.json" groups="" group unit
  if [ "$(conf_get SENSOR_GUARD)" = 1 ]; then
    if sensor_guard_possible; then
      group=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("run_group") or "provenza")' "$SENSOR_ETC/sensor.json")
      getent group "$group" >/dev/null && usermod -aG "$group" provenza-proxy
      if sensor_pin_proxy; then CHANGED_SENSOR=1; ok "sensor.json: lets out only this proxy binary and configuration"; fi
      exec_start="$SENSOR_BIN --proxy run -- $exec_start"
      groups="SupplementaryGroups=$group"
    else
      warn "sensor guard: no enrolled sensor here, or it follows the signed policy (then sign a release" \
           "naming the proxy's hashes, which setup added to the next one) - the proxy runs on its own"
    fi
  fi
  unit=$(sed -e "s|@EXEC_START@|$exec_start|" -e "s|@SUPPLEMENTARY_GROUPS@|$groups|" "$UNIT_SRC/provenza-proxy.service")
  if [ "$(cat "$SYSTEMD_DIR/provenza-proxy.service" 2>/dev/null)" != "$unit" ]; then
    printf '%s\n' "$unit" >"$SYSTEMD_DIR/provenza-proxy.service"
    CHANGED_PROXY=1
  fi
}

setup_proxy() {
  step "Egress proxy"
  if [ "$(env_get PROVENZA_DOMAIN)" = localhost ]; then
    warn "skipped: the proxy needs Provenza at a real domain with a trusted certificate (not localhost)"
    return 0
  fi
  if ! systemctl cat provenza-proxy.service >/dev/null 2>&1 && command -v ss >/dev/null \
     && ss -ltnH "sport = :${PROXY_LISTEN##*:}" 2>/dev/null | grep -q .; then
    warn "skipped: $PROXY_LISTEN is taken by another program"
    return 0
  fi
  getent passwd provenza-proxy >/dev/null \
    || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin provenza-proxy
  install -d -m 750 -o root -g provenza-proxy "$PROXY_ETC"
  if install_bin "$EDGE_DIST/provenza-proxy-linux-$(arch)" "$PROXY_BIN"; then CHANGED_PROXY=1; ok "$PROXY_BIN updated"; fi
  write_proxy_config
}

# ---------------------------------------------------------------- the agent

write_agent_config() {
  [ -f "$AGENT_ETC/config.json" ] && return 0
  cat >"$AGENT_ETC/config.json" <<EOF
{
  "api_url": "$(server_url)/api/v1/shadow-ai/ingest",
  "ingestion_key_file": "$AGENT_ETC/ingestion.key",
  "scan_interval_sec": 30,
  "batch_interval_sec": 10,
  "batch_size": 50,
  "heartbeat_sec": 900,
  "model_search_paths": [
    "/root/.ollama/models", "/home/*/.ollama/models", "/usr/share/ollama/.ollama/models",
    "/home/*/.cache/huggingface/hub", "/home/*/.cache/lm-studio/models", "/home/*/models"
  ],
  "discovery_enabled": true,
  "discovery_interval_sec": 900
}
EOF
  chmod 600 "$AGENT_ETC/config.json"
  CHANGED_AGENT=1
  ok "$AGENT_ETC/config.json"
}

setup_agent() {
  step "Endpoint agent"
  if [ "$(env_get PROVENZA_DOMAIN)" = localhost ]; then
    warn "skipped: the agent needs Provenza at a real domain with a trusted certificate (not localhost)"
    return 0
  fi
  install -d -m 700 "$AGENT_ETC"
  if install_bin "$EDGE_DIST/provenza-agent-linux-$(arch)" "$AGENT_BIN"; then CHANGED_AGENT=1; ok "$AGENT_BIN updated"; fi
  write_agent_config
  if ! cmp -s "$UNIT_SRC/provenza-agent.service" "$SYSTEMD_DIR/provenza-agent.service"; then
    install -m 644 "$UNIT_SRC/provenza-agent.service" "$SYSTEMD_DIR/provenza-agent.service"
    CHANGED_AGENT=1
  fi
}

# Does the agent's configuration still need a key file?
agent_needs_key() {
  [ -f "$AGENT_ETC/ingestion.key" ] && return 1
  [ -f "$AGENT_ETC/config.json" ] || return 0
  grep -q '"ingestion_key_file"' "$AGENT_ETC/config.json"   # else the key is in the configuration itself
}

# ---------------------------------------------------------------- the sensor

sensor_needs_key() { [ "$WANT_SENSOR" = 1 ] && [ -x "$SENSOR_BIN" ] && [ ! -s "$SENSOR_ETC/key" ]; }

enroll_sensor() {  # enroll_sensor keyfile
  step "Egress sensor"
  provenza-sensor enroll --url "$(server_url)" --key - --no-restart <"$1" 2>&1 | sed 's/^/    /' \
    || { warn "the sensor did not enroll (see above): later, provenza-sensor enroll --url $(server_url)"; return 0; }
  systemctl enable provenzasensor >/dev/null 2>&1 || true
  CHANGED_SENSOR=1
  ok "enrolled"
}

# ---------------------------------------------------------------- start

start_units() {
  systemctl daemon-reload
  if [ "$CHANGED_SENSOR" = 1 ]; then systemctl restart provenzasensor && ok "provenzasensor restarted"; fi
  if [ -f "$SYSTEMD_DIR/provenza-proxy.service" ]; then
    systemctl enable provenza-proxy >/dev/null 2>&1
    if [ "$CHANGED_PROXY" = 1 ] || [ "$CHANGED_SENSOR" = 1 ] || ! systemctl is-active --quiet provenza-proxy; then
      systemctl restart provenza-proxy
    fi
  fi
  if [ -f "$SYSTEMD_DIR/provenza-agent.service" ]; then
    systemctl enable provenza-agent >/dev/null 2>&1
    if [ "$CHANGED_AGENT" = 1 ] || ! systemctl is-active --quiet provenza-agent; then
      systemctl restart provenza-agent
    fi
  fi
  sleep 3
  local u
  for u in provenza-proxy provenza-agent; do
    [ -f "$SYSTEMD_DIR/$u.service" ] || continue
    if systemctl is-active --quiet "$u"; then ok "$u running"
    else warn "$u is not running: journalctl -u $u -n 30"; fi
  done
}

# ---------------------------------------------------------------- commands

cmd_setup() {
  local refresh=${1:-0} flags=() bin_sha cfg_sha
  require_podman
  [ -f "$DEPLOY_DIR/.env" ] || die "deploy/.env not found - install Provenza first (install.sh)"
  [ -n "$SENSOR_GUARD" ] && conf_set SENSOR_GUARD "$SENSOR_GUARD"
  # the organization these services belong to, for later runs (refresh)
  if [ -n "$ORG" ]; then conf_set ORG "$ORG"; else ORG=$(conf_get ORG); fi
  if [ "$refresh" = 1 ]; then
    WANT_PROXY=0 WANT_AGENT=0
    # services set up here (a unit of the same name that reads its configuration
    # elsewhere was made by hand: left alone)
    [ -f "$SYSTEMD_DIR/provenza-proxy.service" ] && [ -f "$PROXY_ETC/proxy.json" ] && WANT_PROXY=1
    [ -f "$SYSTEMD_DIR/provenza-agent.service" ] && [ -f "$AGENT_ETC/config.json" ] && WANT_AGENT=1
    if [ "$WANT_PROXY$WANT_AGENT" = 00 ]; then ok "no edge services on this host (provenza edge setup)"; return 0; fi
  fi
  KEYS_DIR=$(mktemp -d)
  trap 'rm -rf "${EDGE_DIST:-}" "${KEYS_DIR:-}"' EXIT
  extract_binaries

  if [ "$WANT_PROXY" = 1 ]; then setup_proxy; fi
  if [ "$WANT_AGENT" = 1 ]; then setup_agent; fi

  # keys still missing
  if [ "$refresh" = 0 ]; then
    if [ -f "$PROXY_ETC/proxy.json" ] && [ ! -s "$PROXY_ETC/proxy.key" ]; then flags+=(--proxy); fi
    if [ "$WANT_AGENT" = 1 ] && [ -d "$AGENT_ETC" ] && agent_needs_key; then flags+=(--ingestion); fi
    if sensor_needs_key; then flags+=(--sensor); fi
  fi
  # the proxy's binary and configuration for the next signed release, when they changed
  if [ -f "$PROXY_ETC/proxy.json" ] && [ -x "$PROXY_BIN" ]; then
    bin_sha=$(sha "$PROXY_BIN"); cfg_sha=$(sha "$PROXY_ETC/proxy.json")
    # an edited configuration takes effect with a restart
    [ -n "$(conf_get RELEASE_CONFIG)" ] && [ "$cfg_sha" != "$(conf_get RELEASE_CONFIG)" ] && CHANGED_PROXY=1
    if [ "$bin_sha" != "$(conf_get RELEASE_BINARY)" ] || [ "$cfg_sha" != "$(conf_get RELEASE_CONFIG)" ]; then
      flags+=(--proxy-binary "$bin_sha" --proxy-config "$cfg_sha")
      [ -n "$(conf_get RELEASE_BINARY)" ] && [ "$bin_sha" != "$(conf_get RELEASE_BINARY)" ] \
        && flags+=(--drop-proxy-binary "$(conf_get RELEASE_BINARY)")
      [ -n "$(conf_get RELEASE_CONFIG)" ] && [ "$cfg_sha" != "$(conf_get RELEASE_CONFIG)" ] \
        && flags+=(--drop-proxy-config "$(conf_get RELEASE_CONFIG)")
    fi
  fi
  if [ ${#flags[@]} -gt 0 ]; then
    step "Keys"
    make_keys "$KEYS_DIR" "${flags[@]}"
    if [ -n "${bin_sha:-}" ]; then conf_set RELEASE_BINARY "$bin_sha"; conf_set RELEASE_CONFIG "$cfg_sha"; fi
  fi
  if [ -s "$KEYS_DIR/proxy.key" ]; then
    install -m 640 -o root -g provenza-proxy "$KEYS_DIR/proxy.key" "$PROXY_ETC/proxy.key"; CHANGED_PROXY=1
    ok "$PROXY_ETC/proxy.key"
  fi
  if [ -s "$KEYS_DIR/ingestion.key" ]; then
    install -m 600 "$KEYS_DIR/ingestion.key" "$AGENT_ETC/ingestion.key"; CHANGED_AGENT=1
    ok "$AGENT_ETC/ingestion.key"
  fi
  if [ -s "$KEYS_DIR/sensor.key" ]; then enroll_sensor "$KEYS_DIR/sensor.key"; fi
  rm -rf "$KEYS_DIR"
  # the unit, and the sensor's lists of this proxy (a new binary or configuration)
  if [ "$WANT_PROXY" = 1 ] && [ -f "$PROXY_ETC/proxy.json" ]; then write_proxy_unit; fi

  step "Starting"
  start_units
  if [ "$refresh" = 0 ] && [ -f "$PROXY_ETC/proxy.json" ] && [ ! -f "$PROXY_STATE/release.json" ]; then
    printf '\n  %sOne step is yours:%s sign the policy in Provenza (Policies -> Signed policy ->\n' "$B" "$N"
    printf '  Prepare the first release -> Sign with passkey). Until then the proxy refuses every\n'
    printf '  request; afterwards it trusts that release and what follows from it only.\n'
  fi
  return 0
}

cmd_status() {
  local u
  printf '%sEdge services%s\n' "$B" "$N"
  for u in provenza-proxy provenza-agent provenzasensor; do
    if systemctl cat "$u.service" >/dev/null 2>&1; then
      printf '  %-16s %s\n' "$u" "$(systemctl show -p ActiveState,SubState --value "$u" | paste -sd/ -)"
    else
      printf '  %-16s not installed\n' "$u"
    fi
  done
  if [ -f "$PROXY_STATE/release.json" ] && command -v python3 >/dev/null; then
    python3 - "$PROXY_STATE/release.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
r = d["doc"]["release"]
print(f"  proxy follows the signed policy: release #{r['number']}, pin {d['pin'][:16]}")
PY
  elif [ -f "$PROXY_ETC/proxy.json" ]; then
    printf '  proxy: no signed release verified yet (Policies -> Signed policy)\n'
  fi
  if [ "$(conf_get SENSOR_GUARD)" = 1 ]; then printf '  proxy runs through the sensor (sensor guard on)\n'; fi
  if [ -x "$PROXY_BIN" ]; then printf '  %s  %s\n' "$(sha "$PROXY_BIN" | cut -c1-16)" "$PROXY_BIN"; fi
  if [ -x "$AGENT_BIN" ]; then printf '  %s  %s\n' "$(sha "$AGENT_BIN" | cut -c1-16)" "$AGENT_BIN"; fi
  return 0
}

require_root
cmd=${1:-}; [ $# -gt 0 ] && shift
while [ $# -gt 0 ]; do
  case "$1" in
    --org) ORG=${2:?}; shift 2 ;;
    --no-proxy) WANT_PROXY=0; shift ;;
    --no-agent) WANT_AGENT=0; shift ;;
    --sensor) WANT_SENSOR=1; shift ;;
    --sensor-guard) SENSOR_GUARD=1; shift ;;
    --no-sensor-guard) SENSOR_GUARD=0; shift ;;
    --yes|-y) shift ;;   # nothing to ask: accepted for install.sh
    -h|--help) usage ;;
    *) die "unknown option: $1 (provenza edge --help)" ;;
  esac
done
case "$cmd" in
  setup)   cmd_setup 0 ;;
  refresh) cmd_setup 1 ;;
  status)  cmd_status ;;
  ""|-h|--help|help) usage ;;
  *) die "unknown command: $cmd (setup, refresh, status)" ;;
esac
