#!/usr/bin/env bash
# Let connections from outside reach the ports Podman publishes (Caddy's 80
# and 443). Run by provenza-forward.service at boot and after every start
# of Docker; `provenza status` runs the check.
#
#   forward.sh apply    allow them if something blocks them
#   forward.sh check    exit 1 if they are blocked
#
# Why: a published port is a DNAT to the container, so a connection from
# outside goes through the FORWARD chain. Docker sets that chain's policy to
# DROP every time it starts, and netavark (Podman) does not accept new
# connections there itself. With Docker installed, the site then works from
# the server but times out from anywhere else. The rule below accepts only
# connections that were DNAT-ed to a published port; it goes in DOCKER-USER
# when Docker is present (Docker never rewrites that chain), else at the top
# of FORWARD when its policy is DROP. Nothing is changed otherwise.
#
# Docker also turns on br_netfilter: then even traffic between two containers
# of one Podman network passes FORWARD, and that DROP cuts the backend off
# from PostgreSQL on the internal data network ("postgres is not reachable").
# A second rule accepts traffic bridged within one Podman bridge - between
# containers of the same network only: it opens no route between networks
# and none out of the internal one.

set -euo pipefail

RULE=(-m conntrack --ctstate DNAT -m comment --comment provenza-published-ports -j ACCEPT)
BRIDGED=(-i podman+ -m physdev --physdev-is-bridged -m comment --comment provenza-same-network -j ACCEPT)

command -v iptables >/dev/null || exit 0

policy_drop() { iptables -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; }
has_rule() { iptables -C "$1" "${RULE[@]}" 2>/dev/null; }
has_bridged() { iptables -C "$1" "${BRIDGED[@]}" 2>/dev/null; }
# bridged traffic goes through iptables only with br_netfilter on (Docker turns it on)
bridge_filtered() { [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" = 1 ]; }

case "${1:-}" in
  apply)
    if iptables -S DOCKER-USER >/dev/null 2>&1; then
      has_rule DOCKER-USER || iptables -I DOCKER-USER 1 "${RULE[@]}"
      has_bridged DOCKER-USER || iptables -I DOCKER-USER 1 "${BRIDGED[@]}"
      echo "published ports and container networks: allowed in DOCKER-USER (Docker is present)"
    elif policy_drop; then
      has_rule FORWARD || iptables -I FORWARD 1 "${RULE[@]}"
      has_bridged FORWARD || iptables -I FORWARD 1 "${BRIDGED[@]}"
      echo "published ports and container networks: allowed at the top of FORWARD (its policy is DROP)"
    else
      echo "published ports: nothing blocks them"
    fi
    ;;
  check)
    policy_drop || exit 0
    has_rule DOCKER-USER || has_rule FORWARD || exit 1
    bridge_filtered || exit 0
    has_bridged DOCKER-USER || has_bridged FORWARD
    ;;
  *) echo "usage: $0 apply|check" >&2; exit 2 ;;
esac
