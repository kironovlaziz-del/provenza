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

set -euo pipefail

RULE=(-m conntrack --ctstate DNAT -m comment --comment provenza-published-ports -j ACCEPT)

command -v iptables >/dev/null || exit 0

policy_drop() { iptables -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; }
has_rule() { iptables -C "$1" "${RULE[@]}" 2>/dev/null; }

case "${1:-}" in
  apply)
    if iptables -S DOCKER-USER >/dev/null 2>&1; then
      has_rule DOCKER-USER || iptables -I DOCKER-USER 1 "${RULE[@]}"
      echo "published ports: allowed in DOCKER-USER (Docker is present)"
    elif policy_drop; then
      has_rule FORWARD || iptables -I FORWARD 1 "${RULE[@]}"
      echo "published ports: allowed at the top of FORWARD (its policy is DROP)"
    else
      echo "published ports: nothing blocks them"
    fi
    ;;
  check)
    policy_drop || exit 0
    has_rule DOCKER-USER || has_rule FORWARD
    ;;
  *) echo "usage: $0 apply|check" >&2; exit 2 ;;
esac
