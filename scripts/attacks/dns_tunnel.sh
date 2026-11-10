#!/usr/bin/env bash
# Attack demo: dns_tunnel (see scripts/attack_demo.sh for the tools and the expected alert)
exec "$(dirname "$0")/../attack_demo.sh" dns_tunnel "$@"
