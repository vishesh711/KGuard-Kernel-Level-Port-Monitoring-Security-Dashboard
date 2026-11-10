#!/usr/bin/env bash
# Attack demo: brute_force (see scripts/attack_demo.sh for the tools and the expected alert)
exec "$(dirname "$0")/../attack_demo.sh" brute_force "$@"
