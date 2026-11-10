#!/usr/bin/env bash
# Attack demo: syn_flood (see scripts/attack_demo.sh for the tools and the expected alert)
exec "$(dirname "$0")/../attack_demo.sh" syn_flood "$@"
