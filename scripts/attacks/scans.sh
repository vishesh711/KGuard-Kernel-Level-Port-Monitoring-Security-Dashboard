#!/usr/bin/env bash
# Attack demo: scans (see scripts/attack_demo.sh for the tools and the expected alert)
exec "$(dirname "$0")/../attack_demo.sh" scans "$@"
