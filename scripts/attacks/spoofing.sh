#!/usr/bin/env bash
# Attack demo: spoofing (see scripts/attack_demo.sh for the tools and the expected alert)
exec "$(dirname "$0")/../attack_demo.sh" spoofing "$@"
