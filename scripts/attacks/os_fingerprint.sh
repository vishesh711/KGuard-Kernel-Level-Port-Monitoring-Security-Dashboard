#!/usr/bin/env bash
# Attack demo: os_fingerprint (see scripts/attack_demo.sh for the tools and the expected alert)
exec "$(dirname "$0")/../attack_demo.sh" os_fingerprint "$@"
