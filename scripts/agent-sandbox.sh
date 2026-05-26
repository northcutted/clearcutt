#!/usr/bin/env bash
# ClearCutt Hardened Fleets Agent Sandbox Wrapper
# Author: Eddie Northcutt
# Paradigm: Ephemeral Sandbox Boundary Credentials Scrubbing

set -euo pipefail

# Load Nix environment if available to keep commands accessible inside the sandbox
if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
elif [ -f /Users/eddie/.nix-profile/etc/profile.d/nix.sh ]; then
  source /Users/eddie/.nix-profile/etc/profile.d/nix.sh
fi

# Status UI feedback
echo -e "\033[1;35m[Sandbox Isolation]\033[0m Scrubbing all enterprise environment keys and credentials..." >&2

# Inspect parent environment safely
if [[ -n "${ENTERPRISE_MIRROR_URL:-}" ]] || [[ -n "${ENTERPRISE_MIRROR_USER:-}" ]] || [[ -n "${ENTERPRISE_MIRROR_TOKEN:-}" ]]; then
  echo -e "\033[1;33m[Sandbox Isolation] ⚠ WARNING:\033[0m Transient enterprise credentials detected in parent shell. Scrubbing session..." >&2
fi

# Maintain PATH so standard commands and nix tools are accessible
CLEAN_PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
if [[ -n "${PATH:-}" ]]; then
  CLEAN_PATH="${PATH}"
fi

# Execute target command inside completely clean system context
exec env -i \
  PATH="$CLEAN_PATH" \
  HOME="$HOME" \
  USER="$USER" \
  TERM="${TERM:-xterm-256color}" \
  SHELL="/bin/bash" \
  "$@"
