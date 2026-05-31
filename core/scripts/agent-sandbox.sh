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
echo -e "\033[1;35m[Sandbox Isolation]\033[0m Scrubbing all enterprise environment keys and filesystem credentials..." >&2

# Inspect parent environment safely
if [[ -n "${ENTERPRISE_MIRROR_URL:-}" ]] || [[ -n "${ENTERPRISE_MIRROR_USER:-}" ]] || [[ -n "${ENTERPRISE_MIRROR_TOKEN:-}" ]]; then
  echo -e "\033[1;33m[Sandbox Isolation] ⚠ WARNING:\033[0m Transient enterprise credentials detected in parent shell. Scrubbing session..." >&2
fi

# Maintain PATH so standard commands and nix tools are accessible
CLEAN_PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"
if [[ -n "${PATH:-}" ]]; then
  CLEAN_PATH="${PATH}"
fi

# Keep LLM-authored commands away from ~/.config, ~/.netrc, ~/.aws, SSH keys,
# and other ambient host credentials. The real build isolation is still Nix's
# sandbox; this wrapper strips process env and gives tools an empty home.
SANDBOX_HOME="${AGENT_SANDBOX_HOME:-$(mktemp -d "${TMPDIR:-/tmp}/clearcutt-agent-home.XXXXXX")}"

# Execute target command inside a scrubbed process context
exec env -i \
  PATH="$CLEAN_PATH" \
  HOME="$SANDBOX_HOME" \
  XDG_CONFIG_HOME="$SANDBOX_HOME/.config" \
  XDG_CACHE_HOME="$SANDBOX_HOME/.cache" \
  USER="${USER:-agent}" \
  TERM="${TERM:-xterm-256color}" \
  SHELL="/bin/bash" \
  "$@"
