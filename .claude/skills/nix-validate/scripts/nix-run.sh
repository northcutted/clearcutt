#!/usr/bin/env bash
# Run a nix command against this repo's flake inside a container.
#
# Exists because the flake cannot be evaluated on a machine without Nix, and
# every "it compiles, ship it" on core/ has been a coin flip. Five separate
# pushes to this repo failed in CI on errors nix eval catches in seconds:
# a dangling import, an undeclared function argument, a missing attribute, an
# unquoted dotted attribute path, a renamed runtime line.
#
# Usage:
#   nix-run.sh <nix args...>
#   nix-run.sh eval --raw '.#packages.x86_64-linux.java25-distroless.name'
#
# The /nix store persists in a named volume, so the first run pays for nixpkgs
# and later runs are fast.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
IMAGE="${CLEARCUTT_NIX_IMAGE:-docker.io/nixos/nix:latest}"
VOLUME="${CLEARCUTT_NIX_VOLUME:-clearcutt-nix-store}"
ENGINE="${CLEARCUTT_CONTAINER_ENGINE:-}"

if [[ -z "$ENGINE" ]]; then
  for candidate in podman docker; do
    if command -v "$candidate" >/dev/null 2>&1; then ENGINE="$candidate"; break; fi
  done
fi
if [[ -z "$ENGINE" ]]; then
  echo "nix-run: no container engine found (looked for podman, docker)" >&2
  echo "         install one, or set CLEARCUTT_CONTAINER_ENGINE" >&2
  exit 127
fi
if ! "$ENGINE" info >/dev/null 2>&1; then
  echo "nix-run: '$ENGINE info' failed — the engine is installed but not usable." >&2
  echo "         For podman on macOS: podman machine start" >&2
  "$ENGINE" info 2>&1 | head -3 >&2
  exit 127
fi

if [[ $# -eq 0 ]]; then
  echo "usage: nix-run.sh <nix args...>" >&2
  exit 2
fi

# The repo is mounted read-only: validation must never mutate the working tree,
# and a read-only mount makes that structural rather than a promise. Nix is told
# the repo is a safe git directory because the container user does not own the
# bind-mounted files.
exec "$ENGINE" run --rm \
  -v "$REPO_ROOT:/repo:ro" \
  -v "$VOLUME:/nix" \
  -w /repo/core \
  "$IMAGE" \
  sh -lc 'git config --global --add safe.directory "*" >/dev/null 2>&1 || true
          exec nix --extra-experimental-features "nix-command flakes" --no-warn-dirty "$@"' _ "$@"
