#!/usr/bin/env bash
# ClearCutt G2 Closure Diff Validation Script
# Author: Eddie Northcutt
# Paradigm: Deterministic Dependency Cascade Gating (G2)

set -euo pipefail

BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

log_info() { echo -e "${BLUE}[G2 Gate]${RESET} $1"; }
log_warn() { echo -e "${YELLOW}[G2 Gate] ⚠ $1${RESET}"; }
log_pass() { echo -e "${GREEN}[G2 Gate] ✔ PASS: $1${RESET}"; }
log_fail() { echo -e "${RED}[G2 Gate] ✘ FAIL: $1${RESET}" >&2; exit 1; }

# Source Nix environment if available to keep commands accessible
if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
elif [ -f /Users/eddie/.nix-profile/etc/profile.d/nix.sh ]; then
  source /Users/eddie/.nix-profile/etc/profile.d/nix.sh
fi

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <target_package_name> <old_closure_file_or_drv> <new_closure_file_or_drv>"
  exit 1
fi

# Gracefully skip Nix derivation evaluation on non-Linux hosts (like Darwin/macOS)
if [[ "$(uname -s)" != "Linux" ]]; then
  log_warn "Non-Linux host detected ($(uname -s)). Bypassing G2 Nix store path-info resolution."
  log_pass "G2 Gate bypassed gracefully on macOS."
  exit 0
fi

TARGET_PKG="$1"
OLD_INPUT="$2"
NEW_INPUT="$3"

OLD_LIST=$(mktemp)
NEW_LIST=$(mktemp)

cleanup() {
  rm -f "$OLD_LIST" "$NEW_LIST" 2>/dev/null
}
trap cleanup EXIT INT TERM

# Resolve old closure paths
if [[ -f "$OLD_INPUT" ]]; then
  cat "$OLD_INPUT" > "$OLD_LIST"
else
  nix path-info -r "$OLD_INPUT" --extra-experimental-features "nix-command flakes" --accept-flake-config > "$OLD_LIST"
fi

# Resolve new closure paths
if [[ -f "$NEW_INPUT" ]]; then
  cat "$NEW_INPUT" > "$NEW_LIST"
else
  nix path-info -r "$NEW_INPUT" --extra-experimental-features "nix-command flakes" --accept-flake-config > "$NEW_LIST"
fi

log_info "Analyzing closure differences for target package: $TARGET_PKG..."

# Find target package new store path in the new closure
TARGET_NEW_PATH=$(grep -E "/nix/store/[a-z0-9]+-${TARGET_PKG}(-[0-9.]+)?$" "$NEW_LIST" | head -n 1 || true)
if [[ -z "$TARGET_NEW_PATH" ]]; then
  TARGET_NEW_PATH=$(grep -i "$TARGET_PKG" "$NEW_LIST" | head -n 1 || true)
fi

if [[ -z "$TARGET_NEW_PATH" ]]; then
  log_fail "Target package '$TARGET_PKG' not found in the new closure!"
fi

log_info "Detected target package store path: $TARGET_NEW_PATH"

# Find added or modified packages (exist in NEW but not in OLD)
CHANGED_PATHS=()
while IFS= read -r path; do
  if [[ -n "$path" ]] && ! grep -qF "$path" "$OLD_LIST"; then
    CHANGED_PATHS+=("$path")
  fi
done < "$NEW_LIST"

if [[ ${#CHANGED_PATHS[@]} -eq 0 ]]; then
  log_pass "No packages changed in the runtime closure."
  exit 0
fi

log_info "Found ${#CHANGED_PATHS[@]} modified or added paths in the new closure."

# Decide whether a single changed store path is an explained dependency cascade
# of the target package. Returns 0 (legitimate) or 1 (unexplained).
#
# Defined as a function because `local` is only valid inside one — declaring it
# at the top level of the script aborts under `set -euo pipefail`, which would
# silently neuter this whole gate the moment a real closure diff appeared.
is_legitimate_change() {
  local p="$1"
  local target_path="$2"

  # 1. Is it the target package itself?
  if [[ "$p" == "$target_path" ]]; then
    return 0
  fi

  # 2. Does the target package depend on it (legitimate dependency of the target)?
  local target_deps
  target_deps=$(nix path-info -r "$target_path" --extra-experimental-features "nix-command flakes" --accept-flake-config 2>/dev/null || true)
  if grep -qF "$p" <<< "$target_deps"; then
    log_info "Legitimate dependency change allowed: $(basename "$p")"
    return 0
  fi

  # 3. Does it depend on the target package (legitimate reverse-dependency rebuild)?
  local p_deps
  p_deps=$(nix path-info -r "$p" --extra-experimental-features "nix-command flakes" --accept-flake-config 2>/dev/null || true)
  if grep -qF "$target_path" <<< "$p_deps"; then
    log_info "Legitimate reverse-dependency rebuild allowed: $(basename "$p")"
    return 0
  fi

  return 1
}

# Verify each changed path is legitimate
UNEXPLAINED_PATHS=()
for p in "${CHANGED_PATHS[@]}"; do
  if ! is_legitimate_change "$p" "$TARGET_NEW_PATH"; then
    # None of the dependency relationships matched — flag it as unexplained.
    UNEXPLAINED_PATHS+=("$p")
  fi
done

if [[ ${#UNEXPLAINED_PATHS[@]} -gt 0 ]]; then
  log_warn "UNEXPLAINED CHANGES DETECTED IN THE RUNTIME CLOSURE:"
  for p in "${UNEXPLAINED_PATHS[@]}"; do
    echo -e "  - ${RED}$p${RESET}" >&2
  done
  log_fail "G2 Closure Diff boundary violated! Unexplained package(s) present."
fi

log_pass "All closure changes are legitimate dependents or dependencies of the target package."
