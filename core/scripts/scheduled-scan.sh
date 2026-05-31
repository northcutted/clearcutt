#!/usr/bin/env bash
# ClearCutt Vulnerability Scan and Remediation Detection Script
# Author: Eddie Northcutt
# Paradigm: CVE scan refresh for catalog or remediation gating (Stage 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$CORE_ROOT"

BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

log_info() { echo -e "${BLUE}[Remediation Scan]${RESET} $1"; }
log_pass() { echo -e "${GREEN}[Remediation Scan] ✔ $1${RESET}"; }
log_warn() { echo -e "${YELLOW}[Remediation Scan] ⚠ $1${RESET}"; }
log_fail() { echo -e "${RED}[Remediation Scan] ✘ $1${RESET}" >&2; exit 1; }

# Source Nix environment if available to keep commands accessible
if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
elif [ -f /Users/eddie/.nix-profile/etc/profile.d/nix.sh ]; then
  source /Users/eddie/.nix-profile/etc/profile.d/nix.sh
fi

SCAN_MODE="${SCAN_MODE:-catalog}"
log_info "Initiating Stage 1 detection scan in ${SCAN_MODE} mode..."

# 1. Update Grype vulnerability database
if command -v grype &>/dev/null; then
  log_info "Updating Grype vulnerability database..."
  grype db update || log_warn "Grype database update failed, proceeding with active local database"
else
  log_fail "Grype CLI is missing. Install Grype to execute scheduled scans."
fi

# 2. Invoke vulnerabilities scanner with Node.js
if [[ -f ./scripts/scan-vulnerabilities.mjs ]]; then
  log_info "Running SBOM vulnerability scans and classifications..."
  node ./scripts/scan-vulnerabilities.mjs --mode "$SCAN_MODE"
else
  log_fail "vulnerability scanning script 'scripts/scan-vulnerabilities.mjs' is missing!"
fi

log_pass "SBOM vulnerability scanning and runtime vs base classification completed successfully."
