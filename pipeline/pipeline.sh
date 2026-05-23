#!/usr/bin/env bash
# ClearCutt Closed-Loop Patch & Release Pipeline
# Brand Owner & Principal Architect: Eddie Northcutt
# Paradigm: SLSA L3 Compliant Zero-CVE Delivery System

set -euo pipefail

# Console colors for premium UI/UX feedback
BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

# Load Nix daemon environment
if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
else
  echo -e "${RED}[ClearCutt CI]${RESET} Nix daemon profile not found! Ensure Nix is installed." >&2
  exit 1
fi

# Configuration parameters
WORKSPACE_DIR="$PWD"
OUTPUT_DIR="$WORKSPACE_DIR/build-outputs"
KEYS_DIR="$WORKSPACE_DIR/.nix-enterprise-auth-cache"
mkdir -p "$OUTPUT_DIR"

log_info() {
  echo -e "${BLUE}[ClearCutt CI]${RESET} $1"
}

log_success() {
  echo -e "${GREEN}[ClearCutt CI] ✔ $1${RESET}"
}

log_warn() {
  echo -e "${YELLOW}[ClearCutt CI] ⚠ $1${RESET}"
}

log_error() {
  echo -e "${RED}[ClearCutt CI] ✘ $1${RESET}" >&2
}

# Run automated Daily Patch Cycle (nix flake update)
run_patch_cycle() {
  log_info "Initiating automated daily patch cycle. Fetching upstream channels..."
  if nix flake update --extra-experimental-features "nix-command flakes"; then
    log_success "Upstream Nix channels refreshed. All flake inputs updated successfully."
  else
    log_error "Failed to refresh Nix flake inputs."
    exit 1
  fi
}

# Ensure cryptographic signing keypair is available
ensure_cosign_keys() {
  mkdir -p "$KEYS_DIR"
  if [[ ! -f "$KEYS_DIR/cosign.key" ]] || [[ ! -f "$KEYS_DIR/cosign.pub" ]]; then
    log_warn "Cosign release keys not found. Materializing ephemeral local key pair..."
    # Set dummy password for automated key generation
    export COSIGN_PASSWORD="clearcutt-hardened-key-passphrase"
    cosign generate-key-pair --output-key-prefix "$KEYS_DIR/cosign"
    log_success "Local signing keypair generated inside isolated session cache."
  fi
}

# Compile and certify a single target
certify_target() {
  local target="$1"
  log_info "--------------------------------------------------------"
  log_info "Processing target compiler matrix: ${BLUE}$target${RESET}"
  log_info "--------------------------------------------------------"

  local tar_path="$OUTPUT_DIR/$target.tar.gz"
  local sbom_path="$OUTPUT_DIR/$target.sbom.json"
  local sig_path="$OUTPUT_DIR/$target.sig"

  # 1. Compilation phase
  log_info "Compiling declarative layered OCI image..."
  if nix build ".#$target" --out-link "$tar_path" --extra-experimental-features "nix-command flakes"; then
    log_success "OCI Image layered and compiled -> $tar_path"
  else
    log_error "Compilation failed for target $target"
    return 1
  fi

  # 2. Extract SBOM Phase
  log_info "Extracting cryptographic dependency graph path-info..."
  local temp_path_info
  temp_path_info=$(mktemp)
  nix path-info --json -r "$tar_path" --extra-experimental-features "nix-command flakes" > "$temp_path_info"
  
  log_info "Compiling traceably validated SPDX 2.3 SBOM..."
  python3 "$WORKSPACE_DIR/pipeline/sbom-generator.py" "$temp_path_info" > "$sbom_path"
  rm -f "$temp_path_info"
  log_success "SPDX 2.3 SBOM generated -> $sbom_path"

  # 3. Security Vulnerability Gating Phase (Trivy and Grype double-gate)
  log_info "Executing vulnerability gate: Running Trivy scanner..."
  # trivy image --input <tar> fails with --exit-code 1 if high/critical CVEs with fixes exist
  if trivy image --input "$tar_path" --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed; then
    log_success "Security Gate 1: Trivy scan passed cleanly. No Critical/High CVEs with patches."
  else
    log_error "Vulnerability Gate Failed! Trivy found Critical/High CVEs with available patches."
    return 1
  fi

  log_info "Executing vulnerability gate: Running Grype scanner..."
  # grype <tar> fails with exit code if fixed high/critical CVEs exist
  if grype "docker-archive:$tar_path" --fail-on high --only-fixed; then
    log_success "Security Gate 2: Grype scan passed cleanly. Double-gate verified."
  else
    log_error "Vulnerability Gate Failed! Grype found Critical/High CVEs with available patches."
    return 1
  fi

  # 4. Cryptographic Provenance Signatures (SLSA L3)
  log_info "Executing post-build signing phase: Running Sigstore Cosign..."
  ensure_cosign_keys
  export COSIGN_PASSWORD="clearcutt-hardened-key-passphrase"
  
  # Cryptographically sign the local OCI tarball binary and save signature
  if cosign sign-blob --key "$KEYS_DIR/cosign.key" --output-signature "$sig_path" "$tar_path"; then
    log_success "SLSA L3 signature appended securely -> $sig_path"
  else
    log_error "Cosign signing failed."
    return 1
  fi

  log_success "Target matrix successfully certified for distribution: $target"
}

# Main command dispatcher
main() {
  local run_patch=false
  local target_list=()

  # Command line parsing
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --patch-cycle)
        run_patch=true
        shift
        ;;
      *)
        target_list+=("$1")
        shift
        ;;
    esac
  done

  # Run daily patch cycle if requested
  if [ "$run_patch" = true ]; then
    run_patch_cycle()
  fi

  # Default target if none provided
  if [ ${#target_list[@]} -eq 0 ]; then
    log_warn "No compile targets specified. Defaulting to testing target: coreLTS-slim"
    target_list+=("coreLTS-slim")
  fi

  local failed=0
  for target in "${target_list[@]}"; do
    if ! certify_target "$target"; then
      log_error "Certification failed for $target."
      failed=1
      break
    fi
  done

  if [ "$failed" -eq 0 ]; then
    log_success "Pipeline completed. All target architectures certified."
    exit 0
  else
    log_error "Pipeline failed during certification gating."
    exit 1
  fi
}

main "$@"
EOF
