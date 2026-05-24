#!/usr/bin/env bash
# ClearCutt Consolidated & Portable Patch, Build, Scan, & Release Pipeline
# Brand Owner & Principal Architect: Eddie Northcutt
# Paradigm: Hermetic supply chain pipeline with Trivy+Grype double-gates, Syft SBOMs, and SLSA v1 Provenance

set -euo pipefail

# Console colors for premium UI/UX feedback
BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

# Load Nix daemon environment if available
if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi

# Global Configuration Parameters
WORKSPACE_DIR="$PWD"
OUTPUT_DIR="$WORKSPACE_DIR/build-outputs"
KEYS_DIR="$WORKSPACE_DIR/.nix-enterprise-auth-cache"
mkdir -p "$OUTPUT_DIR"

log_info() {
  echo -e "${BLUE}[ClearCutt Pipeline]${RESET} $1"
}

log_success() {
  echo -e "${GREEN}[ClearCutt Pipeline] ✔ $1${RESET}"
}

log_warn() {
  echo -e "${YELLOW}[ClearCutt Pipeline] ⚠ $1${RESET}"
}

log_error() {
  echo -e "${RED}[ClearCutt Pipeline] ✘ $1${RESET}" >&2
}

# ----------------------------------------------------
# 1. SCM Status Containment (SCM-Specific calls isolated here)
# ----------------------------------------------------
report_scm_status() {
  local state="$1" # pending, success, failure
  local context="clearcutt-release-pipeline"
  local desc="$2"

  if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    return 0
  fi

  if [[ -n "${GITHUB_TOKEN:-}" ]] && [[ -n "${GITHUB_SHA:-}" ]] && [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    log_info "Reporting SCM status to GitHub: $state ($desc)"
    curl -s -X POST \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      https://api.github.com/repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA} \
      -d "{\"state\":\"${state}\",\"context\":\"${context}\",\"description\":\"${desc}\"}" >/dev/null || true
  fi
}

# ----------------------------------------------------
# 2. Daily Flake Channels Patching
# ----------------------------------------------------
run_patch_cycle() {
  log_info "Initiating automated daily patch cycle. Fetching upstream channels..."
  report_scm_status "pending" "Initiating automated daily flake inputs patch cycle"
  
  if nix flake update --extra-experimental-features "nix-command flakes"; then
    log_success "Upstream Nix channels refreshed. Flake inputs updated successfully."
    report_scm_status "success" "Daily flake inputs updated successfully"
  else
    log_error "Failed to refresh Nix flake inputs."
    report_scm_status "failure" "Daily flake inputs refresh failed"
    exit 1
  fi
}

# ----------------------------------------------------
# 3. Ephemeral Cosign Signing Keys (Local dev/testing fallback)
# ----------------------------------------------------
ensure_cosign_keys() {
  mkdir -p "$KEYS_DIR"
  if [[ ! -f "$KEYS_DIR/cosign.key" ]] || [[ ! -f "$KEYS_DIR/cosign.pub" ]]; then
    log_warn "Cosign release keys not found. Materializing ephemeral local key pair..."
    log_warn "SECURITY NOTE: Local key generation is STRICTLY for local development and local test gates."
    log_warn "In production GHA workflows, keyless OIDC signing is automatically negotiated."
    export COSIGN_PASSWORD="clearcutt-hardened-key-passphrase"
    cosign generate-key-pair --output-key-prefix "$KEYS_DIR/cosign"
    log_success "Ephemeral signing keypair generated inside isolated session cache."
  fi
}

# ----------------------------------------------------
# 4. Target Compiler & Gating Pipeline
# ----------------------------------------------------
certify_target() {
  local target="$1"
  local system="$2"
  local publish="$3"
  local registry="$4"
  local repo="$5"

  log_info "========================================================"
  log_info "Processing matrix target: ${BLUE}$target${RESET} [Platform: ${BLUE}$system${RESET}]"
  log_info "========================================================"

  local tar_path="$OUTPUT_DIR/$target.tar.gz"
  local sbom_path="$OUTPUT_DIR/$target.sbom.json"
  local sig_path="$OUTPUT_DIR/$target.sig"

  local lang
  lang=$(echo "$target" | cut -d'-' -f1)
  local tier
  tier=$(echo "$target" | cut -d'-' -f2)

  # A. Nix Compilation Phase
  log_info "Compiling OCI layered image via Nix..."
  local link_path="$OUTPUT_DIR/$target-link"
  local build_attr=""
  
  # Determine correct Nix flake target path based on platform
  if [[ "$system" == "aarch64-darwin" ]] || [[ "$system" == "x86_64-darwin" ]]; then
    # OCI image matrix is only defined on Linux host systems. Darwin builds fallback
    # to host system platform layers if requested, or compile natively using standard packages.
    build_attr=".#$target"
  else
    build_attr=".#packages.${system}.\"${target}\""
  fi

  if nix build "$build_attr" --out-link "$link_path" --extra-experimental-features "nix-command flakes"; then
    cp -L "$link_path" "$tar_path"
    rm -f "$link_path"
    log_success "OCI image layered and compiled -> $tar_path"
  else
    log_error "Compilation failed for target $target on platform $system"
    rm -f "$link_path" 2>/dev/null || true
    return 1
  fi

  # B. High-Fidelity SPDX SBOM Generation via Syft
  local uncompressed_tar="$OUTPUT_DIR/$target.tar"
  log_info "Decompressing OCI layered image for security scans..."
  if ! gzip -d -c "$tar_path" > "$uncompressed_tar"; then
    log_error "Decompression of OCI layered image failed."
    return 1
  fi

  log_info "Extracting cryptographic dependency graph and generating SPDX SBOM via Syft..."
  if syft "docker-archive:$uncompressed_tar" -o spdx-json > "$sbom_path"; then
    log_success "Traceable SPDX SBOM compiled -> $sbom_path"
  else
    log_error "Syft SBOM generation failed."
    rm -f "$uncompressed_tar" 2>/dev/null || true
    return 1
  fi

  # C. Security Vulnerability Gating (Trivy and Grype double-gate)
  log_info "Executing vulnerability gate: Running Trivy scanner..."
  if trivy image --input "$uncompressed_tar" --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed; then
    log_success "Security Gate 1: Trivy scan passed cleanly. No patched Critical/High CVEs."
  else
    if [[ "$tier" == "dev" ]]; then
      log_warn "Vulnerability Warning: Trivy identified Critical/High CVEs in Dev tier. Continuing (Dev is non-blocking)..."
    else
      log_error "Vulnerability Gate Failed! Trivy identified Critical/High CVEs with available patches."
      rm -f "$uncompressed_tar" 2>/dev/null || true
      return 1
    fi
  fi

  log_info "Executing vulnerability gate: Running Grype scanner..."
  if grype "docker-archive:$uncompressed_tar" --fail-on high --only-fixed; then
    log_success "Security Gate 2: Grype scan passed cleanly. Double-gate verified."
  else
    if [[ "$tier" == "dev" ]]; then
      log_warn "Vulnerability Warning: Grype identified Critical/High CVEs in Dev tier. Continuing (Dev is non-blocking)..."
    else
      log_error "Vulnerability Gate Failed! Grype identified Critical/High CVEs with available patches."
      rm -f "$uncompressed_tar" 2>/dev/null || true
      return 1
    fi
  fi

  rm -f "$uncompressed_tar" 2>/dev/null || true

  # D. Registry Distribution & Cryptographic Signature/Attestation Phase
  if [[ "$publish" == "true" ]]; then
    local image_tag="$registry/$repo/clearcutt-$lang:$tier"

    log_info "Publishing certified OCI archive to registry -> $image_tag"
    
    local skopeo_creds=()
    local actor="${REGISTRY_USER:-${GITHUB_ACTOR:-}}"
    local token="${REGISTRY_TOKEN:-${GITHUB_TOKEN:-}}"
    if [[ -n "$actor" ]] && [[ -n "$token" ]]; then
      skopeo_creds=(--dest-creds "${actor}:${token}")
    fi

    if skopeo copy "${skopeo_creds[@]}" "docker-archive:$tar_path" "docker://$image_tag"; then
      log_success "OCI Image successfully copied to registry."
    else
      log_error "Skopeo registry publishing failed."
      return 1
    fi

    # Cosign cryptographic signing
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      log_info "Signing container image keylessly via GHA OIDC provider..."
      cosign sign --yes "$image_tag"
      
      log_info "Attesting SPDX SBOM predicate to registry manifest..."
      cosign attest --yes --type spdxjson --predicate "$sbom_path" "$image_tag"
    else
      log_info "Signing container image locally using ephemeral key pair..."
      ensure_cosign_keys
      export COSIGN_PASSWORD="clearcutt-hardened-key-passphrase"
      cosign sign --yes --key "$KEYS_DIR/cosign.key" "$image_tag"
      
      log_info "Attesting SPDX SBOM locally to registry manifest..."
      cosign attest --yes --key "$KEYS_DIR/cosign.key" --type spdxjson --predicate "$sbom_path" "$image_tag"
    fi

    # E. SLSA v1 Provenance (GHA only)
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      log_info "Generating secure SLSA v1 Provenance and Digest metadata..."
      local image_digest
      image_digest=$(skopeo inspect --creds "${actor}:${token}" "docker://${image_tag}" --format "{{.Digest}}" | cut -d':' -f2)
      
      local lock_hash
      lock_hash=$(sha256sum "$WORKSPACE_DIR/flake.lock" | cut -d' ' -f1)
      local git_ref
      git_ref=$(git rev-parse HEAD 2>/dev/null || echo "${GITHUB_SHA:-unknown}")

      local provenance_path="$OUTPUT_DIR/$target.provenance.json"
      cat <<EOF > "$provenance_path"
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "docker://${registry}/${repo}/clearcutt-${lang}",
      "digest": {
        "sha256": "${image_digest}"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/eddie-northcutt/clearcutt-images/pipeline@v1",
      "externalParameters": {
        "flakeGitRef": "${git_ref}",
        "flakeLockHash": "${lock_hash}"
      }
    }
  }
}
EOF
      log_success "SLSA v1 Provenance compiled -> $provenance_path"
      
      # Write the digest JSON file for downstream SLSA Level 3 GHA generator
      local digest_json_path="$OUTPUT_DIR/$target.digest.json"
      cat <<EOF > "$digest_json_path"
{
  "image": "${registry}/${repo}/clearcutt-${lang}",
  "digest": "sha256:${image_digest}"
}
EOF
      log_success "Staged target digest metadata JSON -> $digest_json_path"
    fi
  else
    # Local-only fallback signature
    log_info "Signing OCI archive locally..."
    ensure_cosign_keys
    export COSIGN_PASSWORD="clearcutt-hardened-key-passphrase"
    
    # We employ a standardized Sigstore bundle file format for Cosign v3 compatibility
    local bundle_path="$OUTPUT_DIR/$target.sigstore.json"
    if cosign sign-blob --key "$KEYS_DIR/cosign.key" --bundle "$bundle_path" "$tar_path"; then
      log_success "SLSA local signature bundle written -> $bundle_path"
    else
      log_error "Cosign local signing failed."
      return 1
    fi
  fi

  log_success "Target matrix successfully certified for distribution: $target"
}

# ----------------------------------------------------
# 5. CLI Command Dispatcher
# ----------------------------------------------------
main() {
  local run_patch=false
  local publish=false
  # Detect current system platform natively
  local current_system
  if [[ "$(uname -s)" == "Darwin" ]]; then
    if [[ "$(uname -m)" == "arm64" ]]; then
      current_system="aarch64-darwin"
    else
      current_system="x86_64-darwin"
    fi
  else
    if [[ "$(uname -m)" == "aarch64" ]]; then
      current_system="aarch64-linux"
    else
      current_system="x86_64-linux"
    fi
  fi
  local system="$current_system"
  local registry="ghcr.io"
  
  # Auto-detect repository owner/path
  local repo=""
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    repo="${GITHUB_REPOSITORY,,}" # lowercase GHA repo
  else
    repo="eddie-northcutt/clearcutt-images"
  fi

  local target_list=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --patch-cycle)
        run_patch=true
        shift
        ;;
      --system)
        system="$2"
        shift 2
        ;;
      --publish)
        publish=true
        shift
        ;;
      --registry)
        registry="$2"
        shift 2
        ;;
      --repo)
        repo="${2,,}"
        shift 2
        ;;
      *)
        target_list+=("$1")
        shift
        ;;
    esac
  done

  if [[ "$run_patch" == "true" ]]; then
    run_patch_cycle
  fi

  if [ ${#target_list[@]} -eq 0 ]; then
    log_warn "No compile targets specified. Defaulting to: coreLTS-slim"
    target_list+=("coreLTS-slim")
  fi

  local failed=0
  for target in "${target_list[@]}"; do
    report_scm_status "pending" "Running compile and scan certification for $target"
    if certify_target "$target" "$system" "$publish" "$registry" "$repo"; then
      report_scm_status "success" "Certified matrix target $target successfully"
    else
      log_error "Certification failed for target $target"
      report_scm_status "failure" "Certification gating failed for target $target"
      failed=1
      break
    fi
  done

  if [ "$failed" -eq 0 ]; then
    log_success "Pipeline completed successfully."
    exit 0
  else
    log_error "Pipeline aborted due to errors."
    exit 1
  fi
}

main "$@"
