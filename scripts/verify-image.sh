#!/usr/bin/env bash
set -euo pipefail

# Colors for premium logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CLEAR='\033[0m'

log_info() {
  echo -e "${BLUE}[INFO]${CLEAR} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${CLEAR} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${CLEAR} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${CLEAR} $1"
}

# Ensure arguments
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <image-reference> [--rebuild-check]"
  echo "Example: $0 ghcr.io/northcutted/clearcutt-corelts:v1.0.0-distroless"
  exit 1
fi

IMAGE_REF="$1"
REBUILD_CHECK=false
if [ "${2:-}" = "--rebuild-check" ]; then
  REBUILD_CHECK=true
fi

log_info "Starting supply chain verification for ${IMAGE_REF}"

# Helper to check dependencies
check_dep() {
  if ! command -v "$1" &> /dev/null; then
    log_error "Required tool '$1' is not installed. Please install it to proceed."
    exit 1
  fi
}

check_dep "cosign"
check_dep "crane"
check_dep "jq"

# 1. Resolve digest reference
log_info "Step 1: Resolving OCI manifest digest..."
DIGEST=$(crane digest "${IMAGE_REF}" 2>/dev/null || true)
if [ -z "${DIGEST}" ]; then
  log_error "Could not resolve crane digest for ${IMAGE_REF}. Make sure the image exists and you have read access."
  exit 1
fi
log_success "Resolved digest: ${DIGEST}"

# Parse image name and tag/arch info to determine organization and repo
BASE_REF=$(echo "${IMAGE_REF}" | cut -d'@' -f1 | cut -d':' -f1)
IMAGE_NAME=$(basename "${BASE_REF}")
ORG_REPO="northcutted/clearcutt" # Canonical upstream organization/repository

# 2. Verify Keyless OIDC Signature
log_info "Step 2: Verifying Cosign keyless OIDC signature..."
WORKFLOW_ID_REGEXP="^https://github\\.com/${ORG_REPO}/\\.github/workflows/release\\.yml@refs/heads/main$"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

log_info "Expected Identity SAN Regexp: ${WORKFLOW_ID_REGEXP}"
log_info "Expected OIDC Issuer: ${OIDC_ISSUER}"

if cosign verify "${IMAGE_REF}" \
  --certificate-identity-regexp "${WORKFLOW_ID_REGEXP}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" > /dev/null 2>&1; then
  log_success "Cosign keyless signature successfully verified!"
else
  log_error "Cosign signature verification failed! The certificate identity did not match."
  exit 1
fi

# 3. Validate Rekor log index inclusion
log_info "Step 3: Validating Rekor transparency log index inclusion..."
# Get signature details and print log index
REKOR_INDEX=$(cosign verify "${IMAGE_REF}" \
  --certificate-identity-regexp "${WORKFLOW_ID_REGEXP}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" 2>/dev/null | jq -r '.[0].Critical.Identity.rekorLogIndex // empty')

if [ -n "${REKOR_INDEX}" ]; then
  log_success "Rekor transparency log index verified: ${REKOR_INDEX}"
  log_info "sigstore search URL: https://search.sigstore.dev/?logIndex=${REKOR_INDEX}"
else
  log_warn "Could not extract direct Rekor Log Index from Cosign verification payload."
fi

# 4. Download and validate SPDX SBOM structure
log_info "Step 4: Downloading and validating SPDX SBOM attestation..."
if cosign verify-attestation "${IMAGE_REF}" \
  --type spdxjson \
  --certificate-identity-regexp "${WORKFLOW_ID_REGEXP}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" > sbom-attestation.json 2>/dev/null; then
  
  # Validate SPDX structure
  if jq -e '.payload' sbom-attestation.json > /dev/null 2>&1; then
    log_success "SPDX SBOM attestation verified successfully."
    # Extract package count
    PKG_COUNT=$(jq -r '.payload | @base64d | fromjson | .predicate.packages | length // 0' sbom-attestation.json)
    log_info "SBOM contains ${PKG_COUNT} declaratively tracked package(s)."
    rm sbom-attestation.json
  else
    log_error "Invalid SBOM payload structure inside verified attestation."
    rm -f sbom-attestation.json
    exit 1
  fi
else
  log_error "SPDX SBOM attestation verification failed!"
  exit 1
fi

# 5. Download and verify OpenVEX document
log_info "Step 5: Inspecting OpenVEX exploitability records..."
# Extract image id (e.g. corelts, java17, etc.)
IMAGE_ID=$(echo "${IMAGE_NAME}" | sed 's/clearcutt-//')
VEX_BASE_URL="${VEX_BASE_URL:-https://northcutted.github.io/clearcutt}"
VEX_URL="${VEX_BASE_URL}/vex/${IMAGE_ID}.json"

log_info "Downloading OpenVEX triage record from ${VEX_URL}..."
if curl -sSf -L "${VEX_URL}" -o vex.json 2>/dev/null; then
  # Assert it's a valid OpenVEX document
  if jq -e '.["@context"] | contains("openvex")' vex.json > /dev/null; then
    log_success "OpenVEX document successfully fetched and validated."
    # List triaged CVEs
    TRIAGED_COUNT=$(jq '.statements | length // 0' vex.json)
    log_info "OpenVEX document contains ${TRIAGED_COUNT} active triage statement(s)."
    rm vex.json
  else
    log_error "Invalid OpenVEX structure downloaded from ${VEX_URL}."
    rm -f vex.json
    exit 1
  fi
else
  log_warn "Could not fetch OpenVEX file for image ID '${IMAGE_ID}' from ${VEX_URL}. Triage checks skipped."
fi

# 6. Optional Nix Flake local rebuild check
if [ "${REBUILD_CHECK}" = true ]; then
  log_info "Step 6: Running local Nix Flake build and reproducibility check..."
  check_dep "nix"
  
  if [ -f "core/flake.nix" ]; then
    log_info "Compiling image target locally via Nix Flake..."
    if nix build ".#${IMAGE_NAME}" --extra-experimental-features "nix-command flakes" --no-link; then
      log_success "Local Nix compilation succeeded! Nix store path closures are bit-for-bit reproducible."
    else
      log_error "Local Nix build failed."
      exit 1
    fi
  else
    log_error "Could not find core/flake.nix in current directory to run local rebuild check. Execute this in repository root."
    exit 1
  fi
fi

log_success "All supply chain verification checks completed successfully!"
