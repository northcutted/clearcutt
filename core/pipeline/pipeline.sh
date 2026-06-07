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

platform_image_prefix() {
  if [[ -n "${CLEARCUTT_IMAGE_PREFIX:-}" ]]; then
    printf '%s\n' "$CLEARCUTT_IMAGE_PREFIX"
    return 0
  fi

  local metadata="$WORKSPACE_DIR/lib/platform-metadata.nix"
  if [[ -f "$metadata" ]]; then
    local parsed
    parsed="$(sed -n 's/^[[:space:]]*imagePrefix[[:space:]]*=[[:space:]]*"\([^"]\+\)";.*/\1/p' "$metadata" | head -n 1)"
    if [[ -n "$parsed" ]]; then
      printf '%s\n' "$parsed"
      return 0
    fi
  fi

  printf '%s\n' "clearcutt"
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
  
  if nix flake update --extra-experimental-features "nix-command flakes" --accept-flake-config; then
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
  # Hard guard: never run this branch under CI. Production releases must
  # use Sigstore keyless OIDC signing — local-dev keys here would shadow it.
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    log_error "ensure_cosign_keys() called inside GitHub Actions. Refusing to generate local keys."
    log_error "This is a bug — the --publish path uses cosign keyless OIDC, not local keys."
    exit 1
  fi

  mkdir -p "$KEYS_DIR"
  if [[ ! -f "$KEYS_DIR/cosign.key" ]] || [[ ! -f "$KEYS_DIR/cosign.pub" ]]; then
    log_warn "Cosign release keys not found. Materializing ephemeral local key pair..."
    log_warn "SECURITY NOTE: Local key generation is STRICTLY for local development."
    log_warn "Keys land in $KEYS_DIR, which is .gitignored — do not move them."
    # Random per-session passphrase rather than a hardcoded one. The user
    # never needs to type this; the key is only used by ./pipeline.sh and
    # the password is re-exported in this same shell invocation below.
    COSIGN_PASSWORD="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)"
    export COSIGN_PASSWORD
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
  local local_signing="$6"
  local target_kind="${7:-runtime}"

  log_info "========================================================"
  log_info "Processing ${target_kind} target: ${BLUE}$target${RESET} [Platform: ${BLUE}$system${RESET}]"
  log_info "========================================================"

  local tar_path="$OUTPUT_DIR/$target.tar.gz"
  local sbom_path="$OUTPUT_DIR/$target.sbom.json"
  local sig_path="$OUTPUT_DIR/$target.sig"

  local lang
  lang=$(echo "$target" | cut -d'-' -f1 | tr '[:upper:]' '[:lower:]')
  local tier
  tier=$(echo "$target" | cut -d'-' -f2)
  if [[ "$target_kind" == "service" ]]; then
    lang="$target"
    tier="service"
  fi

  # A. Nix Compilation Phase
  log_info "Compiling OCI layered image via Nix..."
  local link_path="$OUTPUT_DIR/$target-link"
  local build_attr=""

  # The OCI image matrix (packages.<system>."<lang><ver>-<tier>") is only
  # evaluated on Linux hosts — see the `hostPkgs.stdenv.isLinux` guard in
  # flake.nix. On macOS those attributes simply don't exist, so fail fast with
  # an actionable message instead of letting Nix emit an opaque
  # "attribute 'java21-distroless' missing" error several seconds later.
  if [[ "$system" == *"-darwin" ]]; then
    log_error "OCI image target '$target' is only buildable on a Linux host."
    log_error "On macOS, use 'nix build .#<lang><ver>-native' for raw runtime closures,"
    log_error "or run this pipeline on a Linux runner/VM to produce the image matrix."
    return 1
  fi
  build_attr=".#packages.${system}.\"${target}\""

  if nix build "$build_attr" --out-link "$link_path" --extra-experimental-features "nix-command flakes" --accept-flake-config; then
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

  # C. Security Vulnerability Gating via Syft + Grype
  log_info "Executing vulnerability gate: Running Grype scanner directly against compiled SPDX SBOM..."
  local grype_assertion_status="passed"
  if grype "sbom:$sbom_path" --fail-on high --only-fixed; then
    log_success "Security Gate: Grype SBOM scan passed with no fixable Critical/High CVEs."
  else
    if [[ "$target_kind" == "runtime" && "$tier" == "dev" ]]; then
      grype_assertion_status="warning"
      log_warn "Vulnerability Warning: Grype identified Critical/High CVEs in Dev tier. Continuing (Dev is non-blocking)..."
    elif [[ "$target_kind" == "service" ]] && { [[ "${CLEARCUTT_SERVICE_PRODUCTION_ALLOWED:-false}" != "true" ]] || [[ "${CLEARCUTT_SERVICE_LIFECYCLE_STATUS:-preview}" != "active" ]]; }; then
      grype_assertion_status="warning"
      log_warn "Vulnerability Warning: Grype identified Critical/High CVEs in preview/non-production service target. Continuing, but recording the gate as a warning..."
    else
      log_error "Vulnerability Gate Failed! Grype identified Critical/High CVEs with available patches."
      rm -f "$uncompressed_tar" 2>/dev/null || true
      return 1
    fi
  fi

  rm -f "$uncompressed_tar" 2>/dev/null || true

  # C2. Generate structured test results predicate
  local test_results_path="$OUTPUT_DIR/$target.test-results.json"
  log_info "Generating structured security gating and test results predicate..."
  cat <<EOF > "$test_results_path"
{
  "system": "$system",
  "target": "$target",
  "kind": "$target_kind",
  "language": "$lang",
  "tier": "$tier",
  "status": "passed",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "assertions": [
    {
      "name": "Nix Compilation",
      "status": "passed"
    },
    {
      "name": "Syft SBOM Generation",
      "status": "passed"
    },
    {
      "name": "Grype Vulnerability Gating",
      "status": "$grype_assertion_status"
    }
  ]
}
EOF
  log_success "Test results predicate generated -> $test_results_path"

  # D. Registry Distribution & Cryptographic Signature/Attestation Phase
  if [[ "$publish" == "true" ]]; then
    local arch_suffix=""
    if [[ "$system" == *"aarch64"* ]] || [[ "$system" == *"arm64"* ]]; then
      arch_suffix="arm64"
    else
      arch_suffix="amd64"
    fi

    # Push the single-arch image straight into the final per-language repo under
    # a rolling "_stage-<tier>-<arch>" tag. The assemble-multiarch job stitches
    # the amd64/arm64 staging tags into the real multi-arch indexes
    # (:<tier> and :v<version>-<tier>) and signs/attests THOSE in place.
    #
    # This replaces the old clearcutt-bootstrap staging *package* + cosign-copy
    # promotion: there is no second package to manage. A separate package could
    # never keep the published repo "clean" anyway — `cosign verify <image>`
    # needs the signature stored against the image digest in THIS repo.
    #
    # We push as OCI media types (--format oci). dockerTools.buildLayeredImage
    # emits Docker schema-2 manifests, but cosign v3's default new bundle format
    # requires the signed subject to be an OCI image / OCI image index. Pushing
    # the per-arch images as OCI (and assembling an OCI image index from them in
    # the assemble-multiarch job via `crane index append`) lets cosign sign +
    # attest with the new bundle format, which consolidates the signature and
    # all attestations into a single sha256-<digest> referrers-index tag per
    # digest instead of the legacy separate .sig/.att/.sbom tags. (GHCR still has
    # no OCI 1.1 Referrers API, so it lands as that one fallback tag, not a true
    # referrer — but it's one tag instead of several.)
    #
    # The _stage-* tags are rolling (overwritten every serialized release), so
    # exactly 2 per tier exist at any time rather than accumulating per version.
    local image_prefix
    image_prefix="$(platform_image_prefix)"
    local image_repo="$registry/$repo/${image_prefix}-${lang}"
    local stage_tag="${image_repo}:_stage-${tier}-${arch_suffix}"
    if [[ "$target_kind" == "service" ]]; then
      image_repo="$registry/$repo/${image_prefix}-${target}"
      stage_tag="${image_repo}:_stage-service-${arch_suffix}"
    fi

    log_info "Publishing per-arch staging image to registry (OCI) -> $stage_tag"

    local skopeo_creds=()
    local actor="${REGISTRY_USER:-${GITHUB_ACTOR:-}}"
    local token="${REGISTRY_TOKEN:-${GITHUB_TOKEN:-}}"
    if [[ -n "$actor" ]] && [[ -n "$token" ]]; then
      skopeo_creds=(--dest-creds "${actor}:${token}")
    fi

    if skopeo copy --format oci --retry-times 5 "${skopeo_creds[@]}" "docker-archive:$tar_path" "docker://$stage_tag"; then
      log_success "Per-arch staging image successfully pushed to registry (OCI media types)."
    else
      log_error "Skopeo per-arch staging push failed."
      return 1
    fi
  else
    # Local-only fallback signature
    if [[ "$local_signing" == "true" ]]; then
      log_info "Signing OCI archive locally..."
      ensure_cosign_keys
      # COSIGN_PASSWORD is already exported by ensure_cosign_keys with a fresh
      # random value — don't overwrite it here.

      # We employ a standardized Sigstore bundle file format for Cosign v3 compatibility.
      # To work around a Cosign v3 bug where omitting --output-signature when --bundle is passed
      # causes it to open an empty filename ("open : no such file or directory"), we provide both.
      local bundle_path="$OUTPUT_DIR/$target.sigstore.json"
      if cosign sign-blob --key "$KEYS_DIR/cosign.key" --bundle "$bundle_path" --output-signature "$sig_path" "$tar_path"; then
        log_success "SLSA local signature bundle written -> $bundle_path"
      else
        log_error "Cosign local signing failed."
        return 1
      fi
    else
      log_info "Skipping local archive signing for non-publish certification."
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
  local local_signing=true
  local target_kind="runtime"
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
    repo="northcutted/clearcutt"
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
      --kind)
        target_kind="$2"
        shift 2
        ;;
      --skip-local-signing)
        local_signing=false
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
      --version-tag)
        export VERSION_TAG="$2"
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

  case "$target_kind" in
    runtime|service)
      ;;
    *)
      log_error "Unsupported target kind '$target_kind'. Expected runtime or service."
      exit 1
      ;;
  esac

  if [ ${#target_list[@]} -eq 0 ]; then
    log_warn "No compile targets specified. Defaulting to: coreLTS-slim"
    target_list+=("coreLTS-slim")
  fi

  local failed=0
  for target in "${target_list[@]}"; do
    report_scm_status "pending" "Running compile and scan certification for $target"
    if certify_target "$target" "$system" "$publish" "$registry" "$repo" "$local_signing" "$target_kind"; then
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
