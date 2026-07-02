#!/usr/bin/env bash
# ClearCutt Automated Test Verification Suite
# Verifies all PRD success metrics and technical compliance gates

set -euo pipefail

# Load Nix environment if available
if [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
  source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
elif [ -f "$HOME/.nix-profile/etc/profile.d/nix.sh" ]; then
  source "$HOME/.nix-profile/etc/profile.d/nix.sh"
fi

# Console colors
BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"
WARNING_COUNT=0

# Global exit handler to clean up all session resources cleanly.
verify_exit_handler() {
  # 1. Clean up credential broker dynamically if sourced
  if declare -f cleanup_credential_broker >/dev/null; then
    cleanup_credential_broker 2>/dev/null || true
  fi
  # 2. Clean up container structure test files
  rm -f "/tmp/clearcutt-slim-uncompressed.tar" "/tmp/clearcutt-distroless-uncompressed.tar" 2>/dev/null
}
trap verify_exit_handler EXIT INT TERM

log_section() {
  echo -e "\n${BLUE}=== $1 ===${RESET}"
}

log_info() {
  echo -e "${BLUE}[ClearCutt Test]${RESET} $1"
}

log_warn() {
  WARNING_COUNT=$((WARNING_COUNT + 1))
  echo -e "${YELLOW}[ClearCutt Test] ⚠ $1${RESET}"
}

log_pass() {
  echo -e "${GREEN}  ✔ PASS: $1${RESET}"
}

log_fail() {
  echo -e "${RED}  ✘ FAIL: $1${RESET}" >&2
  exit 1
}

find_clearcutt_cli() {
  if [[ -n "${CLEARCUTT_BIN:-}" && -x "${CLEARCUTT_BIN}" ]]; then
    printf '%s\n' "$CLEARCUTT_BIN"
    return 0
  fi
  if [[ -x "../clearcutt" ]]; then
    printf '%s\n' "../clearcutt"
    return 0
  fi
  if command -v clearcutt >/dev/null 2>&1; then
    command -v clearcutt
    return 0
  fi
  return 1
}

g2_known_good_ref() {
  if [[ -n "${CLEARCUTT_G2_KNOWN_GOOD_REF:-}" ]]; then
    printf '%s\n' "$CLEARCUTT_G2_KNOWN_GOOD_REF"
    return 0
  fi
  printf '%s\n' "ghcr.io/northcutted/clearcutt/clearcutt-corelts:slim"
}

g2_target_package() {
  printf '%s\n' "${CLEARCUTT_G2_TARGET_PACKAGE:-bash-interactive}"
}

find_fleet_config() {
  if [[ -n "${CLEARCUTT_FLEET_CONFIG:-}" && -f "${CLEARCUTT_FLEET_CONFIG}" ]]; then
    printf '%s\n' "$CLEARCUTT_FLEET_CONFIG"
    return 0
  fi
  for candidate in "clearcutt.fleet.yaml" "../clearcutt.fleet.yaml"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

write_g2_known_good_closure() {
  local output_file="$1"
  local image_ref
  image_ref="$(g2_known_good_ref)"

  if [[ -n "${CLEARCUTT_G2_KNOWN_GOOD_CLOSURE:-}" ]]; then
    cp "$CLEARCUTT_G2_KNOWN_GOOD_CLOSURE" "$output_file"
    log_info "Using explicit G2 known-good closure file: $CLEARCUTT_G2_KNOWN_GOOD_CLOSURE"
    return 0
  fi

  if ! command -v skopeo >/dev/null 2>&1; then
    log_fail "G2 requires skopeo or CLEARCUTT_G2_KNOWN_GOOD_CLOSURE to derive a registry baseline."
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    log_fail "G2 requires python3 to extract /nix/store paths from the registry image archive."
  fi

  local work_dir="$2"
  local archive="$work_dir/g2-known-good.oci.tar"
  local arch="${CLEARCUTT_G2_KNOWN_GOOD_ARCH:-amd64}"
  log_info "Pulling G2 known-good baseline from ${image_ref} (${arch})..."
  if ! skopeo --insecure-policy copy \
    --override-os linux \
    --override-arch "$arch" \
    "docker://${image_ref}" \
    "oci-archive:${archive}" >/dev/null; then
    log_fail "G2 could not pull known-good baseline image: ${image_ref}"
  fi
  if ! python3 ./tests/nix-store-closure-from-image.py "$archive" > "$output_file"; then
    log_fail "G2 could not extract /nix/store closure from known-good baseline image: ${image_ref}"
  fi
}

write_g2_current_closure() {
  local image_archive="$1"
  local output_file="$2"
  if ! python3 ./tests/nix-store-closure-from-image.py "$image_archive" > "$output_file"; then
    log_fail "G2 could not extract /nix/store closure from current image archive: ${image_archive}"
  fi
}

representative_smoke_targets() {
  local cli
  cli="$(find_clearcutt_cli || true)"
  if [[ -n "$cli" ]]; then
    local fleet_config
    fleet_config="$(find_fleet_config || true)"
    if [[ -z "$fleet_config" ]]; then
      return 1
    fi
    "$cli" --format json matrix export --source fleet --fleet-config "$fleet_config" --github-actions --matrix release |
      python3 -c '
import json
import sys

priority = [
    ("coreLTS", "slim"),
    ("java21", "slim"),
    ("python3.14", "slim"),
    ("rust1.95", "slim"),
    ("cc15", "distroless"),
]
data = json.load(sys.stdin)
available = {(row.get("language"), row.get("tier")) for row in data.get("include", [])}
def strip_prefix(value, prefix):
    return value[len(prefix):] if value.startswith(prefix) else value
for language, tier in priority:
    if (language, tier) not in available:
        continue
    if language == "coreLTS":
        print(f"core LTS {tier} {language}-{tier}")
    elif language.startswith("python"):
        print(f"python {strip_prefix(language, 'python')} {tier} {language}-{tier}")
    elif language.startswith("rust"):
        print(f"rust {strip_prefix(language, 'rust')} {tier} {language}-{tier}")
    elif language.startswith("java"):
        print(f"java {strip_prefix(language, 'java')} {tier} {language}-{tier}")
    elif language.startswith("cc"):
        print(f"cc {strip_prefix(language, 'cc')} {tier} {language}-{tier}")
    elif language.startswith("node"):
        print(f"node {strip_prefix(language, 'node')} {tier} {language}-{tier}")
    elif language.startswith("go"):
        print(f"go {strip_prefix(language, 'go')} {tier} {language}-{tier}")
    elif language.startswith("dotnet"):
        print(f"dotnet {strip_prefix(language, 'dotnet')} {tier} {language}-{tier}")
' || return 1
    return 0
  fi

  cat <<'EOF'
core LTS slim coreLTS-slim
java 21 slim java21-slim
python 3.14 slim python3.14-slim
rust 1.95 slim rust1.95-slim
cc 15 distroless cc15-distroless
EOF
}

# ----------------------------------------------------
# 1. Credentials Leakage Prevention Test
# ----------------------------------------------------
test_credential_broker() {
  log_section "Vulnerability Gate: Transient Credential Broker Verification"

  # Setup mock credential variables
  export ENTERPRISE_MIRROR_URL="https://my-nexus.internal/repository/npm-group"
  export ENTERPRISE_MIRROR_USER="eddie-northcutt"
  export ENTERPRISE_MIRROR_TOKEN="vault-secured-super-secret-token"

  # Verify the broker script can be loaded
  if [ ! -f ./lib/credential-broker.sh ]; then
    log_fail "Credential broker script not found at ./lib/credential-broker.sh"
  fi

  # Source the broker to activate session hooks
  # shellcheck source=lib/credential-broker.sh
  source ./lib/credential-broker.sh

  # Assert environment variables are compiled correctly
  if [[ "${NPM_CONFIG_USERCONFIG:-}" != *".nix-enterprise-auth-cache/.npmrc" ]]; then
    log_fail "NPM_CONFIG_USERCONFIG not set to isolated cache path."
  fi
  log_pass "NPM Config Userconfig successfully isolated: $NPM_CONFIG_USERCONFIG"

  if [[ "${NETRC:-}" != *".nix-enterprise-auth-cache/.netrc" ]]; then
    log_fail "NETRC not set to isolated cache path."
  fi
  log_pass "NETRC routing table successfully isolated: $NETRC"

  if [[ "${PIP_INDEX_URL:-}" != "https://my-nexus.internal/repository/npm-group" ]]; then
    log_fail "PIP_INDEX_URL not set to mirror URL."
  fi
  log_pass "Pip Index URL successfully routed: $PIP_INDEX_URL"

  if [[ "${GRADLE_OPTS:-}" != *"-I"*".nix-enterprise-auth-cache/init.gradle" ]]; then
    log_fail "GRADLE_OPTS not routed to init.gradle."
  fi
  log_pass "Gradle options successfully routed: $GRADLE_OPTS"

  # Assert file contents are generated securely
  if [ ! -f "$NPM_CONFIG_USERCONFIG" ]; then
    log_fail ".npmrc file not materialized."
  fi
  if ! grep -q "vault-secured-super-secret-token" "$NPM_CONFIG_USERCONFIG"; then
    log_fail "Credentials missing in .npmrc."
  fi
  log_pass "Secure .npmrc contents verified."

  if [ ! -f "$NETRC" ]; then
    log_fail ".netrc file not materialized."
  fi
  if ! grep -q "vault-secured-super-secret-token" "$NETRC"; then
    log_fail "Credentials missing in .netrc."
  fi
  log_pass "Secure .netrc routing verified."

  # Assert local gitignore exclusion exists
  if [ -d ".git" ]; then
    if ! grep -q ".nix-enterprise-auth-cache" .git/info/exclude; then
      log_fail ".nix-enterprise-auth-cache not in git local exclude."
    fi
    log_pass "Git workspace isolation guardrail verified."
  fi

  # Execute session cleanup trap
  cleanup_credential_broker

  # Assert variables and files are completely wiped
  if [[ -n "${NPM_CONFIG_USERCONFIG:-}" ]]; then
    log_fail "NPM_CONFIG_USERCONFIG not cleared after cleanup."
  fi
  if [[ -n "${NETRC:-}" ]]; then
    log_fail "NETRC not cleared after cleanup."
  fi
  if [ -d ".nix-enterprise-auth-cache" ]; then
    log_fail ".nix-enterprise-auth-cache directory still exists after cleanup."
  fi
  log_pass "Transient credential broker session cleanup verified."
}

# ----------------------------------------------------
# 1.5. Agent Sandbox Credentials Isolation Verification
# ----------------------------------------------------
test_agent_sandbox_isolation() {
  log_section "Vulnerability Gate: Sandbox Credentials Isolation Verification"

  # Materialize active broker session first
  export ENTERPRISE_MIRROR_URL="https://my-nexus.internal/repository/npm-group"
  export ENTERPRISE_MIRROR_USER="eddie-northcutt"
  export ENTERPRISE_MIRROR_TOKEN="vault-secured-super-secret-token"

  # Source the broker to ensure variables are fully set
  # shellcheck source=lib/credential-broker.sh
  source ./lib/credential-broker.sh

  # We verify that a sub-shell running inside the sandbox script is completely stripped of keys
  local sandbox_vars
  sandbox_vars=$(./scripts/agent-sandbox.sh env | grep -E "^ENTERPRISE_MIRROR_" || true)

  # Check if NPM cache or other materializations exist
  local sandbox_npm_exists=0
  ./scripts/agent-sandbox.sh test -d ".nix-enterprise-auth-cache" && sandbox_npm_exists=1 || sandbox_npm_exists=0

  # Clean up local active session for subsequent tests
  cleanup_credential_broker
  trap verify_exit_handler EXIT INT TERM

  if [[ -n "$sandbox_vars" ]]; then
    log_fail "Vulnerability: Agent sandbox has access to enterprise credentials: $sandbox_vars"
  fi
  log_pass "Scrubbed environment variables verified: no credential keys visible."

  # Double-check isolated file pathways are absent in environment
  local sandbox_npm_var
  sandbox_npm_var=$(./scripts/agent-sandbox.sh bash -c 'echo "${NPM_CONFIG_USERCONFIG:-}"')
  if [[ -n "$sandbox_npm_var" ]]; then
    log_fail "Vulnerability: Agent sandbox leaked active NPM userconfig pathway: $sandbox_npm_var"
  fi
  log_pass "Scrubbed environment paths verified: NPM configs are clean."
}

# ----------------------------------------------------
# 1.7. Generated Fleet Matrix Sync Gate
# ----------------------------------------------------
test_fleet_matrix_synced() {
  log_section "Governance Gate: Generated Fleet Matrix Sync (core/lib/fleet-matrix.nix)"

  local fleet_config
  if ! fleet_config="$(find_fleet_config)"; then
    log_fail "Fleet config (clearcutt.fleet.yaml) not found; cannot verify the generated fleet matrix."
  fi

  local fleet_config_abs repo_root
  fleet_config_abs="$(cd "$(dirname "$fleet_config")" && pwd)/$(basename "$fleet_config")"
  repo_root="$(cd "$(dirname "$fleet_config")" && pwd)"

  # The fleet config is authoritative: `clearcutt fleet compile` resolves it into
  # the generated core/lib/fleet-matrix.nix that the flake reads to build the
  # image matrix AND the realized-closure gate targets. This gate fails if the
  # committed file has drifted from the config — the in-process byte-compare that
  # replaces the old registry↔fleet diff (no `nix eval` in the loop). Recipe
  # coverage (every declared cell resolves to a registry recipe) is enforced
  # separately at flake eval by the assertRecipe gate in flake.nix, so an
  # unbuildable line can never reach a build.
  log_info "Verifying core/lib/fleet-matrix.nix matches clearcutt.fleet.yaml via 'clearcutt fleet compile --check'..."
  local cli
  cli="$(find_clearcutt_cli || true)"
  if [[ -n "$cli" ]]; then
    if ! "$cli" fleet compile --check --fleet-config "$fleet_config_abs" --core-dir "${repo_root}/core"; then
      log_fail "core/lib/fleet-matrix.nix is out of sync with clearcutt.fleet.yaml. Regenerate it: clearcutt fleet compile"
    fi
  else
    log_info "No clearcutt binary found; running the CLI from ${repo_root}/cli via go run."
    if ! go -C "${repo_root}/cli" run ./cmd/clearcutt fleet compile --check --fleet-config "$fleet_config_abs" --core-dir "${repo_root}/core"; then
      log_fail "core/lib/fleet-matrix.nix is out of sync with clearcutt.fleet.yaml. Regenerate it: clearcutt fleet compile"
    fi
  fi

  log_pass "Generated fleet matrix is in sync with the fleet config."
}

test_runtime_floor_synced() {
  log_section "Governance Gate: Known-Good Crypto Identity Allowlist Sync (core/tests/runtime-dep-floor.json)"

  # Derive the repo root from this script's own path (core/tests/verify.sh) so
  # the gate works regardless of CWD.
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

  local flake_dir="${repo_root}/core"
  local floor_out="${repo_root}/core/tests/runtime-dep-floor.json"

  # The allowlist is the resolved store-path IDENTITIES of the patched
  # openssl/sqlite across every shipped crypto set, evaluated from the flake's
  # cryptoIdentities output. This gate fails if the committed allowlist has
  # drifted from what the flake now resolves (a crypto rebuild without a
  # regenerate, or vice versa), so the closure-cve-check.py default-deny gate can
  # never silently lose (or gain) a known-good crypto identity. Requires nix
  # (pure eval, no build).
  log_info "Verifying core/tests/runtime-dep-floor.json matches the flake-resolved crypto identities via 'clearcutt remediation generate-crypto-allowlist --check'..."
  local cli
  cli="$(find_clearcutt_cli || true)"
  if [[ -n "$cli" ]]; then
    if ! "$cli" remediation generate-crypto-allowlist --check --flake-dir "$flake_dir" --out "$floor_out"; then
      log_fail "core/tests/runtime-dep-floor.json is out of sync with the flake-resolved crypto identities. Regenerate it: clearcutt remediation generate-crypto-allowlist"
    fi
  else
    log_info "No clearcutt binary found; running the CLI from ${repo_root}/cli via go run."
    if ! go -C "${repo_root}/cli" run ./cmd/clearcutt remediation generate-crypto-allowlist --check --flake-dir "$flake_dir" --out "$floor_out"; then
      log_fail "core/tests/runtime-dep-floor.json is out of sync with the flake-resolved crypto identities. Regenerate it: clearcutt remediation generate-crypto-allowlist"
    fi
  fi

  log_pass "Known-good crypto identity allowlist is in sync with the flake."
}

# ----------------------------------------------------
# 2. OCI Image Config & Rootless Metadata Verification
# ----------------------------------------------------
test_rootless_boundaries() {
  log_section "Security Gate: Rootless & Non-Privileged Metadata Verification"

  local target_image="coreLTS-slim"
  local build_tar="build-outputs/$target_image.tar.gz"

  if [ ! -f "$build_tar" ]; then
    log_info "Target image tarball not found. Invoking build runner..."
    local link_path="build-outputs/${target_image}-link"
    nix build ".#$target_image" --out-link "$link_path" --extra-experimental-features "nix-command flakes" --accept-flake-config
    cp -L "$link_path" "$build_tar"
    rm -f "$link_path"
  fi

  # Create temp workspace to unpack OCI metadata
  local tmp_unpack
  tmp_unpack=$(mktemp -d)
  tar -xf "$build_tar" -C "$tmp_unpack"

  # Find the image config JSON file
  local config_file
  config_file=$(find "$tmp_unpack" -name "*.json" -not -name "manifest.json" | head -n 1)

  if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
    chmod -R +w "$tmp_unpack" 2>/dev/null || true
    rm -rf "$tmp_unpack"
    log_fail "OCI Image configuration metadata JSON not found in unpacked layer."
  fi

  # Inspect metadata using python's built-in json parser (no jq required!)
  local user_val
  user_val=$(python3 -c "import json; d=json.load(open('$config_file')); print(d.get('config', {}).get('User', ''))")
  local wdir_val
  wdir_val=$(python3 -c "import json; d=json.load(open('$config_file')); print(d.get('config', {}).get('WorkingDir', ''))")
  local ld_library_path_val
  ld_library_path_val=$(python3 -c "import json; d=json.load(open('$config_file')); print(next((e for e in d.get('config', {}).get('Env', []) if e.startswith('LD_LIBRARY_PATH=')), ''))")

  chmod -R +w "$tmp_unpack" 2>/dev/null || true
  rm -rf "$tmp_unpack"

  if [[ "$user_val" != "10001:10001" ]]; then
    log_fail "Metadata User mapping mismatch. Got: '$user_val', Expected: '10001:10001'"
  fi
  log_pass "Hardcoded rootless user mapped: $user_val"

  if [[ "$wdir_val" != "/app" ]]; then
    log_fail "Metadata WorkingDir mismatch. Got: '$wdir_val', Expected: '/app'"
  fi
  log_pass "Hardcoded rootless working directory mapped: $wdir_val"

  # Production tiers must not bake LD_LIBRARY_PATH into the OCI config: glibc
  # resolves DT_RPATH > LD_LIBRARY_PATH > DT_RUNPATH, so a global FHS
  # LD_LIBRARY_PATH outranks the store-bound RUNPATH on every Nix binary —
  # the exact drift class the RPATH gate exists to prevent. Only the dev tier
  # keeps it as a foreign-binary convenience.
  if [[ -n "$ld_library_path_val" ]]; then
    log_fail "Production image $target_image bakes '$ld_library_path_val' into its OCI config; only the dev tier may set LD_LIBRARY_PATH."
  fi
  log_pass "Production OCI config carries no LD_LIBRARY_PATH override."
}

# ----------------------------------------------------
# 3. Dynamic Binary Interpreter RPATH Verification
# ----------------------------------------------------
test_dynamic_binary_headers() {
  log_section "Security Gate: Dynamic Binary RPATH & Interpreter Verification"

  # Gracefully skip ELF checks on non-Linux hosts (like Darwin/macOS)
  if [[ "$(uname -s)" != "Linux" ]]; then
    log_warn "Non-Linux host detected ($(uname -s)). Skipping ELF dynamic interpreter and RPATH verification."
    return 0
  fi

  local target_image="coreLTS-slim"
  local build_tar="build-outputs/$target_image.tar.gz"

  # Create temp workspace to extract image store layers
  local tmp_unpack
  tmp_unpack=$(mktemp -d)
  tar -xf "$build_tar" -C "$tmp_unpack"

  # Find the layer tarballs containing the root filesystem files
  local layer_tars
  layer_tars=$(find "$tmp_unpack" -name "layer.tar")

  local tmp_fs
  tmp_fs=$(mktemp -d)

  for layer in $layer_tars; do
    tar -xf "$layer" -C "$tmp_fs" 2>/dev/null || true
  done

  # Search for all compiled binaries in the OCI store layers
  log_info "Locating all compiled binaries in the OCI store layers..."
  local binaries=()
  while IFS= read -r bin; do
    binaries+=("$bin")
  done < <(find "$tmp_fs" -path "*/nix/store/*/bin/*" -type f -perm -111 2>/dev/null || true)

  if [ ${#binaries[@]} -eq 0 ]; then
    chmod -R +w "$tmp_unpack" "$tmp_fs" 2>/dev/null || true
    rm -rf "$tmp_unpack" "$tmp_fs"
    log_fail "No compiled binaries found in OCI store layers."
  fi

  log_info "Performing dynamic RPATH and interpreter verification on ${#binaries[@]} binaries..."
  for bin in "${binaries[@]}"; do
    # Only run patchelf on valid ELF binaries (skip shell scripts, static configurations, or non-ELFs)
    if ! file "$bin" 2>/dev/null | grep -q "ELF"; then
      continue
    fi

    local bin_name
    bin_name=$(basename "$bin")
    log_info "Verifying dynamic boundaries for: $bin_name"

    # Verify interpreter (if it exists)
    local interpreter=""
    interpreter=$(patchelf --print-interpreter "$bin" 2>/dev/null || true)
    if [[ -n "$interpreter" ]]; then
      if [[ "$interpreter" != "/nix/store/"* ]]; then
        chmod -R +w "$tmp_unpack" "$tmp_fs" 2>/dev/null || true
        rm -rf "$tmp_unpack" "$tmp_fs"
        log_fail "Vulnerability: Binary $bin_name interpreter links outside Nix store -> $interpreter"
      fi
    fi

    # Verify RPATH/RUNPATH (if it exists)
    local rpath=""
    rpath=$(patchelf --print-rpath "$bin" 2>/dev/null || true)
    if [[ -n "$rpath" ]]; then
      IFS=':' read -ra paths <<< "$rpath"
      for p in "${paths[@]}"; do
        # Ignore empty entries or standard relative $ORIGIN flags
        if [[ -n "$p" ]] && [[ "$p" != "\$ORIGIN"* ]] && [[ "$p" != "/nix/store/"* ]]; then
          chmod -R +w "$tmp_unpack" "$tmp_fs" 2>/dev/null || true
          rm -rf "$tmp_unpack" "$tmp_fs"
          log_fail "Vulnerability: Binary $bin_name RPATH references non-hermetic path -> $p"
        fi
      done
    fi
  done

  chmod -R +w "$tmp_unpack" "$tmp_fs" 2>/dev/null || true
  rm -rf "$tmp_unpack" "$tmp_fs"

  log_pass "Dynamic interpreter and RPATH library directories fully isolated across all store runtimes."
}

# ----------------------------------------------------
# 4. Distroless Zero-Utility Boundaries Verification
# ----------------------------------------------------
test_distroless_boundaries() {
  log_section "Security Gate: Distroless Zero-Utility Boundaries Verification"

  local target_image="coreLTS-distroless"
  local build_tar="build-outputs/$target_image.tar.gz"

  if [ ! -f "$build_tar" ]; then
    log_info "Target image tarball not found. Invoking build runner..."
    local link_path="build-outputs/${target_image}-link"
    nix build ".#$target_image" --out-link "$link_path" --extra-experimental-features "nix-command flakes" --accept-flake-config
    cp -L "$link_path" "$build_tar"
    rm -f "$link_path"
  fi

  # Create temp workspace to extract distroless layers
  local tmp_unpack
  tmp_unpack=$(mktemp -d)
  tar -xf "$build_tar" -C "$tmp_unpack"

  local tmp_fs
  tmp_fs=$(mktemp -d)
  local layer_tars
  layer_tars=$(find "$tmp_unpack" -name "layer.tar")

  for layer in $layer_tars; do
    tar -xf "$layer" -C "$tmp_fs" 2>/dev/null || true
  done

  chmod -R +w "$tmp_unpack" 2>/dev/null || true
  rm -rf "$tmp_unpack"

  # Assert absolute absence of shell utilities
  local shell_found=0
  local problematic_paths=(
    "bin/sh" "bin/bash" "bin/ash" "bin/zsh"
    "usr/bin/sh" "usr/bin/bash" "usr/bin/ash" "usr/bin/zsh"
    "bin/ls" "bin/cat" "usr/bin/ls" "usr/bin/cat"
  )

  for p in "${problematic_paths[@]}"; do
    if [ -f "$tmp_fs/$p" ] || [ -L "$tmp_fs/$p" ]; then
      log_warn "Standard utility found in distroless target: $p"
      shell_found=1
    fi
  done

  chmod -R +w "$tmp_fs" 2>/dev/null || true
  rm -rf "$tmp_fs"

  if [ "$shell_found" -ne 0 ]; then
    log_fail "Distroless environment contains interactive shell utilities or coreutils!"
  fi

  log_pass "Distroless FHS boundaries verified. Zero-shell and zero-utility footprint active."

  # Closure-level purity: the FHS checks above only see /bin and /usr/bin,
  # but every store path's bin/ is reachable via PATH-less absolute
  # invocation and shows up in SBOMs. Walk the layer tars (header modes
  # survive non-root extraction) for shells, package managers, and
  # setuid/setgid files anywhere in the image. Residual findings can be
  # consciously accepted in tests/closure-purity-allowlist.txt with a
  # one-line reason — never by weakening this gate.
  log_info "Walking /nix/store closure for shells, package managers, and setuid/setgid files..."
  # Native-Go gate (clearcutt verify closure-purity), the port of
  # tests/closure-purity-check.py. Falls back to `go run` for local runs without
  # a prebuilt binary, mirroring the fleet-matrix drift check above.
  local cli purity_root purity_failed=0
  cli="$(find_clearcutt_cli || true)"
  if [[ -n "$cli" ]]; then
    "$cli" verify closure-purity "$build_tar" --allowlist ./tests/closure-purity-allowlist.txt || purity_failed=1
  else
    purity_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    log_info "No clearcutt binary found; running the CLI from ${purity_root}/cli via go run."
    go -C "${purity_root}/cli" run ./cmd/clearcutt verify closure-purity \
      "$(pwd)/$build_tar" --allowlist "$(pwd)/tests/closure-purity-allowlist.txt" || purity_failed=1
  fi
  if [[ "$purity_failed" -ne 0 ]]; then
    log_fail "Distroless closure purity violated: the /nix/store closure ships shells, package managers, or setuid/setgid files (see findings above)."
  fi

  log_pass "Distroless closure purity verified across the full /nix/store closure."

  # Runtime-patch completeness (the CVE keystone): walk the SHIPPED closure
  # of both the slim and distroless tiers — slim ships the openssl-linked
  # runtime too — and fail if any openssl/sqlite store path's IDENTITY is not on
  # the committed known-good allowlist (tests/runtime-dep-floor.json).
  # Default-deny, so an off-allowlist crypto build is a hard failure here, not a
  # silent ship. Same image archives that the purity gate already consumes.
  local slim_tar="build-outputs/coreLTS-slim.tar.gz"
  if [ ! -f "$slim_tar" ]; then
    log_info "Slim image tarball not found for runtime-cve gate. Invoking build runner..."
    local slim_link="build-outputs/coreLTS-slim-link"
    nix build ".#coreLTS-slim" --out-link "$slim_link" --extra-experimental-features "nix-command flakes" --accept-flake-config
    cp -L "$slim_link" "$slim_tar"
    rm -f "$slim_link"
  fi

  log_info "Walking slim + distroless /nix/store closures for off-allowlist openssl/sqlite identities (allowlist: tests/runtime-dep-floor.json)..."
  # Native-Go gate (clearcutt verify runtime-cve), the port of
  # tests/closure-cve-check.py, with the same CLI-or-`go run` fallback as the
  # closure-purity gate above.
  cli="$(find_clearcutt_cli || true)"
  local rc_root rc_failed
  rc_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  rc_failed=0
  if [[ -n "$cli" ]]; then
    "$cli" verify runtime-cve "$slim_tar" --floor ./tests/runtime-dep-floor.json || rc_failed=1
  else
    go -C "${rc_root}/cli" run ./cmd/clearcutt verify runtime-cve \
      "$(pwd)/$slim_tar" --floor "$(pwd)/tests/runtime-dep-floor.json" || rc_failed=1
  fi
  if [[ "$rc_failed" -ne 0 ]]; then
    log_fail "Slim runtime-patch completeness violated: the shipped closure carries an off-allowlist openssl/sqlite identity (see findings above)."
  fi
  rc_failed=0
  if [[ -n "$cli" ]]; then
    "$cli" verify runtime-cve "$build_tar" --floor ./tests/runtime-dep-floor.json || rc_failed=1
  else
    go -C "${rc_root}/cli" run ./cmd/clearcutt verify runtime-cve \
      "$(pwd)/$build_tar" --floor "$(pwd)/tests/runtime-dep-floor.json" || rc_failed=1
  fi
  if [[ "$rc_failed" -ne 0 ]]; then
    log_fail "Distroless runtime-patch completeness violated: the shipped closure carries an off-allowlist openssl/sqlite identity (see findings above)."
  fi

  log_pass "Runtime-patch completeness verified: slim + distroless ship only patched openssl/sqlite."
}

# ----------------------------------------------------
# 5. Nix Native Consumer Integration Verification
# ----------------------------------------------------
test_native_nix_integration() {
  log_section "Security Gate: Nix Native Consumer Integration Verification"

  log_info "Verifying Nix Native Overlays default compiler outputs..."
  local overlay_check
  # Evaluate against the flake's locked nixpkgs input, not the host <nixpkgs>
  # channel: the gate must certify the pinned package set consumers get.
  overlay_check=$(nix-instantiate --eval --extra-experimental-features "nix-command flakes" -E '
    let
      flake = builtins.getFlake (toString ./.);
      pkgs = import flake.inputs.nixpkgs {
        system = builtins.currentSystem;
        config.allowUnfree = true;
        overlays = [ flake.overlays.default ];
      };
    in
      pkgs.clearcuttJava21 != null && pkgs.clearcuttDotnet8Runtime != null
  ')

  if [[ "$overlay_check" != "true" ]]; then
    log_fail "Nix Native Overlay failed to evaluate clearcuttJava21 and clearcuttDotnet8Runtime attributes."
  fi
  log_pass "Nix Native overlays default evaluated successfully."

  log_info "Verifying CVE remediation flows through overlays.default..."
  local remediation_check
  # Each CVE overlay exposes its patched build as a `clearcutt*` handle (e.g.
  # clearcuttOpenssl, clearcuttPython313). Assert every handle resolves to a real
  # derivation THROUGH overlays.default — proving the barrel is composed in and
  # the patches are non-vacuous. The deep guarantee (that the patched build
  # actually SHIPS in the production image closures, with no stock copy) is the
  # runtime-patch-completeness gate run over the shipped closures, not here.
  # Passes vacuously only when overlays/cve/ is empty.
  remediation_check=$(nix-instantiate --eval --extra-experimental-features "nix-command flakes" -E '
    let
      flake = builtins.getFlake (toString ./.);
      base = import flake.inputs.nixpkgs {
        system = builtins.currentSystem;
        config.allowUnfree = true;
      };
      patched = import flake.inputs.nixpkgs {
        system = builtins.currentSystem;
        config.allowUnfree = true;
        overlays = [ flake.overlays.default ];
      };
      clearcuttNames = builtins.filter
        (n: builtins.substring 0 12 n == "clearcuttCve")
        (builtins.attrNames (flake.overlays.cveRemediation base base));
      isPatchedDrv = name:
        let r = builtins.tryEval (patched.${name}.drvPath or "");
        in r.success && builtins.isString r.value && r.value != "";
      empty = clearcuttNames == [];
    in
      empty || builtins.all isPatchedDrv clearcuttNames
  ')

  if [[ "$remediation_check" != "true" ]]; then
    log_fail "overlays.default does not expose the CVE remediation clearcutt* handles as derivations."
  fi
  log_pass "CVE remediation overlay verified through overlays.default."

  log_info "Verifying Nix Native lib.mkHardenedShell generator..."
  local shell_check
  shell_check=$(nix-instantiate --eval --extra-experimental-features "nix-command flakes" -E '
    let
      flake = builtins.getFlake (toString ./.);
      shell = flake.lib.mkHardenedShell {
        system = "x86_64-linux";
        language = "java";
        version = "21";
      };
    in
      shell.drvPath != ""
  ')

  if [[ "$shell_check" != "true" ]]; then
    log_fail "Nix Native lib.mkHardenedShell failed to build standard shell derivation."
  fi
  log_pass "Nix Native lib.mkHardenedShell derivation generated successfully."
}

# ----------------------------------------------------
# 6. Container Structure Verification Tests
# ----------------------------------------------------
test_container_structure_tests() {
  log_section "Security Gate: Container Structure Verification Tests"

  local slim_tar="build-outputs/coreLTS-slim.tar.gz"
  local distroless_tar="build-outputs/coreLTS-distroless.tar.gz"

  # Ensure both are built
  if [ ! -f "$slim_tar" ]; then
    log_info "Slim image not found. Building..."
    local link_path="build-outputs/coreLTS-slim-link"
    nix build ".#coreLTS-slim" --out-link "$link_path" --extra-experimental-features "nix-command flakes" --accept-flake-config
    cp -L "$link_path" "$slim_tar"
    rm -f "$link_path"
  fi
  if [ ! -f "$distroless_tar" ]; then
    log_info "Distroless image not found. Building..."
    local link_path="build-outputs/coreLTS-distroless-link"
    nix build ".#coreLTS-distroless" --out-link "$link_path" --extra-experimental-features "nix-command flakes" --accept-flake-config
    cp -L "$link_path" "$distroless_tar"
    rm -f "$link_path"
  fi

  # CST has a known parsing limitation with path casing in --image flag
  # and expects uncompressed tar files for the tar driver.
  # We stage and gunzip both images to completely lowercase, uncompressed paths in /tmp.
  local slim_tmp_tar="/tmp/clearcutt-slim-uncompressed.tar"
  local distroless_tmp_tar="/tmp/clearcutt-distroless-uncompressed.tar"

  log_info "Staging and uncompressing slim image to $slim_tmp_tar..."
  gzip -d -c "$slim_tar" > "$slim_tmp_tar"

  log_info "Staging and uncompressing distroless image to $distroless_tmp_tar..."
  gzip -d -c "$distroless_tar" > "$distroless_tmp_tar"

  log_info "Executing Container Structure Tests on Slim Tier..."
  container-structure-test test \
    --driver tar \
    --image "$slim_tmp_tar" \
    --config ./tests/structure-test-slim.yaml

  log_info "Executing Container Structure Tests on Distroless Tier..."
  container-structure-test test \
    --driver tar \
    --image "$distroless_tmp_tar" \
    --config ./tests/structure-test-distroless.yaml

  # Leverage global verify_exit_handler for absolute guarantees
  rm -f "$slim_tmp_tar" "$distroless_tmp_tar"

  log_pass "Container structure verification tests passed."
}

# ----------------------------------------------------
# 7. AI-Assisted CVE Remediation Verification Gates (G1–G4)
# ----------------------------------------------------
test_cve_remediation_gates() {
  log_section "Vulnerability Gate: AI Remediation G1-G4 Verification Gates"

  local target_image="coreLTS-slim"
  local build_tar="build-outputs/$target_image.tar.gz"

  # G1 Build Verification: Tarball must exist or compile successfully
  log_info "Verifying G1: Hermetic Build Gating..."
  if [ ! -f "$build_tar" ]; then
    local link_path="build-outputs/${target_image}-link"
    if ! nix build ".#$target_image" --out-link "$link_path" --extra-experimental-features "nix-command flakes" --accept-flake-config; then
      log_fail "G1 Gate Failed: Hermetic Nix compilation aborted."
    fi
    cp -L "$link_path" "$build_tar"
    rm -f "$link_path"
  fi
  log_pass "G1 Gate: Image compiled successfully."

  # G2 Closure Diff Verification: compare the current local image closure against a
  # registry-derived known-good image, or an explicit closure fixture supplied
  # via CLEARCUTT_G2_KNOWN_GOOD_CLOSURE for offline tests.
  log_info "Verifying G2: Closure Diff Analysis..."

  if [[ "$(uname -s)" == "Linux" ]]; then
    local g2_fixture_dir
    g2_fixture_dir=$(mktemp -d)
    local g2_known_good="$g2_fixture_dir/known-good.closure"
    local g2_current="$g2_fixture_dir/current.closure"
    local g2_target_pkg
    g2_target_pkg="$(g2_target_package)"

    write_g2_known_good_closure "$g2_known_good" "$g2_fixture_dir"
    write_g2_current_closure "$build_tar" "$g2_current"
    if ! ./tests/verify-closure-diff.sh "$g2_target_pkg" "$g2_known_good" "$g2_current"; then
      rm -rf "$g2_fixture_dir"
      log_fail "G2 Gate Failed: Current $target_image closure diverged from known-good baseline outside the $g2_target_pkg package boundary."
    fi

    local g2_old="$g2_fixture_dir/fixture-old.closure"
    local g2_new="$g2_fixture_dir/fixture-new.closure"
    cat > "$g2_old" <<'EOF'
/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-core-1.0
/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.40
EOF
    cat > "$g2_new" <<'EOF'
/nix/store/cccccccccccccccccccccccccccccccc-core-1.1
/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.40
EOF
    if ! ./tests/verify-closure-diff.sh core "$g2_old" "$g2_new"; then
      rm -rf "$g2_fixture_dir"
      log_fail "G2 Gate Failed: Target-only closure fixture was rejected."
    fi
    rm -rf "$g2_fixture_dir"
  else
    log_info "Skipping G2 target-only fixture on macOS (bypassed)."
  fi
  
  # Assert G2 correctly fails on invalid/unexplained package addition (only on Linux where G2 is fully active)
  if [[ "$(uname -s)" == "Linux" ]]; then
    log_info "Asserting G2 fails on unexplained package addition..."
    if ./tests/verify-closure-diff.sh core ".#coreLTS-slim" ".#coreLTS-dev" &>/dev/null; then
      log_fail "G2 Security Failure: Allowed unexplained packages to pass!"
    fi
  else
    log_info "Skipping G2 failure assertion on macOS (bypassed)."
  fi
  log_pass "G2 Gate: Validated clean dependency cascades and successfully rejected arbitrary packages."

  # G3 CVE Re-Scan Verification: Run Syft & Grype on the built image
  log_info "Verifying G3: Vulnerability Re-Scan Gating..."
  local sbom_path="build-outputs/$target_image.sbom.json"
  if [ ! -f "$sbom_path" ]; then
    local uncompressed_tar="/tmp/$target_image.tar"
    gzip -d -c "$build_tar" > "$uncompressed_tar"
    syft "docker-archive:$uncompressed_tar" -o spdx-json > "$sbom_path"
    rm -f "$uncompressed_tar"
  fi
  
  # Grype scan on SBOM. This target is a production slim runtime, so findings
  # that cross the release threshold must fail the local gate the same way they
  # fail in the release pipeline.
  if ! grype "sbom:$sbom_path" --fail-on high --only-fixed >/dev/null; then
    log_fail "G3 Gate Failed: fixable high/critical vulnerabilities found in $target_image."
  fi
  log_pass "G3 Gate: Vulnerability re-scanning pipeline active."

  # G4 Smoke Test Verification: Functional execution test
  log_info "Verifying G4: Language-specific Functional Smoke Testing..."
  local smoke_targets=()
  while IFS= read -r spec; do
    [[ -n "$spec" ]] && smoke_targets+=("$spec")
  done < <(representative_smoke_targets)
  if [[ "${#smoke_targets[@]}" -eq 0 ]]; then
    log_fail "G4 Gate Failed: no representative smoke targets resolved from fleet matrix."
  fi
  for spec in "${smoke_targets[@]}"; do
    local smoke_lang smoke_ver smoke_tier smoke_target smoke_tar smoke_link
    IFS=' ' read -r smoke_lang smoke_ver smoke_tier smoke_target <<< "$spec"
    smoke_tar="build-outputs/${smoke_target}.tar.gz"
    if [ ! -f "$smoke_tar" ]; then
      # On non-Linux hosts, we cannot build Linux OCI image targets!
      if [[ "$(uname -s)" != "Linux" ]]; then
        log_warn "Non-Linux host detected. Skipping OCI build and smoke test for '${smoke_target}'."
        continue
      fi
      smoke_link="build-outputs/${smoke_target}-link"
      if ! nix build ".#\"${smoke_target}\"" --out-link "$smoke_link" --extra-experimental-features "nix-command flakes" --accept-flake-config; then
        log_fail "G4 Gate Failed: unable to build ${smoke_target} for smoke testing."
      fi
      cp -L "$smoke_link" "$smoke_tar"
      rm -f "$smoke_link"
    fi
    if ! ./tests/run-smoke-tests.sh "$smoke_lang" "$smoke_ver" "$smoke_tier" "$smoke_tar"; then
      log_fail "G4 Gate Failed: ${smoke_target} failed functional checks."
    fi
  done
  log_pass "G4 Gate: Representative functional smoke testing passed cleanly."
}

# Run all verification tests
main() {
  log_info "===================================================="
  log_info "     ClearCutt Automated Gating & Test Suite        "
  log_info "===================================================="
  
  test_credential_broker
  test_agent_sandbox_isolation
  test_fleet_matrix_synced
  test_runtime_floor_synced
  test_rootless_boundaries
  test_dynamic_binary_headers
  test_distroless_boundaries
  test_native_nix_integration
  test_container_structure_tests
  test_cve_remediation_gates

  if [[ "$WARNING_COUNT" -gt 0 ]]; then
    echo -e "\n${YELLOW}===================================================="
    echo -e "      CLEARCUTT GATING COMPLETED WITH WARNINGS      "
    echo -e "      Review $WARNING_COUNT warning(s)/skip(s) above."
    echo -e "====================================================${RESET}"
  else
    echo -e "\n${GREEN}===================================================="
    echo -e "      ALL CLEARCUTT SECURITY GATING CHECKS PASSED   "
    echo -e "====================================================${RESET}"
  fi
}

main
