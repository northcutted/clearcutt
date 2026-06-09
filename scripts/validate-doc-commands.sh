#!/usr/bin/env bash
set -euo pipefail

bin="${1:-./clearcutt}"

if [[ ! -x "$bin" ]]; then
  echo "usage: $0 ./clearcutt" >&2
  echo "error: clearcutt binary is not executable at $bin" >&2
  exit 2
fi

docs=(
  README.md
  docs/README.md
  docs/getting-started.md
  docs/cli-reference.md
  docs/demo.md
  docs/catalog-generator.md
  docs/site-generator.md
  docs/platform-kit.md
  docs/fork-validation.md
  docs/trust/evidence-walkthrough.md
  docs/trust/catalog-evidence.md
)

site_docs=(
  site/src/pages/platform-kit.astro
  cli/internal/sitetemplate/template/src/pages/platform-kit.astro
)

fail=0

check_absent() {
  local pattern="$1"
  local message="$2"
  if rg -n --fixed-strings "$pattern" "${docs[@]}" >/tmp/clearcutt-doc-drift.txt; then
    echo "docs command drift: $message" >&2
    cat /tmp/clearcutt-doc-drift.txt >&2
    fail=1
  fi
}

check_absent_site() {
  local pattern="$1"
  local message="$2"
  if rg -n --fixed-strings "$pattern" "${site_docs[@]}" >/tmp/clearcutt-doc-drift.txt; then
    echo "docs command drift: $message" >&2
    cat /tmp/clearcutt-doc-drift.txt >&2
    fail=1
  fi
}

help_contains() {
  local description="$1"
  shift
  local token="${@: -1}"
  local cmd=("${@:1:$#-1}")
  if ! "$bin" "${cmd[@]}" --help | rg -q --fixed-strings -- "$token"; then
    echo "docs command drift: help for 'clearcutt ${cmd[*]}' does not contain '$token' ($description)" >&2
    fail=1
  fi
}

check_absent "clearcutt catalog gather" "use catalog generate or catalog build in docs"
check_absent "catalog site build --include-services" "--include-services belongs to catalog generate, not catalog site build"
check_absent "catalog site preview --site" "catalog site preview has no --site flag"
check_absent "clearcutt policy verify" "policy generates admission policy; it is not a policy verify subcommand"
check_absent "v0.11.1" "documented ClearCutt release pins must point at a published release"
check_absent "platform status --output .. --fleet-config clearcutt.fleet.yaml" "go -C cli run resolves relative paths from cli/; use --output \"$PWD\" or build ./clearcutt first"
check_absent_site "catalog site scaffold --output ./catalog-site" "generated catalog site scaffold examples must pass --catalog ./dist/catalog"
if rg -n "build provenance and SBOM|SBOM.*gh attestation verify|gh attestation verify.*SBOM" "${docs[@]}" >/tmp/clearcutt-doc-drift.txt; then
  echo "docs command drift: GitHub CLI attestation examples must not imply SBOM verification" >&2
  cat /tmp/clearcutt-doc-drift.txt >&2
  fail=1
fi

help_contains "portable catalog generation" catalog generate "--include-services"
help_contains "site build catalog input" catalog site build "--catalog"
help_contains "site build output" catalog site build "--output"
help_contains "site build dependency install" catalog site build "--install"
help_contains "image catalog policy gate" verify image "--require-signature"
help_contains "registry-side evidence verification" verify release-evidence "--workflow-identity"
help_contains "app template generator" app template "--output"
help_contains "devcontainer generator" dev java21-distroless "--devcontainer"
help_contains "fork status output root" platform status "--output"
help_contains "fork status fleet config" platform status "--fleet-config"
help_contains "admission policy engine" policy java21-distroless "--engine"

exit "$fail"
