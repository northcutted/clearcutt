#!/usr/bin/env bash
set -euo pipefail

fail=0

flag() {
  echo "workflow hardening drift: $*" >&2
  fail=1
}

search_regex() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg --hidden --no-ignore -n -e "$pattern" "$@"
  else
    grep -R -n -E -e "$pattern" "$@"
  fi
}

regex_exists() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -q -e "$pattern" "$@"
  else
    grep -q -E -e "$pattern" "$@"
  fi
}

fixed_exists() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    rg -q --fixed-strings -- "$pattern" "$@"
  else
    grep -q -F -e "$pattern" "$@"
  fi
}

if search_regex 'uses:[[:space:]]+[^#[:space:]]+@(v[0-9]+|main|master)([[:space:]]|$)' .github/workflows .github/actions examples cli/internal/commands/app_template.go; then
  flag "workflow and composite action references must be pinned to immutable SHAs"
fi

if search_regex 'slsaBuilder: .*@v[0-9]|SLSABuilder:[[:space:]]+".*@v[0-9]|generator_container_slsa3\.yml@v[0-9]' clearcutt.fleet.yaml cli/internal/fleet/config.go .github/workflows examples; then
  flag "release.slsaBuilder and generated SLSA builder refs must be pinned to the reviewed reusable workflow SHA"
fi

if ! regex_exists 'slsaBuilder: .+@[0-9a-f]{40}' clearcutt.fleet.yaml; then
  flag "release.slsaBuilder is missing a 40-character commit SHA"
fi

deploy_site_block="$(
  awk '
    /^  deploy-site:/ {capture=1}
    capture && /^  [[:alnum:]_-]+:/ && !/^  deploy-site:/ {exit}
    capture {print}
  ' .github/workflows/release.yml
)"

for required in \
  "contents: read" \
  "packages: read" \
  "pages: write" \
  "id-token: write"
do
  if ! grep -q "$required" <<<"$deploy_site_block"; then
    flag "release.yml deploy-site caller is missing '$required'"
  fi
done

for required in \
  "SHA256SUMS.txt" \
  "sha256sum -c -" \
  "cosign verify-blob" \
  "--certificate-identity"
do
  if ! fixed_exists "$required" .github/actions/certify-app/action.yml; then
    flag "certify-app action must verify downloaded ClearCutt CLI assets with '$required'"
  fi
done

exit "$fail"
