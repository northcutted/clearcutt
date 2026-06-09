#!/usr/bin/env bash
set -euo pipefail

fail=0

flag() {
  echo "workflow hardening drift: $*" >&2
  fail=1
}

if rg --hidden --no-ignore -n 'uses:\s+[^#[:space:]]+@(v[0-9]+|main|master)(\s|$)' .github/workflows .github/actions examples cli/internal/commands/app_template.go; then
  flag "workflow and composite action references must be pinned to immutable SHAs"
fi

if rg --hidden --no-ignore -n 'slsaBuilder: .*@v[0-9]|SLSABuilder:\s+".*@v[0-9]|generator_container_slsa3\.yml@v[0-9]' clearcutt.fleet.yaml cli/internal/fleet/config.go .github/workflows examples; then
  flag "release.slsaBuilder and generated SLSA builder refs must be pinned to the reviewed reusable workflow SHA"
fi

if ! rg -q 'slsaBuilder: .+@[0-9a-f]{40}' clearcutt.fleet.yaml; then
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
  if ! rg -q --fixed-strings -- "$required" .github/actions/certify-app/action.yml; then
    flag "certify-app action must verify downloaded ClearCutt CLI assets with '$required'"
  fi
done

exit "$fail"
