#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$(mktemp -d /tmp/clearcutt-release-control-plane.XXXXXX)}"
REPO="$OUT/clearcutt-demo"

case "$OUT" in
  ""|"/"|"/tmp")
    echo "Refusing to use unsafe OUT directory: $OUT" >&2
    exit 2
    ;;
esac

find_go() {
  local candidate
  for candidate in "${GO:-}" /opt/homebrew/bin/go "$(command -v go 2>/dev/null || true)" /usr/local/go/bin/go; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

run_clearcutt() {
  if [[ -n "${CLEARCUTT:-}" ]]; then
    "$CLEARCUTT" "$@"
  else
    local go_bin
    go_bin="$(find_go)"
    if "$go_bin" -C "$ROOT/cli" version >/dev/null 2>&1; then
      "$go_bin" -C "$ROOT/cli" run ./cmd/clearcutt "$@"
    else
      (cd "$ROOT/cli" && "$go_bin" run ./cmd/clearcutt "$@")
    fi
  fi
}

run_clearcutt platform render "$REPO" \
  --profile catalog-only \
  --catalog-source github-release \
  --catalog-source-repo northcutted/clearcutt \
  --catalog-targets java21-distroless,node24-slim,python3.14-dev \
  --catalog-release-limit 1 \
  --owner northcutted \
  --repo clearcutt-demo \
  --registry-base ghcr.io/northcutted/clearcutt \
  --visibility public \
  --pages \
  --generated-at 2026-01-01T00:00:00Z

for expected in \
  clearcutt.lock \
  .clearcutt/github.yaml \
  .clearcutt/site.yaml \
  .github/workflows/catalog.yml \
  .github/workflows/pr-gate.yml \
  docs/first-catalog.md; do
  test -f "$REPO/$expected"
done

for forbidden in images.yaml cli core site; do
  if [[ -e "$REPO/$forbidden" ]]; then
    echo "Release-backed control plane unexpectedly contains $forbidden" >&2
    exit 1
  fi
done

grep -q 'source: github-release' "$REPO/clearcutt.lock"
grep -q 'sourceRepo: northcutted/clearcutt' "$REPO/clearcutt.lock"
grep -q 'catalogMode: fleet' "$REPO/.clearcutt/site.yaml"
grep -q -- '--owner "northcutted" --repo "clearcutt"' "$REPO/.github/workflows/catalog.yml"
grep -q -- '--targets "java21-distroless,node24-slim,python3.14-dev"' "$REPO/.github/workflows/catalog.yml"
if grep -q -- '--images' "$REPO/.github/workflows/catalog.yml"; then
  echo "Release-backed catalog workflow still uses inventory mode" >&2
  exit 1
fi

if command -v actionlint >/dev/null 2>&1; then
  actionlint "$REPO/.github/workflows/catalog.yml" "$REPO/.github/workflows/pr-gate.yml"
fi

run_clearcutt catalog site build \
  --catalog "$ROOT/cli/internal/testdata/catalog" \
  --output "$OUT/site" \
  --install \
  --clean \
  --site-config "$REPO/.clearcutt/site.yaml" \
  --base-path /clearcutt-demo \
  --site-url https://northcutted.github.io

for expected in \
  "SBOM: Observed" \
  "Provenance: Verified" \
  "Signature: Verified" \
  "Tests: Verified"; do
  if ! grep -R -F "$expected" "$OUT/site" >/dev/null; then
    echo "Generated release-backed site is missing expected text: $expected" >&2
    exit 1
  fi
done

echo "Generated release-backed control plane smoke passed."
echo "Output directory: $OUT"
