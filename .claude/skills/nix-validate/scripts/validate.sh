#!/usr/bin/env bash
# Validate the ClearCutt flake without pushing.
#
# Pure evaluation by default: no image is built, so this runs in seconds on a
# warm store. That is deliberate — every core/ failure this repo has shipped to
# CI was an EVAL error, not a build error:
#
#   dangling import        core/flake.nix imported a deleted overlay
#   undeclared argument    flake passed cryptoPkgs to a registry that dropped it
#   missing attribute      a gate defaulted to a runtime line the matrix removed
#   unquoted dotted attr   .#python3.14-distroless parsed as python3 -> 14-...
#
# Each cost a full CI round trip. Each is caught here.
#
# Usage:
#   validate.sh                 # eval every fleet cell + flake outputs
#   validate.sh --build TARGET  # also realize one image (slow, needs the cache)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
NIX_RUN="$HERE/nix-run.sh"
MATRIX="$REPO_ROOT/core/lib/fleet-matrix.nix"

BUILD_TARGET=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build) BUILD_TARGET="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "validate.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

if [[ ! -f "$MATRIX" ]]; then
  echo "validate.sh: $MATRIX not found; run 'clearcutt fleet compile' first" >&2
  exit 1
fi

fail=0
note() { printf '  %-9s %s\n' "$1" "$2"; }

echo "== flake evaluates =="
if out="$("$NIX_RUN" flake metadata --json 2>&1)"; then
  note "ok" "flake metadata resolves"
else
  note "FAIL" "flake does not evaluate"
  printf '%s\n' "$out" | tail -20
  exit 1
fi

# The systems and cells come from the GENERATED matrix, so this checks exactly
# what CI will build — a renamed runtime line moves the check with it.
systems=$(grep -oE '"[a-z0-9_]+-linux"' "$MATRIX" | tr -d '"' | sort -u)
cells=$(grep -oE 'line = "[^"]+"; language = "[^"]+"; version = "[^"]+"; tier = "[^"]+"' "$MATRIX" \
        | sed -E 's/line = "([^"]+)".*tier = "([^"]+)"/\1-\2/' | sort -u)

echo "== fleet cells resolve as flake attributes =="
for system in $systems; do
  for cell in $cells; do
    # Quote the attribute: a flake installable splits its path on ".", so an
    # unquoted python3.14-distroless resolves as python3 -> "14-distroless".
    if out="$("$NIX_RUN" eval --raw ".#packages.$system.\"$cell\".name" 2>&1)"; then
      note "ok" "$system $cell -> $out"
    else
      note "FAIL" "$system $cell"
      printf '%s\n' "$out" | grep -E 'error' | head -3
      fail=1
    fi
  done
done

echo "== flake outputs enumerate =="
for attr in checks devShells lib; do
  if out="$("$NIX_RUN" eval --json ".#$attr" --apply 'x: builtins.attrNames x' 2>&1)"; then
    note "ok" "$attr: $(printf '%s' "$out" | head -c 90)"
  else
    note "FAIL" "$attr does not evaluate"
    printf '%s\n' "$out" | grep -E 'error' | head -3
    fail=1
  fi
done

if [[ -n "$BUILD_TARGET" ]]; then
  echo "== build $BUILD_TARGET =="
  system="$(printf '%s\n' "$systems" | head -n1)"
  if "$NIX_RUN" build ".#packages.$system.\"$BUILD_TARGET\"" --no-link; then
    note "ok" "$BUILD_TARGET realized"
  else
    note "FAIL" "$BUILD_TARGET did not build"
    fail=1
  fi
fi

if [[ $fail -ne 0 ]]; then
  echo
  echo "validate.sh: FAILED — fix before pushing; CI would fail the same way."
  exit 1
fi
echo
echo "validate.sh: all checks passed."
