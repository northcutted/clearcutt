#!/usr/bin/env bash
# ClearCutt — Open a draft PR for a CVE remediation branch.
#
# Single source of truth for the PR title/body across both the manual
# `cve-patch-agent` workflow and the scheduled-scan auto-dispatcher.
#
# Usage:
#   open-remediation-pr.sh <branch> <package> <cve> <installed_version> [summary_json]
#
# Requires: gh CLI authenticated with `pull-requests: write` + `contents: write`.

set -euo pipefail

BRANCH="${1:?branch name required}"
PACKAGE="${2:?package name required}"
CVE="${3:?cve id required}"
INSTALLED_VERSION="${4:-unknown}"
SUMMARY_PATH="${5:-}"

if [[ "$BRANCH" != "cve-remediation/"* ]]; then
  echo "Refusing to PR non-remediation branch: $BRANCH" >&2
  exit 1
fi

echo "Pushing $BRANCH to origin..."
git push origin "$BRANCH" --force-with-lease

TITLE="chore: automated CVE patch remediation for ${PACKAGE} (${CVE})"

SUMMARY_SECTION=""
if [[ -n "$SUMMARY_PATH" && -s "$SUMMARY_PATH" ]]; then
  SUMMARY_SECTION=$(python3 - "$SUMMARY_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

recipe = data.get("recipe") or {}
validation = data.get("validation") or []
affected = data.get("affected_targets") or []

print("### Broker campaign")
print(f"- **Route:** `{recipe.get('route', data.get('remediation_route', 'unknown'))}`")
if recipe.get("package_attribute"):
    print(f"- **Nix package attribute:** `{recipe['package_attribute']}`")
if data.get("fixed_version"):
    print(f"- **Expected fixed version:** `{data['fixed_version']}`")
print(f"- **Affected target fanout:** `{len(affected)}`")
prod_count = len([item for item in affected if item.get("tier") in {"slim", "distroless"}])
print(f"- **Production target fanout:** `{prod_count}`")
if affected:
    labels = []
    for item in affected[:8]:
        labels.append(f"{item.get('target')}:{item.get('arch')}")
    extra = "" if len(affected) <= 8 else f" (+{len(affected) - 8} more)"
    print(f"- **Affected targets:** `{', '.join(labels)}{extra}`")

print()
print("### Before/after validation")
if not validation:
    print("- No validation summary was attached by the drafting agent.")
else:
    for item in validation:
        status = item.get("status", "unknown")
        target = item.get("target", "unknown")
        reason = item.get("reason", "")
        print(f"- `{target}`: **{status}** - {reason}")
        if item.get("scanPath"):
            print(f"  - Grype scan: `{item['scanPath']}`")
        if item.get("sbomPath"):
            print(f"  - SBOM: `{item['sbomPath']}`")
PY
)
fi

# IMPORTANT: this body intentionally avoids overstating verification.
# The drafting agent only validates the broker-selected affected target set.
# The full matrix runs inside the PR's pr-gate workflow and remains the
# authoritative merge gate.
BODY=$(cat <<EOF
This Pull Request was automatically drafted by the **ClearCutt CVE Patch Drafting Agent**.

### Details
- **Package:** \`${PACKAGE}\`
- **Installed version:** \`${INSTALLED_VERSION}\`
- **CVE:** \`${CVE}\`
- **Overlay file:** \`core/overlays/cve/\` (one file per remediation)

$SUMMARY_SECTION

### Verification
The agent verified the patch against the broker-selected affected target set
and required the original CVE/package pair to disappear from rebuilt Grype
scan output. The full 13-language x 3-tier x 2-arch matrix runs in this PR's \`pr-gate\` job;
**do not merge until that suite is green.**

### Rollback
To revert, delete the new file under \`core/overlays/cve/\` and re-merge to main.
EOF
)

echo "Opening draft PR..."
gh pr create \
  --title "$TITLE" \
  --body "$BODY" \
  --head "$BRANCH" \
  --base main \
  --draft

echo "Done. PR created against $BRANCH."
