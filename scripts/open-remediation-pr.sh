#!/usr/bin/env bash
# ClearCutt — Open a draft PR for a CVE remediation branch.
#
# Single source of truth for the PR title/body across both the manual
# `cve-patch-agent` workflow and the scheduled-scan auto-dispatcher.
#
# Usage:
#   open-remediation-pr.sh <branch> <package> <cve> <installed_version>
#
# Requires: gh CLI authenticated with `pull-requests: write` + `contents: write`.

set -euo pipefail

BRANCH="${1:?branch name required}"
PACKAGE="${2:?package name required}"
CVE="${3:?cve id required}"
INSTALLED_VERSION="${4:-unknown}"

if [[ "$BRANCH" != "cve-remediation/"* ]]; then
  echo "Refusing to PR non-remediation branch: $BRANCH" >&2
  exit 1
fi

echo "Pushing $BRANCH to origin..."
git push origin "$BRANCH" --force

TITLE="chore: automated CVE patch remediation for ${PACKAGE} (${CVE})"

# IMPORTANT: this body intentionally avoids overstating verification.
# The drafting agent only built ONE canary target — the full matrix runs
# inside the PR's pr-gate workflow and is the authoritative gate. Past
# wording ("100% Green / G1-G5 Gates Passed") was misleading.
BODY=$(cat <<EOF
This Pull Request was automatically drafted by the **ClearCutt CVE Patch Drafting Agent**.

### Details
- **Package:** \`${PACKAGE}\`
- **Installed version:** \`${INSTALLED_VERSION}\`
- **CVE:** \`${CVE}\`
- **Overlay file:** \`overlays/cve/\` (one file per remediation)

### Verification
The agent verified the patch builds against a single canary target
(\`coreLTS-slim\` on Linux, \`java21-native\` on Darwin). The full
13-language × 3-tier × 2-arch matrix runs in this PR's \`pr-gate\` job;
**do not merge until that suite is green.**

### Rollback
To revert, delete the new file under \`overlays/cve/\` and re-merge to main.
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
