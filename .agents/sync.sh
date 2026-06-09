#!/usr/bin/env bash
# ==============================================================================
# Agent Sync Tool
# Compiles centralized agent instructions and schemas into harness-native files.
# ==============================================================================

set -euo pipefail

# Locate repository root directory robustly without invoking git (avoids Apple xcrun issues)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

if [[ "${CLEARCUTT_AGENT_SYNC_VERBOSE:-0}" == "1" ]]; then
  echo "==> Syncing agent instruction outputs..."
fi

# Verify source files exist
for file in onboard.md instructions.md architecture.md lessons_learned.md; do
  if [ ! -f ".agents/context/${file}" ]; then
    echo "ERROR: Source file .agents/context/${file} is missing!" >&2
    exit 1
  fi
done

# Create target directories
mkdir -p .github
mkdir -p .vscode
mkdir -p .claude/skills

# Generate header function
generate_header() {
  local target_name="$1"
  cat <<EOF
# ==============================================================================
# WARNING: GENERATED FILE - DO NOT EDIT MANUALLY
# This file is compiled automatically from files inside the '.agents/context/' directory.
#
# Target: ${target_name}
# Source: .agents/context/onboard.md, .agents/context/instructions.md, .agents/context/architecture.md, .agents/context/lessons_learned.md
#
# To modify these instructions, edit the source files under '.agents/context/' and run:
#   make agent-sync
# ==============================================================================

EOF
}

# ------------------------------------------------------------------------------
# 1. Compile local harness rule files
# ------------------------------------------------------------------------------
if [[ "${CLEARCUTT_AGENT_SYNC_ROOT_RULES:-0}" == "1" ]]; then
  [[ "${CLEARCUTT_AGENT_SYNC_VERBOSE:-0}" == "1" ]] && echo "==> Compiling local root harness rule files..."
  CURSOR_FILE="${REPO_ROOT}/.cursorrules"
  generate_header ".cursorrules" > "${CURSOR_FILE}"
  cat .agents/context/onboard.md >> "${CURSOR_FILE}"
  echo -e "\n\n" >> "${CURSOR_FILE}"
  cat .agents/context/instructions.md >> "${CURSOR_FILE}"
  echo -e "\n\n" >> "${CURSOR_FILE}"
  cat .agents/context/architecture.md >> "${CURSOR_FILE}"
  echo -e "\n\n" >> "${CURSOR_FILE}"
  cat .agents/context/lessons_learned.md >> "${CURSOR_FILE}"

  cp "${CURSOR_FILE}" "${REPO_ROOT}/.windsurfrules"
  cp "${CURSOR_FILE}" "${REPO_ROOT}/.claudeprompt"
fi

# ------------------------------------------------------------------------------
# 2. Compile .github/copilot-instructions.md (GitHub Copilot)
# ------------------------------------------------------------------------------
[[ "${CLEARCUTT_AGENT_SYNC_VERBOSE:-0}" == "1" ]] && echo "==> Compiling .github/copilot-instructions.md..."
COPILOT_FILE="${REPO_ROOT}/.github/copilot-instructions.md"
generate_header ".github/copilot-instructions.md" > "${COPILOT_FILE}"
cat .agents/context/onboard.md >> "${COPILOT_FILE}"
echo -e "\n\n" >> "${COPILOT_FILE}"
cat .agents/context/instructions.md >> "${COPILOT_FILE}"
echo -e "\n\n" >> "${COPILOT_FILE}"
cat .agents/context/architecture.md >> "${COPILOT_FILE}"
echo -e "\n\n" >> "${COPILOT_FILE}"
cat .agents/context/lessons_learned.md >> "${COPILOT_FILE}"

# ------------------------------------------------------------------------------
# 3. Compile .vscode/tasks.json (VS Code & Cursor Procedural Memory)
# ------------------------------------------------------------------------------
[[ "${CLEARCUTT_AGENT_SYNC_VERBOSE:-0}" == "1" ]] && echo "==> Compiling .vscode/tasks.json..."
cat <<'EOF' > .vscode/tasks.json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Sync Agent System",
      "type": "shell",
      "command": "make agent-sync",
      "group": {
        "kind": "build",
        "isDefault": false
      },
      "problemMatcher": []
    },
    {
      "label": "Verify CLI & Ecosystem (Fast)",
      "type": "shell",
      "command": "./.claude/skills/test-clearcutt/scripts/verify.sh",
      "group": {
        "kind": "test",
        "isDefault": true
      },
      "problemMatcher": ["$go"]
    },
    {
      "label": "Nix Conformance Gating",
      "type": "shell",
      "command": "cd core && nix develop --extra-experimental-features \"nix-command flakes\" --accept-flake-config --command ./tests/verify.sh",
      "group": {
        "kind": "test",
        "isDefault": false
      },
      "problemMatcher": []
    },
    {
      "label": "Python Remediation Tests",
      "type": "shell",
      "command": "make core-remediation-tests",
      "group": {
        "kind": "test",
        "isDefault": false
      },
      "problemMatcher": []
    },
    {
      "label": "Generate Catalog Metadata",
      "type": "shell",
      "command": "make catalog-generate",
      "problemMatcher": []
    },
    {
      "label": "Build Astro Catalog Site",
      "type": "shell",
      "command": "make site-build",
      "problemMatcher": []
    }
  ]
}
EOF

if [[ "${CLEARCUTT_AGENT_SYNC_VERBOSE:-0}" == "1" ]]; then
  echo "Agent instruction outputs compiled."
fi
