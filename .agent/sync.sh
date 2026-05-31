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

echo "==> Centralizing Agent DX System in ClearCutt..."

# Verify source files exist
for file in onboard.md instructions.md architecture.md lessons_learned.md; do
  if [ ! -f ".agent/${file}" ]; then
    echo "ERROR: Source file .agent/${file} is missing!" >&2
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
# This file is compiled automatically from files inside the '.agent/' directory.
#
# Target: ${target_name}
# Source: .agent/onboard.md, .agent/instructions.md, .agent/architecture.md, .agent/lessons_learned.md
# Compiled At: $(date +"%Y-%m-%d %H:%M:%S")
#
# To modify these instructions, edit the source files under '.agent/' and run:
#   make agent-sync
# ==============================================================================

EOF
}

# ------------------------------------------------------------------------------
# 1. Compile .cursorrules (Cursor AI)
# ------------------------------------------------------------------------------
echo "==> Compiling .cursorrules..."
CURSOR_FILE="${REPO_ROOT}/.cursorrules"
generate_header ".cursorrules" > "${CURSOR_FILE}"
cat .agent/onboard.md >> "${CURSOR_FILE}"
echo -e "\n\n" >> "${CURSOR_FILE}"
cat .agent/instructions.md >> "${CURSOR_FILE}"
echo -e "\n\n" >> "${CURSOR_FILE}"
cat .agent/architecture.md >> "${CURSOR_FILE}"
echo -e "\n\n" >> "${CURSOR_FILE}"
cat .agent/lessons_learned.md >> "${CURSOR_FILE}"

# ------------------------------------------------------------------------------
# 2. Compile .windsurfrules (Windsurf/Cascade AI)
# ------------------------------------------------------------------------------
echo "==> Compiling .windsurfrules..."
cp "${CURSOR_FILE}" "${REPO_ROOT}/.windsurfrules"

# ------------------------------------------------------------------------------
# 3. Compile .claudeprompt (Claude Code)
# ------------------------------------------------------------------------------
echo "==> Compiling .claudeprompt..."
cp "${CURSOR_FILE}" "${REPO_ROOT}/.claudeprompt"

# ------------------------------------------------------------------------------
# 4. Compile .github/copilot-instructions.md (GitHub Copilot)
# ------------------------------------------------------------------------------
echo "==> Compiling .github/copilot-instructions.md..."
COPILOT_FILE="${REPO_ROOT}/.github/copilot-instructions.md"
generate_header ".github/copilot-instructions.md" > "${COPILOT_FILE}"
cat .agent/onboard.md >> "${COPILOT_FILE}"
echo -e "\n\n" >> "${COPILOT_FILE}"
cat .agent/instructions.md >> "${COPILOT_FILE}"
echo -e "\n\n" >> "${COPILOT_FILE}"
cat .agent/architecture.md >> "${COPILOT_FILE}"
echo -e "\n\n" >> "${COPILOT_FILE}"
cat .agent/lessons_learned.md >> "${COPILOT_FILE}"

# ------------------------------------------------------------------------------
# 5. Compile .vscode/tasks.json (VS Code & Cursor Procedural Memory)
# ------------------------------------------------------------------------------
echo "==> Compiling .vscode/tasks.json..."
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

echo "✔ Agent DX configurations compiled successfully!"
