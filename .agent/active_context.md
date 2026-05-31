# Short-Term Agent Context Memory (RAM)

This register keeps track of the active task state across different agent runs and harnesses.

---

## Current Active Task

**Objective:** Bootstrap the Unified, Harness-Agnostic Agent DX & Memory System in this repository.

### Active Objectives
* [x] Create centralized `.agent/` directory.
* [x] Write `.agent/onboard.md` onboarding and extension rules.
* [x] Write `.agent/instructions.md` core guidelines.
* [x] Write `.agent/architecture.md` design and security policies.
* [x] Create long-term memory `.agent/lessons_learned.md` with initial lessons.
* [x] Create `.agent/sync.sh` script to build native harness files.
* [x] Integrate sync task in root `Makefile` (`make agent-sync`).
* [x] Create runbooks for Runtimes and CLI development under `.agent/runbooks/`.
* [x] Verify file synchronization and update `.claude/skills/test-clearcutt/scripts/verify.sh`.

---

## Active Status & State

* **Last Updated:** 2026-05-30
* **Current Agent/Harness:** Antigravity (Gemini 3.5 Flash)
* **Pending Actions:** All core system bootstrapping is successfully done and verified via `./.claude/skills/test-clearcutt/scripts/verify.sh`.
* **Blockages/Errors:** Resolved macOS `make` issue (xcrun/libxcrun architecture mismatch) by running `bash .agent/sync.sh` directly. Added a corresponding entry to `lessons_learned.md`.
