# Short-Term Agent Context Memory (RAM)

This register is for active cross-agent handoff state only. Historical work
belongs in `.agent/runbooks/` or durable memory summaries, not in this file.

---

## Current Active Task

**Objective:** Set up repo-native Codex workflows for ClearCutt.

**Status:** Completed on 2026-06-07.

## Completed Setup

- Added repo-scoped Codex defaults in `.codex/config.toml`.
- Added Codex command guardrails in `.codex/rules/default.rules`.
- Preserved the existing custom reviewer agents in `.codex/agents/`.
- Added ClearCutt skills under `.agents/skills/`:
  - `clearcutt-audit`
  - `clearcutt-cli-change`
  - `clearcutt-local-run`
  - `clearcutt-site-qa`
  - `clearcutt-release-triage`
  - `clearcutt-retrospective`
- Added reusable Codex/GitHub prompt templates under `.github/codex/prompts/`.
- Updated `AGENTS.md` with Codex setup guidance and review guidelines.
- Added local build/run and catalog data mode guidance to `AGENTS.md`,
  including stale `site/src/data/catalog` handling.
- Added a controlled self-improvement loop to `AGENTS.md`, a retrospective
  skill, retrospective prompt templates, and updated stale catalog advice in
  `.agent/lessons_learned.md`.
- Created active weekly worktree automation `clearcutt-weekly-claim-drift-audit`
  for read-only claim-vs-proof drift review.
- Created active weekly worktree automation `clearcutt-agent-setup-drift-review`
  for read-only agent guidance drift and token-efficiency review.

## Current Handoff State

There is no active implementation task to resume from this file.

Future agents should start from:

1. The user's latest prompt.
2. `git status --short`.
3. `AGENTS.md`.
4. The relevant `.agents/skills/*/SKILL.md` file when the task matches a skill.

Do not resume the older Node/Python-to-Go migration from this file; that stale
state has been retired from active context.
