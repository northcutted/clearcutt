# ClearCutt Agent Tooling

This directory is the committed home for repo-scoped agent tooling.

- `context/` contains the source instruction files used to generate harness-specific outputs. `active_context.md` is ignored local scratch state; keep durable handoffs in runbooks or memory instead.
- `runbooks/` contains longer operational handoffs for repeatable repository work.
- `skills/` contains Codex skill definitions for ClearCutt workflows.
- `reviewers/` contains read-only reviewer profiles for broad audits.
- `sync.sh` compiles `.agents/context/` into committed or ignored harness outputs.

Root-level files such as `.cursorrules`, `.windsurfrules`, and `.claudeprompt`
are ignored generated outputs. `.codex/` stays limited to Codex runtime config
and command guardrails.
