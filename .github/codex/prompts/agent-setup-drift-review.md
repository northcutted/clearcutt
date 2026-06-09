# ClearCutt Agent Setup Drift Review

Run a read-only review of ClearCutt's agent guidance for staleness, duplication, contradiction, token bloat, and missing promotion paths. Do not edit files.

Inspect:

- `AGENTS.md`
- `.agents/skills/*/SKILL.md`
- `.agents/context/lessons_learned.md`
- `.agents/context/active_context.md`
- `.agents/runbooks/`
- `.codex/config.toml`
- `.codex/rules/`
- `.github/codex/prompts/`

Report only actionable findings. Prioritize:

- stale commands or paths;
- duplicated guidance that should be consolidated into a skill;
- instructions that cause broad searches, unnecessary builds, or noisy logs;
- generated or ignored paths treated as source of truth;
- missing fixture-backed validation guidance;
- conflicts between `.agents/context/lessons_learned.md`, `AGENTS.md`, and skills.

For each finding include:

- problem;
- evidence path;
- recommended minimal fix;
- promotion or pruning target;
- token-efficiency impact.
