# ClearCutt Agent Retrospective

Run a concise retrospective on the latest agent mistake, repeated correction, stale guidance, failed validation loop, or excessive token use. Do not edit files unless the owner explicitly asks for implementation.

Use this format:

## Mistake
What happened?

## Root Cause
Why did the agent do it?

## Better Rule
What small instruction would have prevented it?

## Promotion Target
Choose one: `AGENTS.md`, `.agents/skills/*`, `.agents/context/lessons_learned.md`, `.codex/rules`, `docs/analysis`, or Codex Memories.

## Token Efficiency Impact
What context, command, log, or validation waste happened? What smaller path should be used next time?

## Proposed Patch
Exact minimal file changes, or `none` if the lesson should stay as a note.

Promote only evidence-backed lessons. If a new rule supersedes stale guidance, say which old guidance should be removed or rewritten.
