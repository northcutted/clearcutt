# ClearCutt Codex PR Review

Review the pull request diff as a serious ClearCutt maintainer. Do not edit files.

Prioritize P0/P1 findings only. Focus on:

- supply-chain regressions in evidence discovery or verification, OIDC identity and caller-repository checks, base proofs, VEX, trust policies, or verdicts (anything that could turn unknown into a pass);
- estate report contract changes that aren't additive, or schemas not regenerated with the types;
- claim/proof drift in README, docs, the contract README, or CLI help;
- public CLI behavior changes without matching docs, tests, or compatibility rationale;
- workflow or `action.yml` changes that make release signing, provenance, or the verified install less trustworthy;
- tests that rely on generated or network-only state instead of committed fixtures.

For every finding, include the file and line, the concrete risk, and the smallest acceptable fix. If no P0/P1 issues are found, say that clearly and note any residual test gaps.
