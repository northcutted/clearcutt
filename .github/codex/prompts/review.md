# ClearCutt Codex PR Review

Review the pull request diff as a serious ClearCutt maintainer. Do not edit files.

Prioritize P0/P1 findings only. Focus on:

- supply-chain regressions in signing, SBOMs, provenance, OIDC identity, evidence verification, catalog generation, scans, exceptions, VEX, policy, or remediation;
- claim/proof drift in README, docs, site copy, generated template copy, or CLI help;
- public CLI behavior changes without matching docs, tests, or compatibility rationale;
- workflow changes that make fork setup, release evidence, Pages publishing, scheduled scans, remediation, or rebase less trustworthy;
- generated-site/template drift between `site/` and `cli/internal/sitetemplate/template/`;
- tests that rely on generated or network-only state instead of committed fixtures.

For every finding, include the file and line, the concrete risk, and the smallest acceptable fix. If no P0/P1 issues are found, say that clearly and note any residual test gaps.
