# ClearCutt Claim Drift Audit

Run a read-only ClearCutt claim-vs-proof audit. Write findings only under `docs/analysis/` if an output file is requested.

Compare current claims in `README.md`, `docs/`, `contract/README.md`, `CHANGELOG.md`, `action.yml`, and CLI help against proof in code, workflows, tests, the contract schemas, the `contract/fixtures/` estate report, and `examples/`.

Classify each material claim as Proven, Mostly proven, Partially implemented, Scaffolded, Demo-only, Planned, Unclear, Misleading, or Unsupported.

Prioritize risks that would damage credibility with platform engineers, security auditors, engineering managers, or open-source reviewers.
