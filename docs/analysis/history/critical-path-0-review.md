# Critical Path 0 Review

Date: 2026-06-07

Status: historical review snapshot. The "needs minor fixes" verdict below described the branch before the follow-up polish/hardening pass. The flagged wording issues have since been addressed or superseded; start with `docs/analysis/README.md` for the current state.

Verdict at time of review: needs minor fixes

## Executive Readout

Critical Path 0 is broadly on track. The requested validation commands pass, the changed `site/` files and embedded generated-site template files are byte-for-byte consistent, the release workflow permission changes are minimal, and the current CLI source exposes the documented command paths in help.

The remaining issues are copy/claim precision issues, not implementation failures:

- `gh attestation verify` copy says it verifies both build provenance and SBOM, but the documented command does not pass `--predicate-type`; local `gh` help confirms the default predicate is SLSA provenance.
- High-risk wording still appears in changed site/template surfaces: `Every published ClearCutt image`, `Non-falsifiable attestation`, and broad `hermetic` phrasing.
- Some first-path examples intentionally write files or require Docker/Nix. I did not run those exact write-effecting commands in the worktree because this was an audit-only pass. The fixture-backed first-run commands and current-source mixed-catalog site build were validated.

## Changed Files

Output of `git diff --name-only`:

```text
.github/workflows/release.yml
README.md
cli/internal/catalog/load.go
cli/internal/commands/platform.go
cli/internal/commands/root.go
cli/internal/commands/verify.go
cli/internal/sitetemplate/template/README.md
cli/internal/sitetemplate/template/src/components/CveDashboard.astro
cli/internal/sitetemplate/template/src/components/ProvenanceBlock.astro
cli/internal/sitetemplate/template/src/components/TerminalSimulator.tsx
cli/internal/sitetemplate/template/src/components/VerifyBlock.astro
cli/internal/sitetemplate/template/src/components/VulnerabilityTable.tsx
cli/internal/sitetemplate/template/src/lib/claims.ts
cli/internal/sitetemplate/template/src/lib/image-metadata.ts
cli/internal/sitetemplate/template/src/pages/about.astro
cli/internal/sitetemplate/template/src/pages/cli.astro
cli/internal/sitetemplate/template/src/pages/getting-started.astro
docs/exceptions-and-vex.md
docs/getting-started.md
docs/platform-kit.md
docs/security-model.md
docs/site-generator.md
site/README.md
site/src/components/CveDashboard.astro
site/src/components/ProvenanceBlock.astro
site/src/components/TerminalSimulator.tsx
site/src/components/VerifyBlock.astro
site/src/components/VulnerabilityTable.tsx
site/src/lib/claims.ts
site/src/lib/image-metadata.ts
site/src/pages/about.astro
site/src/pages/cli.astro
site/src/pages/getting-started.astro
```

Note: `git status --short` also shows untracked `.codex/`, `AGENTS.md`, and `docs/analysis/`. Those are not part of `git diff --name-only`; this report adds `docs/analysis/critical-path-0-review.md`.

## Diff Stat

Output of `git diff --stat`:

```text
 .github/workflows/release.yml                      |  2 +
 README.md                                          | 48 ++++++++++++++--------
 cli/internal/catalog/load.go                       |  8 ++--
 cli/internal/commands/platform.go                  |  2 +-
 cli/internal/commands/root.go                      |  2 +-
 cli/internal/commands/verify.go                    | 32 ++++++++-------
 cli/internal/sitetemplate/template/README.md       | 10 ++---
 .../template/src/components/CveDashboard.astro     |  2 +-
 .../template/src/components/ProvenanceBlock.astro  |  4 +-
 .../template/src/components/TerminalSimulator.tsx  |  8 ++--
 .../template/src/components/VerifyBlock.astro      |  2 +-
 .../template/src/components/VulnerabilityTable.tsx |  2 +-
 .../sitetemplate/template/src/lib/claims.ts        |  8 ++--
 .../template/src/lib/image-metadata.ts             | 14 +++----
 .../sitetemplate/template/src/pages/about.astro    |  4 +-
 .../sitetemplate/template/src/pages/cli.astro      |  6 +--
 .../template/src/pages/getting-started.astro       |  6 +--
 docs/exceptions-and-vex.md                         |  5 ++-
 docs/getting-started.md                            | 24 +++++++----
 docs/platform-kit.md                               |  4 +-
 docs/security-model.md                             |  8 ++--
 docs/site-generator.md                             | 13 ++++--
 site/README.md                                     | 10 ++---
 site/src/components/CveDashboard.astro             |  2 +-
 site/src/components/ProvenanceBlock.astro          |  4 +-
 site/src/components/TerminalSimulator.tsx          |  8 ++--
 site/src/components/VerifyBlock.astro              |  2 +-
 site/src/components/VulnerabilityTable.tsx         |  2 +-
 site/src/lib/claims.ts                             |  8 ++--
 site/src/lib/image-metadata.ts                     | 14 +++----
 site/src/pages/about.astro                         |  4 +-
 site/src/pages/cli.astro                           |  6 +--
 site/src/pages/getting-started.astro               |  6 +--
 33 files changed, 156 insertions(+), 124 deletions(-)
```

## Requested Command Results

| Command | Result | Notes |
|---|---|---|
| `git diff --name-only` | pass | Listed above. |
| `git diff --stat` | pass | Listed above. |
| `git diff --check` | pass | No whitespace errors. |
| `go -C cli test ./...` | pass | All CLI packages passed or had no test files. |
| `go -C cli run ./cmd/clearcutt verify --help` | pass | Shows `image`, `catalog`, and `release-evidence`; `image` is described as policy contract gating. |
| `go -C cli run ./cmd/clearcutt catalog site build --help` | pass | Shows expected build flags including `--catalog`, `--config`, `--images`, `--site-config`, `--overrides`, `--install`, and `--output`. |
| `npm run typecheck` in `site/` | pass | `astro check`: 0 errors, 0 warnings, 0 hints. |
| `npm run build` in `site/` | pass | Astro built 47 pages; Pagefind indexed 41 pages. |
| `actionlint .github/workflows/release.yml` | pass | No findings. |

Additional source-current checks run for this audit:

| Command | Result | Notes |
|---|---|---|
| `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list` | pass | Clean-clone safe README fixture path works from repo root. |
| `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless` | pass | Clean-clone safe README fixture path works from repo root. |
| `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog catalog validate` | pass | 0 errors, 1 warning for fixture layer/package mapping. |
| `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --max-critical 0 --max-high 3 --allow-preview` | pass | Output says `Policy Gating Report` and catalog-record evidence messages. |
| `/tmp/clearcutt-critical-path-0-current --catalog cli/internal/testdata/catalog verify image java21-distroless ...` | pass | Current-source binary run from repo root with docs path. |
| `/tmp/clearcutt-critical-path-0-current --catalog cli/internal/testdata/mixed-catalog catalog validate` | pass | 2 image records validated. |
| `/tmp/clearcutt-critical-path-0-current catalog site build --catalog cli/internal/testdata/mixed-catalog --output /tmp/clearcutt-critical-path-0-current-service-demo --install --clean` | pass | Current-source mixed fixture site build succeeded; 10 pages built. |

Not run in the worktree because this audit was explicitly no-modification: first-path examples that write `examples/`, `dist/`, `clearcutt.fleet.yaml`, generated Nix files, or user config, or that start Docker/Nix-backed flows. Their CLI command paths were checked against help.

## Documented CLI Help Check

All documented `clearcutt` command paths reviewed from the changed docs/site examples exist in CLI help when invoked as `clearcutt <path> --help`:

```text
clearcutt list
clearcutt inspect
clearcutt diff
clearcutt verify image
clearcutt verify catalog
clearcutt verify release-evidence
clearcutt certify
clearcutt conformance run
clearcutt matrix explain
clearcutt matrix add
clearcutt matrix remove
clearcutt matrix export
clearcutt runtime scaffold
clearcutt runtime validate
clearcutt service explain
clearcutt service scaffold
clearcutt service validate
clearcutt service matrix
clearcutt service build
clearcutt service smoke
clearcutt service publish
clearcutt fleet certify-target
clearcutt fleet publish-target
clearcutt fleet assemble-target
clearcutt fleet verify-target
clearcutt fleet export-provenance
clearcutt fleet finalize-release
clearcutt catalog build
clearcutt catalog generate
clearcutt catalog validate
clearcutt catalog summarize
clearcutt catalog diff
clearcutt catalog inspect
clearcutt catalog site scaffold
clearcutt catalog site build
clearcutt catalog site preview
clearcutt catalog site eject
clearcutt app template
clearcutt app build
clearcutt app diff-base
clearcutt app rebase
clearcutt dev
clearcutt overlay generate
clearcutt exceptions validate
clearcutt mirror
clearcutt mirror verify
clearcutt policy
clearcutt scan
clearcutt remediation
clearcutt vex
clearcutt platform init
clearcutt platform setup-nix
clearcutt platform status
```

## `verify image` Semantics

Result: pass with a small usability caveat.

The changed docs and help now describe `verify image` as catalog policy gating, not cryptographic verification:

- `cli/internal/commands/verify.go:79` says it evaluates catalog-record evidence flags, smoke test status, vulnerability limits, and lifecycle constraints.
- `README.md:248` says `verify image` is a catalog policy gate and points cryptographic verification to `verify release-evidence`.
- `docs/getting-started.md:110` says it checks the catalog record for reported evidence, lifecycle status, smoke tests, and vulnerability thresholds.
- `site/src/pages/cli.astro:120` and `cli/internal/sitetemplate/template/src/pages/cli.astro:120` distinguish the image gate from release-evidence registry-side Cosign/SLSA checks.
- `site/src/pages/getting-started.astro:116` and template mirror say the example checks catalog-record evidence flags and vulnerability thresholds.
- `docs/exceptions-and-vex.md:33` introduces the example as policy gating.

Caveat: `site/src/components/VerifyBlock.astro:22` and the template mirror show `clearcutt verify image ${image.id}` without an explicit `--catalog`. The nearby copy at `site/src/components/VerifyBlock.astro:183` correctly says it checks catalog-record evidence, so this is not a crypto-semantics failure. It is only less clean-clone friendly than the fixture-backed docs examples.

## Cryptographic Verification References

Result: needs minor fix.

Valid references:

- `clearcutt verify release-evidence --help` is real and requires `--ref`, `--repo`, and `--workflow-identity`.
- Local `cosign verify --help` confirms the documented `--certificate-identity`, `--certificate-identity-regexp`, and `--certificate-oidc-issuer` flags are valid.
- Local `cosign verify-attestation --help` confirms `--type spdxjson`, identity, and issuer style are valid.
- Local `cosign verify-blob --help` confirms `--bundle`, identity regexp, and issuer flags are valid. The release workflow creates `.sig` bundle files with `cosign sign-blob --bundle`.
- Local `slsa-verifier verify-image --help` confirms `--source-uri` and `--source-branch` are valid.
- Local `gh attestation verify --help` confirms `oci://...`, `--repo`, `--cert-identity`, `--cert-identity-regex`, and `--source-ref` are valid.

Issue:

- `site/src/pages/about.astro:287` and `cli/internal/sitetemplate/template/src/pages/about.astro:287` say the GitHub CLI verifies "build provenance and SBOM", but the command at line 293 does not pass `--predicate-type`. Local `gh attestation verify --help` says the default predicate type is `https://slsa.dev/provenance/v1`; other predicate types require `--predicate-type`. The command syntax is valid, but the copy overstates what that one command verifies.

Recommended fix: either say the GitHub CLI example verifies GitHub-native provenance only, or add a second `gh attestation verify ... --predicate-type <SBOM predicate>` example for SBOM verification.

## High-Risk Phrase Scan

Search terms:

- `every image`
- `SLSA-compliant`
- `non-falsifiable`
- `hermetic`
- `Vulnerability Free`
- `VERIFIED KEYLESS`
- `secure by default`
- `production-ready`
- `enterprise-grade`
- `complete deployment`

Remaining tracked-diff-file matches:

| Phrase | Location | Assessment |
|---|---|---|
| `Every published ClearCutt image` | `site/src/pages/about.astro:230`, `cli/internal/sitetemplate/template/src/pages/about.astro:230` | Risky universal framing. It says "expected", but still reads like a broad all-images evidence guarantee. |
| `every image detail page` | `site/src/pages/about.astro:299`, `cli/internal/sitetemplate/template/src/pages/about.astro:299` | Benign UI statement, not a trust claim. |
| `Non-falsifiable attestation` | `site/src/components/ProvenanceBlock.astro:465`, `cli/internal/sitetemplate/template/src/components/ProvenanceBlock.astro:465` | Should be softened. Attestations are signed and inspectable, but predicate contents can still be wrong or malicious if the signer workflow is compromised. |
| `Hermetically Built` / `hermetically-built` / `hermetic Nix base compilations` | `site/src/pages/about.astro:88`, `site/src/pages/about.astro:108`, `site/src/pages/about.astro:116`, plus template mirrors | Broad hermetic wording remains. Prefer scoping to Nix store closure isolation and reproducibility checks. |
| `Hermetic Store Closures` / `Nix-based hermetic compilation prevents...` | `site/src/lib/claims.ts:35`, `site/src/lib/claims.ts:36`, plus template mirrors | The title is more defensible than the description; "prevents untracked package injection" reads too absolute. |

No tracked-diff-file matches found for exact `SLSA-compliant`, `Vulnerability Free`, `VERIFIED KEYLESS`, `secure by default`, `production-ready`, `enterprise-grade`, or `complete deployment`.

## Site And Template Consistency

Result: pass.

Local `cmp -s` checks passed for all changed site/template pairs:

```text
site/README.md
site/src/components/CveDashboard.astro
site/src/components/ProvenanceBlock.astro
site/src/components/TerminalSimulator.tsx
site/src/components/VerifyBlock.astro
site/src/components/VulnerabilityTable.tsx
site/src/lib/claims.ts
site/src/lib/image-metadata.ts
site/src/pages/about.astro
site/src/pages/cli.astro
site/src/pages/getting-started.astro
```

Each file is byte-for-byte identical to its `cli/internal/sitetemplate/template/` counterpart.

## Release Workflow Permissions

Result: pass.

The workflow diff is minimal:

```diff
@@ -420,6 +420,7 @@ jobs:
     permissions:
+      contents: read
       id-token: write
       packages: write
       attestations: write
@@ -540,6 +541,7 @@ jobs:
     permissions:
+      contents: read
       id-token: write
       packages: write
       attestations: write
```

This is correct because both jobs define job-level permissions and then use `actions/checkout`:

- `assemble-multiarch`: `.github/workflows/release.yml:422` adds `contents: read`; checkout is at `.github/workflows/release.yml:431`.
- `assemble-service-multiarch`: `.github/workflows/release.yml:543` adds `contents: read`; checkout is at `.github/workflows/release.yml:552`.

The existing `id-token: write`, `packages: write`, and `attestations: write` scopes remain unchanged for signing, GHCR writes, and attestations. `actionlint .github/workflows/release.yml` passed.

## Awkward Or Confusing Wording

These are technically close, but worth tightening before calling the pass complete:

1. `site/src/pages/about.astro:287` and template mirror: "The same build provenance and SBOM are also published as GitHub-native attestations" is confusing because the shown `gh attestation verify` command only verifies the default SLSA provenance predicate.
2. `site/src/pages/about.astro:230` and template mirror: "Every published ClearCutt image is expected to carry..." is better than the old absolute claim, but still reads universal. "Published release workflows are configured to attach..." would better match catalog truth semantics.
3. `site/src/lib/claims.ts:36` and template mirror: "Nix-based hermetic compilation prevents untracked package injection" is too absolute. Prefer "constrains runtime inputs to declared Nix store closures" or similar.
4. `site/src/components/ProvenanceBlock.astro:465` and template mirror: "Non-falsifiable attestation" should be replaced with "Recorded provenance attestation" or "Signed provenance record".
5. `docs/platform-kit.md:52` and `cli/internal/commands/platform.go:361`: "Gate on signature, SBOM, provenance..." is understandable but slightly clipped. "Gate on signature, SBOM, provenance, and optional rebase-attestation evidence" works, but "Gate on required signature, SBOM, provenance..." would read cleaner.

## Recommended Next Step

Make a small wording-only follow-up that:

- Narrows the GitHub CLI attestation example to provenance only, or adds explicit SBOM predicate verification.
- Replaces `Non-falsifiable attestation`.
- Scopes the remaining `hermetic` claims to Nix store closure isolation and reproducibility evidence.
- Softens `Every published ClearCutt image...` to release-workflow configuration plus catalog status.

After that, rerun the same validation command set.
