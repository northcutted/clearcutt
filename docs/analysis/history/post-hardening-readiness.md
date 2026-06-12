# ClearCutt Post-Hardening Readiness Note

Date: 2026-06-08

Status: historical follow-up note for the post-audit hardening branch. The current analysis landing page is `docs/analysis/README.md`. This file superseded readiness verdicts and unresolved P0/P1 blocker language in the 2026-06-07 analysis snapshots:

- `docs/analysis/history/clearcutt-audit.md`
- `docs/analysis/history/clearcutt-action-plan.md`
- `docs/analysis/history/decisions-needed.md`
- `docs/analysis/history/critical-path-0-review.md`

Those files remain useful as historical audit inputs and backlog context, but their original "not ready" and "needs minor fixes" verdicts should not be read as the current branch state.

## Current Readiness Readout

ClearCutt is ready for targeted serious human feedback on the current branch. The core P0/P1 trust, first-run, catalog staleness, app-team proof, workflow hardening, and positioning blockers identified in the earlier analysis have been addressed or explicitly reframed.

This does not mean the whole project is finished. Screenshots remain deferred by owner direction, live registry/GitHub Actions execution was not rerun in this pass, and broader P2/P3 product polish remains outside this critical-path review.

## Superseded P0/P1 Findings

| Earlier finding | Current branch state | Evidence |
|---|---|---|
| Universal signing/SLSA/security wording was too broad. | Top-level language now qualifies evidence as workflow-configured and catalog-reported instead of universal proof. | `README.md`, `docs/security-model.md`, `site/src/lib/claims.ts`, `site/src/pages/about.astro` |
| ClearCutt's lead identity was unclear. | The project now leads as a forkable platform kit and reference implementation. | `README.md`, `docs/README.md`, `docs/platform-kit.md`, `site/src/pages/index.astro` |
| `verify image` blurred catalog gating with registry cryptographic verification. | `verify image` is now documented and described as a catalog policy gate; `verify release-evidence` is the registry-side cryptographic path. | `README.md`, `docs/trust/evidence-walkthrough.md`, `docs/cli-reference.md`, `cli/internal/commands/verify.go` |
| Catalog freshness and stale public VEX files could mislead reviewers. | The generated catalog has 39 index entries, 39 image records, no orphan image JSON files, and no `site/public/vex` or `site/dist/vex` JSON files. | `site/src/data/catalog/index.json`, `site/src/data/catalog/images/`, `site/src/data/catalog/evidence-manifest.json` |
| Missing centralized evidence manifest. | Catalog builds now emit a schema-backed per-release `evidence-manifest.json`, and the site serves it at `/catalog/evidence-manifest.json`. | `cli/internal/commands/catalog_evidence_manifest.go`, `cli/internal/catalog/schemas/evidence-manifest.v1.schema.json`, `site/src/pages/catalog/evidence-manifest.json.ts` |
| App-template and app-certification examples used stale command paths and incomplete image refs. | Generated app workflows install a verified ClearCutt CLI, avoid old `certify-app@...` usage, and pass digest-qualified `--image-ref`. | `cli/internal/commands/app_template.go`, `examples/clearcutt-template-*/.github/workflows/release.yml`, `docs/certification.md` |
| Release workflow/action hardening gaps. | Action refs and SLSA builder refs are pinned; release Pages permissions are explicit; a PR guard validates hardening. | `.github/workflows/release.yml`, `.github/workflows/pr-gate.yml`, `.github/actions/certify-app/action.yml`, `scripts/validate-workflow-hardening.sh` |
| VEX and exception copy/statuses could imply stronger non-impact proof than recorded. | Deferred remediation reasons no longer become `not_affected`; example exception wording avoids absolute "completely sealed" language. | `cli/internal/commands/vex.go`, `cli/internal/commands/vex_test.go`, `site/src/pages/cli.astro` |

## Current Reviewer State

The latest read-only focused subagent reviews reported:

| Reviewer | Result | Scope |
|---|---|---|
| CLI reviewer | HAPPY | Documented command paths, app-template runtime gating, generated workflows, catalog-site commands, doc drift guard. |
| Catalog/site reviewer | HAPPY | Stale catalog/evidence risks, site/template parity, evidence manifest route, no public VEX drift. |
| Release engineer | HAPPY | Workflow permissions, pinned refs, SLSA builder identity, PR hardening guard, app workflow installs. |
| Docs architect | HAPPY | Role routing, first-run fixture path, platform-owner command, evidence walkthrough. |
| App developer | HAPPY | Fixture catalog path, devcontainer path, generated app workflow proof, `--image-ref`. |
| Security auditor | HAPPY | Trust boundary wording, release-evidence verification, evidence manifest, VEX semantics, workflow pinning. |
| Brutal skeptic | NOT HAPPY before this note | Flagged only stale `docs/analysis/` truth. This note and the superseded banners address that blocker. |

## Validation Commands

These commands passed after the post-hardening changes:

```bash
go -C cli test ./...
go -C cli vet ./...
go -C cli build -o ../clearcutt ./cmd/clearcutt
npm --prefix site run typecheck
rm -rf site/dist && npm --prefix site run build
actionlint .github/workflows/*.yml examples/clearcutt-template-go/.github/workflows/*.yml examples/clearcutt-template-java/.github/workflows/*.yml examples/clearcutt-template-node/.github/workflows/*.yml examples/clearcutt-template-python/.github/workflows/*.yml
bash scripts/validate-doc-commands.sh ./clearcutt
bash scripts/validate-workflow-hardening.sh
./clearcutt --catalog site/src/data/catalog catalog validate --schema-version clearcutt.catalog.evidence-manifest/v1
./clearcutt --catalog site/src/data/catalog verify catalog
diff -ru --exclude data site/src cli/internal/sitetemplate/template/src
git diff --check
```

Additional current-state checks:

```bash
find site/public/vex -maxdepth 1 -type f -name '*.json'
find site/dist/vex -maxdepth 1 -type f -name '*.json'
comm -3 <(jq -r '.images[] | if type == "string" then . else .id end' site/src/data/catalog/index.json | sort) <(find site/src/data/catalog/images -maxdepth 1 -type f -name '*.json' -exec basename {} .json \; | sort)
```

Those checks produced no stale VEX files and no catalog index/image membership mismatch.

## Remaining Non-Blocking Risks

- Screenshots and browser visual QA are intentionally deferred.
- Live GitHub Actions release execution, registry push/pull, and live Cosign/GitHub attestation verification were not rerun locally.
- The worktree is broad and dirty from the larger polish/hardening pass; reviewers should evaluate the current branch diff intentionally.
- P2/P3 backlog items from the original action plan remain useful future work, but they are not blockers for targeted serious human feedback.
