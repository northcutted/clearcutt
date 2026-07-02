# ClearCutt Audit: CLI-First SLSA Image Fleet Pivot

Date: 2026-06-30

## Executive readout

ClearCutt is already a serious platform-engineering project, not a toy demo. The core pieces are present: a Go CLI with fleet, catalog, verification, app, remediation, policy, and release commands; a config-driven image matrix in `clearcutt.fleet.yaml`; GitHub Actions workflows that mostly delegate mechanics to `./clearcutt`; a generated catalog site; app templates and app rebase flows; and registry-side evidence verification for signatures, SBOMs, test attestations, and SLSA provenance.

The strongest product direction is to pivot from "fork this monorepo" to "download a signed `clearcutt` CLI, point it at or scaffold a GitHub repo, and let it create and operate a golden image fleet." That is directionally right. The repo even has a proposed plan for this in `docs/analysis/cli-pivot-plan.md`.

The current release-ready claim should be conservative: ClearCutt provides a GHCR-first, GitHub Actions-oriented, CLI-owned reference path for publishing and verifying an evidence-backed base image fleet. It is not yet ready to broadly claim registry-agnostic SLSA L3 fleet ownership or zero-touch remediation without qualifiers.

## Strongest parts

- The CLI surface is broad and coherent. `go -C cli run ./cmd/clearcutt --help` shows platform kit, catalog/release evidence, app workflow, governance gates, and security operations grouped in a way that matches the product thesis.
- `clearcutt.fleet.yaml` is a real public contract for registry identity, runtime/service matrix, release identity, SLSA builder, admission defaults, remediation policy, and site branding.
- `.github/workflows/release.yml` is mostly a thin orchestrator around `./clearcutt fleet ...`, with GitHub Actions supplying OIDC, permissions, matrix execution, artifacts, and reusable SLSA provenance.
- `verify release-evidence` is a real registry-side gate, distinct from `verify image`, which is correctly documented as a catalog policy gate.
- The app path is stronger than expected: `app build`, `app diff-base`, `app rebase`, offline `certify`, generated templates, and registry-side signature/provenance guidance are all present.
- The catalog site is useful: it exposes image selection, service images, evidence state, verification snippets, SBOM/vulnerability views, and customization hooks.
- Remediation has a real approved-drafting loop: scheduled scan/report, ranked plan, bounded patch drafting, aggregate PR behavior, overlay validation, exceptions, VEX, and crypto identity gates.

## Biggest credibility risks

- The project now has a `platform new` scaffold path from a reference checkout, embedded source archive, or explicit source archive, so an installed CLI can scaffold without a local ClearCutt checkout.
- The native Go fleet/service build engine is now the default CLI path for
  certifying and publishing single-architecture targets, with
  `core/pipeline/pipeline.sh` retained behind `--engine shell` as a temporary
  parity fallback.
- SLSA L3 is partly Actions-owned. The CLI owns much of the release mechanics, but the SLSA generator and GitHub-native attestations are workflow steps and trust anchors.
- Registry support is GHCR-first, not fully registry-agnostic. The release, catalog, and default rebase login host now come from `registry.host`, but non-GHCR registries still need caveats around auth, referrers, GitHub attestations, and SLSA verification.
- Release verification results are gates, not durable published evidence. The workflow verifies, but the checklist output is not yet uploaded as a release/catalog artifact.
- Provenance export uses rolling refs in places where versioned refs or immutable digests would be cleaner evidence hygiene.
- Version drift in app examples and generated templates undercuts trust: e.g. Python line references and `currentClearCuttRelease` differ across generator, docs, site, and checked-in examples.
- "Zero-touch patching" would overclaim. The real current posture is approved remediation PR drafting with human review and full gates.
- Grype suppressions need stronger governance. Ignore evidence can expire, but `.grype.yaml` suppressions need a required check that every suppression maps to active, unexpired evidence or VEX.

## Biggest comprehension risks

- New users must choose between clean-clone fixture proof, generated portable catalog, and live release-evidence catalog. The README is careful, but the first-run story still feels like many paths.
- App developers still see Nix-heavy details in catalog surfaces where the default task should be selecting an image, generating a template, and certifying/verifying usage.
- Platform engineers can customize the fleet, but "easy customization" still requires enough Nix/package-attribute understanding that it is platform-maintainer-friendly rather than broadly easy.
- Service images are visible in the catalog, but docs are more operator-focused than app-consumer-focused.

## Audience scoring

| Audience | Score | Read |
|---|---:|---|
| Platform engineer | 4 | Can see the architecture, CLI, workflows, fleet config, first scaffold command, embedded scaffold source, and GitHub preflight. Needs scaffolded workflows to install the released CLI rather than rebuilding local source. |
| App developer | 3 | App lifecycle and templates exist, but first path jumps to registry operations and examples drift. |
| Security/auditor | 4 | Evidence model is inspectable and conservative. Needs durable verification artifacts and suppression governance. |
| Engineering manager | 3 | Value proposition is real, but operational burden and release posture need sharper "what is supported now" framing. |
| Open-source evaluator | 3 | Impressive scope, but first-run and release-currentness need polish before Show HN-level scrutiny. |

## Claim-vs-proof

| Claim | Where claim appears | Current proof | Gap | Risk | Recommended fix |
|---|---|---|---|---|---|
| Platform fleet scaffold | README, docs/platform-kit.md, `platform new`, `platform doctor --github`, `.github/actions/install-clearcutt` | Strong repo layout, workflows, config, docs, checkout/archive/embedded scaffold, GitHub preflight, verified released-CLI install path | Native publish/remediation engines are still not fully Go-owned | Setup friction | Continue porting publish/remediation internals behind the CLI |
| CLI-first fleet operations | CLI help, fleet command, release workflow | Many release jobs call `./clearcutt fleet ...` | Native Go publish path not default | CLI is not fully self-contained | Finish native Go publish/remediation ports |
| SLSA Build L3 evidence | release.yml, clearcutt.fleet.yaml, docs | Uses SLSA generator and verification | Actions-owned and GitHub-specific | Overbroad SLSA claim | Phrase as configured GitHub release workflow evidence |
| Registry can be swapped | docs/registry-swap.md, fleet config | Host now comes from fleet config for release/catalog/default rebase; auth knobs exist | ECR/GAR caveats and second-registry proof remain | Swap looks easier than it is | Keep support tiers and add proven second-registry tests |
| Catalog is customizable | site config, catalog site CLI | Branding/nav/persona/site config exist | No realistic branded example | Abstract customization | Add example `clearcutt.site.yaml` |
| Zero-touch patching | Product aspiration, remediation workflows | Scan/plan/report, optional scheduled deterministic draft PRs, manual AI-assisted drafting, and aggregate PR update exist | Human-gated; deterministic authoring still partly Python; LLM optional and immature | Automation overclaim | Call it approved remediation PR drafting |

## Readiness matrix

| Area | Readiness | Notes |
|---|---|---|
| Runtime fleet config | Mostly proven | Strong matrix/config contract. |
| Service images | Partially implemented | First-class catalog records; release policy needs clarity. |
| GitHub Actions release | Mostly proven | CLI-heavy orchestration; SLSA/GitHub trust anchors remain workflow-owned. |
| Native self-contained CLI | Partially implemented | Certify path has Go engine; `platform new` scaffolds from checkout/archive/embedded source; scaffolded workflows install the verified released CLI by default | Publish/remediation internals still include shell/Python/Nix paths. |
| Registry portability | Scaffolded | GHCR strong; generic registry needs support tiers and single-source config. |
| Catalog portal | Mostly proven | Good evidence UX; app-first matrix needs tuning. |
| App lifecycle/rebase | Mostly proven | Strong advanced path; needs friendlier demo path. |
| Remediation | Partially implemented | Real approved drafting, optional scheduled deterministic draft PRs, and manual AI-assisted drafting; still not autonomous. |
| Verification | Mostly proven | Registry-side verification exists; durable release-verification artifacts are uploaded. |

## Recommended phases

1. **Trust and release-readiness cleanup.** Fix version drift, SLSA wording, durable verification artifacts, immutable provenance export, suppression governance, and registry single-sourcing.
2. **CLI-first pivot foundation.** Finish native Go publish path and deterministic remediation port; keep Nix as the build engine and recipes as embedded assets.
3. **Scaffolded fleet repo.** Keep the verified released-CLI install action as the default generated workflow path, and broaden `platform doctor` package/remediation checks.
4. **Show HN path.** Rewrite README/getting-started around install signed CLI, run fixture proof, inspect catalog, generate app template, and understand fleet scaffold.
5. **Registry and CI engine expansion.** Keep GHCR/GitHub Actions as reference; document support tiers before building additional backends.

## Bottom line

The project is close to being a compelling resume-grade and Show HN-worthy artifact, but the next work should not be adding new feature breadth. The high-leverage work is tightening the release/evidence story, making the CLI the entry point, proving a clean first-run path, and pruning or qualifying claims that are ahead of implementation.
