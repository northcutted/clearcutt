# ClearCutt Human Feedback Action Plan

Date: 2026-06-07

Status: historical audit-derived backlog snapshot. Several P0/P1 items in this file have since been implemented, softened, or superseded by the post-audit hardening pass. For the current readiness state and superseded blocker list, use `docs/analysis/post-hardening-readiness.md`.

Purpose: phase the work needed before serious human feedback. This is an audit-derived plan only. It does not implement product changes.

## Phase 0: Truth And Positioning Cleanup

Goal: fix overclaims, clarify project boundaries, clarify what works today vs planned, and make README/site language conservative and verifiable.

### P0-01: Qualify Universal Signing And SLSA Claims

- ID: P0-01
- Title: Qualify universal signing, attestation, and SLSA claims
- Problem: The public story says "every image signed, attested" and implies universal evidence completeness.
- Evidence: `README.md:3`, `README.md:58`, `.github/workflows/release.yml:499-529`, `.github/workflows/release.yml:686-773`, `site/.gitignore:5-7`.
- Why it matters: Security reviewers will treat overbroad trust claims as a credibility failure.
- Recommended fix: Reword to say published releases are configured to emit signatures, SBOMs, provenance, and catalog records; the catalog must report missing evidence independently.
- Target audience: Security/auditor, platform engineer, engineering manager.
- Files likely touched: `README.md`, `site/src/lib/claims.ts`, `site/src/pages/about.astro`, `docs/security-model.md`, `docs/audit-findings.md`.
- Acceptance criteria: No first-viewport or top-level docs claim "every image" has evidence unless `verify catalog` proves it for the published catalog being referenced.
- Suggested validation command: `rg -n "every image|non-falsifiable|SLSA-compliant|secure by default|zero CVEs|Vulnerability Free|VERIFIED KEYLESS" README.md docs site/src`.
- Priority: P0
- Effort: S
- Risk: Low implementation risk, high credibility impact.
- Dependencies: None.
- Work type: docs-only, site-only.

### P0-02: Publish A Truth Table For Current, Preview, Scaffolded, Demo, Planned

- ID: P0-02
- Title: Add a readiness truth table
- Problem: Implemented, preview, scaffolded, demo-only, and planned areas are mixed across README/site/docs.
- Evidence: `docs/service-images.md:59-74`, `docs/generic-oci-mode.md:88`, `README.md:181`, `docs/policy-bundles.md:16-27`, `cli/internal/commands/policy.go:105-146`.
- Why it matters: Evaluators need to know what they can trust before investing time.
- Recommended fix: Add a single readiness table linked from README and docs index.
- Target audience: All audiences.
- Files likely touched: `README.md`, `docs/README.md`, new `docs/concepts/readiness.md` or equivalent.
- Acceptance criteria: Runtime fleet, catalog generation, site generation, app template, certification, app rebase, services, remediation, policy bundles, Generic OCI mode, and BYO overlays each have a readiness label.
- Suggested validation command: `rg -n "Implemented|Preview|Scaffolded|Demo-only|Planned" README.md docs`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: P0-01 claim language.
- Work type: docs-only.

### P0-03: Clarify ClearCutt's Lead Identity

- ID: P0-03
- Title: Lead with platform kit and reference implementation
- Problem: ClearCutt can read as product, catalog generator, image factory, governance CLI, and platform kit all at once.
- Evidence: `README.md:12-21`, `docs/platform-kit.md:1-6`, `README.md:203-607`, `site/src/pages/platform-kit.astro:16-18`.
- Why it matters: If the category is unclear, reviewers will judge each subsystem as a standalone product and find it incomplete.
- Recommended fix: Lead with "forkable platform kit and reference implementation"; describe catalog generator, image factory, governance CLI, evidence portal, and app workflow as components.
- Target audience: Engineering manager, platform engineer, open-source evaluator.
- Files likely touched: `README.md`, `docs/platform-kit.md`, `site/src/lib/claims.ts`, `site/src/pages/index.astro`.
- Acceptance criteria: First screen answers "what is this?" without requiring command inventory.
- Suggested validation command: `sed -n '1,80p' README.md`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: P0-01.
- Work type: docs-only, site-only.

### P0-04: Separate Catalog Gates From Cryptographic Verification

- ID: P0-04
- Title: Reframe `verify image` as catalog policy gating
- Problem: `verify image` sounds like registry-side signature/SBOM/provenance verification, but it checks catalog-record fields.
- Evidence: `README.md:236-255`, `cli/internal/commands/verify.go:189`, `cli/internal/commands/verify.go:204`, `cli/internal/commands/verify.go:220`, `cli/internal/commands/verify_release_evidence.go:120-155`.
- Why it matters: Security reviewers need exact trust semantics.
- Recommended fix: Document `verify image` as a catalog policy gate and add a separate cryptographic evidence verification path.
- Target audience: Security/auditor, platform engineer.
- Files likely touched: `README.md`, `docs/security-model.md`, `docs/certification.md`, CLI help text in `cli/internal/commands/verify*.go`.
- Acceptance criteria: Docs distinguish "catalog reports evidence" from "cosign verified evidence against registry."
- Suggested validation command: `rg -n "verify image|verify release|cosign|catalog policy" README.md docs cli/internal/commands`.
- Priority: P0
- Effort: M
- Risk: Medium because CLI wording may be public behavior.
- Dependencies: Owner decision on CLI rename vs docs-only clarification.
- Work type: cross-cutting.

### P0-05: Label Services As Preview Until Evidence Is Current

- ID: P0-05
- Title: Make service-image readiness conservative
- Problem: Service images read like a current first-class lane while config and docs mark them preview/non-production.
- Evidence: `README.md:181`, `clearcutt.fleet.yaml:86-152`, `docs/service-images.md:59-88`, `cli/internal/testdata/mixed-catalog`.
- Why it matters: Platform engineers will distrust the project if preview features are presented as production paths.
- Recommended fix: Label service images as preview/scaffolded everywhere until current catalog evidence and release workflows prove them.
- Target audience: Platform engineer, security/auditor, engineering manager.
- Files likely touched: `README.md`, `docs/service-images.md`, `site/src/pages/catalog.astro`, `site/src/components/ServiceGrid.astro`.
- Acceptance criteria: Service lane copy consistently says preview/non-production unless the default catalog includes current service evidence.
- Suggested validation command: `rg -n "service lane|Postgres|Valkey|oauth2-proxy|productionAllowed|preview" README.md docs site/src clearcutt.fleet.yaml`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: P0-02 readiness table.
- Work type: docs-only, site-only.

## Phase 1: First-Run Comprehension

Goal: make README opening, quickstart, mental model, audience paths, and glossary coherent.

### P1-01: Shorten README To Orientation Plus First Proof

- ID: P1-01
- Title: Turn README back into a front door
- Problem: README becomes product page, operator manual, CLI reference, app guide, and deployment guide.
- Evidence: `README.md:12-159` is strong orientation; `README.md:186-607` becomes command/reference sprawl.
- Why it matters: A new visitor should understand ClearCutt and pick one next step in under 5 minutes.
- Recommended fix: Keep thesis, audiences, first successful path, proof map, and links. Move command inventory to docs.
- Target audience: All audiences.
- Files likely touched: `README.md`, new docs pages linked from README.
- Acceptance criteria: README answers "what is this?", "who owns what?", "first command?", "where is trust proof?", and "where do I go by role?"
- Suggested validation command: `wc -l README.md && sed -n '1,180p' README.md`.
- Priority: P0
- Effort: M
- Risk: Medium because moving material can break links.
- Dependencies: P0-03, P1-02.
- Work type: docs-only.

### P1-02: Add A Docs Front Door

- ID: P1-02
- Title: Add audience-routed `docs/README.md`
- Problem: Docs are flat and role routing is implicit.
- Evidence: No `docs/README.md`; README's deeper proof links start around `README.md:146`; docs include platform, app, trust, schema, service, and advanced topics at the same level.
- Why it matters: Each audience needs a different first path.
- Recommended fix: Add a docs index with "I am an app developer", "I operate the fork", "I review evidence", "I evaluate adoption", and "I review the project" paths.
- Target audience: All audiences.
- Files likely touched: `docs/README.md`, `README.md`.
- Acceptance criteria: Each audience has exactly one first document, one first command, and deeper links.
- Suggested validation command: `test -f docs/README.md && rg -n "App developer|Platform owner|Security|Manager|Open-source" docs/README.md`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: P0-02 readiness table.
- Work type: docs-only.

### P1-03: Make The Golden Path Fixture-Backed

- ID: P1-03
- Title: Use a clean-clone proof path that passes
- Problem: Default commands fail in a clean clone without generated catalog data.
- Evidence: `README.md:197-211`, `site/.gitignore:5-7`, `cli/internal/catalog/load.go:25-38`; local `go -C cli run ./cmd/clearcutt list` failed without `--catalog`.
- Why it matters: A new evaluator should see value before generating or publishing a catalog.
- Recommended fix: First path should use `--catalog internal/testdata/catalog` and `java21-distroless`.
- Target audience: Open-source evaluator, app developer, platform engineer.
- Files likely touched: `README.md`, `docs/getting-started.md`, `docs/README.md`, `site/src/pages/getting-started.astro`.
- Acceptance criteria: First five commands in docs pass from a clean checkout with no generated catalog.
- Suggested validation command: `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list && go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: None.
- Work type: docs-only, site-only.

### P1-04: Rewrite App-Team Getting Started Around Template, Dev, Certify

- ID: P1-04
- Title: Make app adoption Docker/Podman first
- Problem: App-team onboarding still asks readers to reason through base image selection and manual Dockerfiles before the paved path.
- Evidence: `docs/getting-started.md:3-31`, `README.md:337-370`, `cli/internal/commands/app_template.go:148-155`, `examples/clearcutt-template-java/README.md:3-12`.
- Why it matters: App developers should not have to learn Nix or platform internals to try ClearCutt.
- Recommended fix: Start with catalog selection, `app template`, devcontainer, `certify`, and CI gate; move manual Dockerfiles lower.
- Target audience: App developer.
- Files likely touched: `docs/getting-started.md`, template README output in `cli/internal/commands/app_template.go`, examples under `examples/clearcutt-template-*`.
- Acceptance criteria: App path explains how to choose an image, create a template, run dev, build/certify, and hand evidence to CI.
- Suggested validation command: `go -C cli run ./cmd/clearcutt app template --help && rg -n "app template|devcontainer|certify" docs/getting-started.md`.
- Priority: P1
- Effort: M
- Risk: Medium if template output changes.
- Dependencies: P1-03.
- Work type: cross-cutting.

### P1-05: Add Glossary And Mental Model

- ID: P1-05
- Title: Define terms once
- Problem: Key terms are repeated across docs without a canonical source.
- Evidence: Lane model in `README.md:25-38`, tier model in `docs/getting-started.md:24-31`, service terms in `docs/service-images.md:9`, trust terms across `docs/security-model.md` and `docs/exceptions-and-vex.md`.
- Why it matters: Terminology drift makes ClearCutt feel more complex than it is.
- Recommended fix: Add glossary and mental-model docs covering two loops, lanes, tiers, catalog, evidence, verification, certification, rebase, exception, VEX, preview, and scaffold.
- Target audience: All audiences.
- Files likely touched: `docs/concepts/glossary.md`, `docs/concepts/mental-model.md`, `README.md`, `docs/README.md`.
- Acceptance criteria: README links to one glossary; repeated definitions can be shortened elsewhere.
- Suggested validation command: `rg -n "fleet|lane|distroless|certify|verify|VEX|exception|preview" docs/concepts README.md`.
- Priority: P1
- Effort: M
- Risk: Low.
- Dependencies: P1-02.
- Work type: docs-only.

## Phase 2: Proof Paths

Goal: make catalog evidence, signing/provenance/SBOM verification, CLI examples, and fork setup validation inspectable.

### P2-01: Add Trust Evidence Walkthrough

- ID: P2-01
- Title: Trace source to image to evidence to policy
- Problem: Trust evidence exists, but auditors must stitch it together manually.
- Evidence: `.github/workflows/release.yml:499-529`, `.github/workflows/release.yml:686-773`, `docs/security-model.md`, `docs/catalog-generator.md:115-127`, `docs/policy-bundles.md`.
- Why it matters: Security reviewers need a single path from source/build to image digest/SBOM/signature/provenance/catalog/policy.
- Recommended fix: Add an evidence walkthrough with exact commands and expected evidence artifacts.
- Target audience: Security/auditor, platform engineer.
- Files likely touched: new `docs/trust/evidence-walkthrough.md` or current `docs/security-model.md`, `README.md`.
- Acceptance criteria: A reviewer can verify one digest with cosign, locate SBOM/provenance, compare catalog record, and understand policy decision semantics.
- Suggested validation command: `rg -n "cosign verify|verify-attestation|SBOM|provenance|digest" docs README.md`.
- Priority: P0
- Effort: M
- Risk: Medium because commands need current release artifacts.
- Dependencies: P0-04.
- Work type: docs-only.

### P2-02: Add Or Document Evidence Manifest

- ID: P2-02
- Title: Centralize expected release evidence
- Problem: Evidence is split across raw catalog directories, summary fields, release assets, and workflow outputs.
- Evidence: `docs/catalog-generator.md:115-127`, `docs/catalog-schema.md:96-112`, `.github/workflows/release.yml:706-773`.
- Why it matters: Auditors want to know what evidence should exist and what is missing.
- Recommended fix: Add a per-release `evidence-manifest.json` concept or document the existing equivalent if one exists.
- Target audience: Security/auditor, platform engineer.
- Files likely touched: `docs/catalog-schema.md`, `docs/catalog-generator.md`, schemas, release workflow if implemented.
- Acceptance criteria: Each image release has a documented expected-evidence set: signature, SBOM, provenance, scan, tests, exceptions/VEX.
- Suggested validation command: `rg -n "evidence manifest|raw evidence|summary.json|attestation" docs schemas .github/workflows`.
- Priority: P1
- Effort: M
- Risk: Medium if schema changes.
- Dependencies: Owner decision on schema change vs docs-only convention.
- Work type: schema, workflow, docs-only.

### P2-03: Create Fork Setup Validation Path

- ID: P2-03
- Title: Prove the fork is wired before release
- Problem: Fork setup prerequisites are scattered.
- Evidence: `FORKING.md:8`, `FORKING.md:79`, `FORKING.md:98`, `clearcutt.fleet.yaml:40-80`, `cli/internal/commands/platform.go`.
- Why it matters: Platform engineers need to know whether their fork can operate before running a release.
- Recommended fix: Add a fork validation checklist using `platform status`, workflow identity checks, registry permissions, GitHub environments, secrets, and Pages/catalog settings.
- Target audience: Platform engineer, open-source evaluator.
- Files likely touched: `FORKING.md`, `docs/platform-kit.md`, `README.md`.
- Acceptance criteria: Fork owner can run one validation sequence and know what remains.
- Suggested validation command: `go -C cli run ./cmd/clearcutt platform status --output .. --fleet-config ../clearcutt.fleet.yaml`.
- Priority: P1
- Effort: S
- Risk: Low.
- Dependencies: Release identity decision.
- Work type: docs-only, CLI optional.

### P2-04: Make CLI Examples Executable And Current

- ID: P2-04
- Title: Align docs examples with real flags and current commands
- Problem: Some documented commands do not match CLI help.
- Evidence: `docs/site-generator.md:72-79` documents `catalog site build --include-services`; `go -C cli run ./cmd/clearcutt catalog site build --help` does not show that flag. `cli/internal/catalog/load.go:34` recommends `catalog gather`.
- Why it matters: Broken examples are fatal during early feedback.
- Recommended fix: Add docs snippet tests or at least a reviewed command matrix for README, getting started, site generator, catalog generator, and platform kit.
- Target audience: All audiences.
- Files likely touched: `docs/site-generator.md`, `docs/catalog-generator.md`, `README.md`, `cli/internal/catalog/load.go`, CI docs checks.
- Acceptance criteria: Every top-level command example is either tested or marked illustrative.
- Suggested validation command: `rg -n "clearcutt .*--include-services|catalog gather|catalog generate|catalog site build" README.md docs cli/internal`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: None.
- Work type: docs-only, CLI.

### P2-05: Add Catalog Evidence Walkthrough

- ID: P2-05
- Title: Explain what the catalog proves and does not prove
- Problem: The catalog looks like a trust portal but raw evidence can be optional or missing.
- Evidence: `site/src/pages/catalog.astro:107-153`, `site/src/pages/images/[id].astro:41`, `docs/catalog-schema.md:96-112`, `docs/catalog-generator.md:48-50`.
- Why it matters: The catalog is one of ClearCutt's strongest proof surfaces if it is honest.
- Recommended fix: Add a walkthrough of image detail pages, evidence badges, raw evidence, missing evidence, and degraded Generic OCI mode.
- Target audience: Security/auditor, app developer, engineering manager.
- Files likely touched: `docs/catalog-generator.md`, `docs/site-generator.md`, site copy, `docs/README.md`.
- Acceptance criteria: A reader can tell which badges are data reports, which are live verification results, and what missing data means.
- Suggested validation command: `rg -n "missing evidence|raw evidence|generic OCI|signature|provenance|SBOM" docs site/src`.
- Priority: P1
- Effort: M
- Risk: Low.
- Dependencies: P0-04, P2-01.
- Work type: docs-only, site-only.

## Phase 3: Product Polish

Goal: improve site IA, catalog details, sample app flows, screenshots/demo script, and generated-portal story.

### P3-01: Add Generated Portal Identity

- ID: P3-01
- Title: Make generated portals identify the fork/catalog owner
- Problem: The catalog site can read like a generic ClearCutt marketing site instead of a generated evidence portal for a specific fleet.
- Evidence: `docs/site-generator.md:3-18`, `site/src/pages/about.astro:104`, `site/src/pages/platform-kit.astro:16-18`, `site/src/lib/site-config.ts:202-307`.
- Why it matters: A generated portal should make ownership and evidence scope obvious.
- Recommended fix: Add configurable identity text: "This site renders catalog data for <owner>/<repo>; ClearCutt is the generator."
- Target audience: App developer, security/auditor, engineering manager.
- Files likely touched: `clearcutt.site.yaml`, `site/src/lib/site-config.ts`, shared layout/pages, `docs/site-generator.md`.
- Acceptance criteria: Generated sites visibly distinguish catalog owner, registry, source repo, generated timestamp, and ClearCutt tooling.
- Suggested validation command: `cd site && npm run build`.
- Priority: P1
- Effort: M
- Risk: Medium if templates/config contract changes.
- Dependencies: P0-03.
- Work type: site-only, schema optional.

### P3-02: Replace Marketing Labels With Evidence Labels

- ID: P3-02
- Title: Make site badges precise
- Problem: Current labels such as "VERIFIED KEYLESS" and "Vulnerability Free" sound stronger than catalog evidence.
- Evidence: `site/src/components/ProvenanceBlock.astro:317-321`, `site/src/components/VulnerabilityTable.tsx:402-405`, `site/src/components/CveDashboard.astro:92`.
- Why it matters: Trust UI must survive skeptical review.
- Recommended fix: Use labels like "catalog reports keyless signature", "no findings in current scan", and "provenance recorded."
- Target audience: Security/auditor, app developer.
- Files likely touched: Site components and generated template copies under `cli/internal/sitetemplate/template`.
- Acceptance criteria: Badges distinguish current scan results, catalog evidence, and live verification.
- Suggested validation command: `rg -n "VERIFIED KEYLESS|Vulnerability Free|SLSA LEVEL" site/src cli/internal/sitetemplate`.
- Priority: P1
- Effort: S
- Risk: Low.
- Dependencies: P0-04.
- Work type: site-only.

### P3-03: Add Realistic App Deployment Examples

- ID: P3-03
- Title: Show app images, not only base images
- Problem: Compose and Kubernetes examples point directly at base images, which does not model app-team adoption.
- Evidence: `examples/oci-deployment/docker-compose.yml:7`, `examples/k8s-deployment/deployment.yaml:21`, `docs/app-lifecycle.md:7-15`.
- Why it matters: App developers need to see how ClearCutt enters their app delivery path.
- Recommended fix: Add examples where an app image uses a ClearCutt base, is certified, and is admitted by policy.
- Target audience: App developer, platform engineer.
- Files likely touched: `examples/`, `docs/getting-started.md`, `docs/app-lifecycle.md`.
- Acceptance criteria: At least one Compose and one Kubernetes example use an app image derived from ClearCutt, not just a base runtime image.
- Suggested validation command: `rg -n "image: .*clearcutt|FROM .*clearcutt|certify" examples docs/getting-started.md`.
- Priority: P1
- Effort: M
- Risk: Medium if examples need runtime validation.
- Dependencies: P1-04.
- Work type: docs-only, site-only, CLI optional.

### P3-04: Add Demo Script And Screenshots

- ID: P3-04
- Title: Create a reviewer demo path
- Problem: Reviewers have no compact way to see the CLI, catalog, evidence page, and app path together.
- Evidence: Site and CLI surfaces exist, but README and docs require deep navigation.
- Why it matters: Human feedback sessions need a repeatable narrative.
- Recommended fix: Add a short demo script and screenshots or GIF references after truth cleanup.
- Target audience: Engineering manager, open-source evaluator, platform engineer.
- Files likely touched: `docs/demo.md`, `docs/README.md`, optional `docs/assets/`.
- Acceptance criteria: Demo can be run from a clean checkout and says which steps are fixture-backed vs live.
- Suggested validation command: `rg -n "demo|fixture|catalog|java21-distroless" docs`.
- Priority: P2
- Effort: M
- Risk: Low if assets are kept small.
- Dependencies: P1-03, P2-05.
- Work type: docs-only.

### P3-05: Add Category-Level Alternatives Page

- ID: P3-05
- Title: Explain ClearCutt vs alternatives without parity claims
- Problem: Build-vs-buy positioning is implicit.
- Evidence: `README.md:57`, `docs/enterprise-adoption.md:3`, external docs for Docker Hardened Images, Chainguard provenance, and Cloud Native Buildpacks.
- Why it matters: Managers need to know when not to use ClearCutt.
- Recommended fix: Add "Use ClearCutt when / do not use ClearCutt when" comparing categories: vendor hardened feed, buildpacks, DIY internal platform, and ClearCutt fork.
- Target audience: Engineering manager, platform engineer.
- Files likely touched: `README.md`, `docs/platform-kit.md`, `docs/enterprise-adoption.md`.
- Acceptance criteria: Page avoids vendor-by-vendor parity claims and makes ownership burden explicit.
- Suggested validation command: `rg -n "vendor|buildpacks|DIY|SLA|FIPS|STIG|support contract" README.md docs`.
- Priority: P1
- Effort: S
- Risk: Low, but must keep current external claims dated/cited if vendors are named.
- Dependencies: P0-03.
- Work type: docs-only.

## Phase 4: Technical Hardening

Goal: harden tests, workflow validation, schema validation, release pipeline correctness, and docs drift prevention.

### P4-01: Fix Release Job Permissions

- ID: P4-01
- Title: Add checkout-readable permissions to multi-arch assemble jobs
- Problem: Multi-arch assemble jobs override permissions but run checkout without `contents: read`.
- Evidence: `.github/workflows/release.yml:422`, `.github/workflows/release.yml:542`.
- Why it matters: Release can fail after single-arch publish and before manifest assembly.
- Recommended fix: Add `contents: read` to `assemble-multiarch` and `assemble-service-multiarch`.
- Target audience: Platform engineer, release engineer.
- Files likely touched: `.github/workflows/release.yml`.
- Acceptance criteria: `actions/checkout` has required permission in both jobs.
- Suggested validation command: `yq '.jobs."assemble-multiarch".permissions, .jobs."assemble-service-multiarch".permissions' .github/workflows/release.yml`.
- Priority: P0
- Effort: S
- Risk: Low.
- Dependencies: None.
- Work type: workflow.

### P4-02: Decide And Enforce Release Identity Policy

- ID: P4-02
- Title: Make releases main-only or explicitly multi-ref
- Problem: Non-main release dispatch conflicts with docs/config expectations.
- Evidence: `.github/workflows/release.yml:27`, `clearcutt.fleet.yaml:41`, `FORKING.md:79`, `.github/workflows/release.yml:767`.
- Why it matters: Signature identity is part of the trust boundary.
- Recommended fix: Either block non-main releases or document/configure trusted non-main identities and policy examples.
- Target audience: Security/auditor, platform engineer.
- Files likely touched: `.github/workflows/release.yml`, `clearcutt.fleet.yaml`, `FORKING.md`, policy docs.
- Acceptance criteria: Release workflow, fleet config, docs, and admission examples agree on trusted identities.
- Suggested validation command: `rg -n "refs/heads/main|github.ref|workflowIdentity|workflow-identity" .github/workflows clearcutt.fleet.yaml FORKING.md docs`.
- Priority: P1
- Effort: M
- Risk: Medium because identity policy can break existing release habits.
- Dependencies: Owner decision.
- Work type: workflow, docs-only.

### P4-03: Make Scheduled Remediation Fork-Safe

- ID: P4-03
- Title: Split scan/plan from AI patch drafting
- Problem: Weekly remediation workflow is write-capable and depends on `OPENROUTER_API_KEY`, but fork docs understate this.
- Evidence: `.github/workflows/scheduled-scan.yml:7`, `.github/workflows/scheduled-scan.yml:20`, `.github/workflows/scheduled-scan.yml:153`, `FORKING.md:107`.
- Why it matters: Fork owners should not get noisy or failing write-capable automation by default.
- Recommended fix: Make scan/plan default; gate AI patch drafting behind explicit opt-in and documented secrets.
- Target audience: Platform engineer, security/auditor.
- Files likely touched: `.github/workflows/scheduled-scan.yml`, `FORKING.md`, `docs/platform-kit.md`.
- Acceptance criteria: Fork with no AI provider secret can run scan/plan cleanly without drafting patches.
- Suggested validation command: `gh workflow run scheduled-scan.yml` in a fork without `OPENROUTER_API_KEY`.
- Priority: P1
- Effort: M
- Risk: Medium because workflow behavior changes.
- Dependencies: Owner decision on remediation default.
- Work type: workflow, docs-only.

### P4-04: Strengthen Policy Bundle Tests

- ID: P4-04
- Title: Test generated policy semantics, not substrings
- Problem: Policy generation claims exceed current generated policy proof.
- Evidence: `docs/policy-bundles.md:16-27`, `cli/internal/commands/policy.go:105-226`, `cli/internal/commands/policy_test.go`.
- Why it matters: Admission policy is a trust-critical surface.
- Recommended fix: Add tests that parse generated Kyverno/Gatekeeper output and prove required rules are present or explicitly label unsupported engines.
- Target audience: Security/auditor, platform engineer.
- Files likely touched: `cli/internal/commands/policy.go`, `cli/internal/commands/policy_test.go`, `docs/policy-bundles.md`.
- Acceptance criteria: Tests fail if required signature/provenance/digest/preview rules are missing from generated policy.
- Suggested validation command: `go -C cli test ./internal/commands -run Policy`.
- Priority: P1
- Effort: M
- Risk: Medium if policy scope is changed.
- Dependencies: P0-04, owner decision on Gatekeeper support.
- Work type: CLI, docs-only.

### P4-05: Add Docs Drift Checks For Commands

- ID: P4-05
- Title: Prevent command examples from drifting
- Problem: Docs contain command/flag mismatches.
- Evidence: `docs/site-generator.md:72-79`, `go -C cli run ./cmd/clearcutt catalog site build --help`, `cli/internal/catalog/load.go:34`.
- Why it matters: First feedback will fail fast on broken commands.
- Recommended fix: Add a lightweight CI check for documented commands or a generated command reference.
- Target audience: Open-source evaluator, app developer, platform engineer.
- Files likely touched: docs check script, `.github/workflows/pr-gate.yml`, docs.
- Acceptance criteria: PR gate catches nonexistent flags in high-traffic docs.
- Suggested validation command: `rg -n "clearcutt " README.md docs | scripts/validate-doc-commands.sh` or equivalent.
- Priority: P1
- Effort: M
- Risk: Medium due to false positives in illustrative snippets.
- Dependencies: P2-04 command cleanup.
- Work type: workflow, docs-only, CLI optional.

### P4-06: Pin Release And Catalog Tool Installers

- ID: P4-06
- Title: Remove live installer drift from CI paths
- Problem: Release/catalog workflows download tools or fall back to installs that can change without repo changes.
- Evidence: `.github/workflows/publish-pages.yml:70`, `.github/workflows/release.yml:734`, `.github/workflows/publish-pages.yml:175`.
- Why it matters: Reproducibility and incident response depend on pinned toolchains.
- Recommended fix: Pin versions, verify checksums, and avoid `npm install` fallback in CI publish paths.
- Target audience: Platform engineer, security/auditor, release engineer.
- Files likely touched: `.github/workflows/release.yml`, `.github/workflows/publish-pages.yml`.
- Acceptance criteria: Release and Pages workflows do not use unverified `install.sh` or unpinned fallback install behavior.
- Suggested validation command: `rg -n "install.sh|npm ci \\|\\| npm install|curl -fsSL" .github/workflows`.
- Priority: P2
- Effort: M
- Risk: Medium because CI setup can break.
- Dependencies: None.
- Work type: workflow.
