# ClearCutt Human Feedback Readiness Audit

Date: 2026-06-07

Status: historical audit snapshot. The readiness verdicts and P0/P1 blocker language in this file describe the repo before the post-audit hardening pass. For the current branch state, use `docs/analysis/post-hardening-readiness.md`.

Scope: read-only product, technical, documentation, site, CLI, release, and trust audit. This report synthesizes independent reviews from `product_strategist`, `platform_engineer`, `app_developer`, `security_auditor`, `cli_reviewer`, `catalog_site_reviewer`, `release_engineer`, `docs_architect`, `competitive_reviewer`, and `brutal_skeptic`, plus local command and file checks. No product files were changed.

## 1. Executive Readout

ClearCutt is best described as a forkable platform kit and production-oriented reference implementation for teams that want to own a hardened container image fleet, its evidence trail, and its adoption path. It is not primarily a hosted product, not only a catalog generator, not only an image factory, and not only a governance CLI. Those are subsystems inside the broader platform kit.

The strongest current story is already visible in `README.md:12-21`: fork the repo, publish under your registry, keep your GitHub Actions OIDC identities, keep your own review process, and avoid a hosted ClearCutt control plane. The repo also has real implementation depth: release workflows in `.github/workflows/release.yml`, catalog generation and validation in `cli/internal/commands/catalog_*.go`, an Astro evidence portal in `site/`, app-team commands under `clearcutt app`, certification gates under `clearcutt certify` and `clearcutt verify`, and policy/remediation examples.

The project is not ready for broad, serious human feedback until the first surfaces tell the truth more tightly. The opening story is understandable in roughly 60 seconds, but the proof story is weakened by universal claims like "every image signed, attested" in `README.md:3`, "supply-chain verified ... in under 5 minutes" in `site/src/pages/getting-started.astro:48`, security phrases like "SLSA level-3 non-falsifiable build provenance" in `docs/security-model.md:10`, and UI labels like "VERIFIED KEYLESS" and "Vulnerability Free" in `site/src/components/ProvenanceBlock.astro:317` and `site/src/components/VulnerabilityTable.tsx:402`. Some of those claims are directionally backed by workflows, but they are broader than what a clean checkout, ignored generated catalog data, and local fixture paths prove.

The smallest useful thing ClearCutt does today is not the whole platform. It is: build or run the CLI, inspect a fixture-backed catalog, validate catalog structure, inspect an image record, and run catalog-policy verification against an image with recorded evidence. Locally verified examples include `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list`, `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog catalog validate`, `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless`, and `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --max-critical 0 --max-high 3 --allow-preview`. That path is useful, but the README and site do not make it the obvious first path.

The repo has enough substance for targeted feedback from platform engineers and security reviewers who are willing to read deeply. It is not yet ready for broad external evaluation because the first-run path, claim boundaries, generated portal identity, and trust verification story need cleanup first.

### Required Question Answers

| Question | Answer |
|---|---|
| What is ClearCutt? | A forkable platform kit and reference implementation for owning hardened image builds, registry publication, evidence, catalog, policy examples, and app-team adoption workflows. |
| Who is it for? | Platform engineers, app developers, security/auditors, engineering managers, and open-source evaluators. Each audience has a real reason to care, but each needs a clearer path. |
| What is the smallest useful thing it does today? | Fixture-backed catalog inspection, validation, image detail inspection, catalog-policy verification, and app-template/devcontainer scaffolding. The full fork-operated release system is more ambitious and requires setup. |
| Is it a product, blueprint, reference implementation, catalog generator, image factory, governance CLI, or platform kit? | It should be positioned as a platform kit and reference implementation. Catalog generator, image factory, governance CLI, evidence portal, and app workflow are components. |
| Is the current top-level story understandable in 60 seconds? | Mostly yes through `README.md:12-38`; no after the README expands into command inventory and mixed audience detail from `README.md:186-607`. |
| What claims are proven by the repo? | Fork-owned control plane, data-backed catalog generation, catalog validation, site rendering from catalog data, release workflow wiring for signing/attestation when configured, app template scaffolding, and fixture-backed verification. |
| What claims are ahead of implementation? | Universal image signing/attestation, production-complete admission policy, service images as first-class production-ready lane, "supply-chain verified in under 5 minutes", and UI labels implying cryptographic verification where catalog metadata is being displayed. |
| What feels credible? | The two-loop model, workflow depth, schema work, catalog evidence pages, fixture-backed tests, conservative limitations page, and fork-owner framing. |
| What feels like marketing? | "Every image signed, attested", "enterprise base images", "mission-critical production", "highly secure", "maximum protection", "Vulnerability Free", "VERIFIED KEYLESS", and "non-falsifiable" without nearby verification commands and caveats. |
| What would block a platform engineer from trying it? | First-run ambiguity, ignored generated catalog data, missing-catalog guidance that says `catalog gather` while docs say `catalog generate`, release identity ambiguity, and operational prerequisites scattered across docs. |
| What would block a security person from trusting it? | `verify image` reads like cryptographic verification but checks catalog-record fields, admission policy examples are scaffolded, evidence manifests are not centralized, and some claims exceed recorded evidence. |
| What would block an app developer from adopting it? | Too many platform concepts before the app path, Nix leakage into app-team surfaces, examples based on base images instead of app images, and weak app-template README output. |
| What should be fixed before human feedback? | Truth/positioning cleanup, first-run fixture-backed path, docs front door, readiness matrix, trust verification path, and high-risk workflow/doc mismatches. |
| What should be cut, moved deeper, renamed, or deferred? | Move most README command inventory deeper, label service images preview, rename BYO overlay as a migration bridge, move Nix-heavy material to platform-owner docs, and defer production-complete admission claims. |

## 2. Strongest Parts Of The Project

- Fork-owner positioning is strong. `README.md:12-21` and `site/src/lib/claims.ts:14` correctly frame ClearCutt as something the adopter operates under their registry, workflow identity, and review process.
- The repo has real platform machinery. `.github/workflows/release.yml:69` gates release through a production environment, `.github/workflows/release.yml:499-529` signs and attests image artifacts, `.github/workflows/release.yml:686-773` wires SLSA and verification, `.github/workflows/publish-pages.yml:120-142` rebuilds catalog data, and `.github/workflows/rebase.yml:1-7` documents dual-control app rebase intent.
- The catalog model is substantial. `docs/catalog-generator.md:3-11` separates portable catalog generation from the full release evidence pipeline, `docs/catalog-schema.md:50-68` documents index metadata, and `schemas/catalog-index.v2.schema.json:187-228` models image kind, evidence, lifecycle, runtime contract, service metadata, and vulnerability summary.
- The Astro catalog site has the right evidence shape. `site/src/pages/images/[id].astro:41` composes image header, usage, provenance, vulnerability, SBOM, layer, label, and history sections. `site/src/lib/catalog.ts:15` supports `public/catalog` and `src/data/catalog`, which fits generated portal use.
- App-team adoption is visible even if not yet cleanly fronted. `README.md:36` says app developers do not need Nix, `cli/internal/commands/app_template.go:148-155` generates Dockerfile, devcontainer, policy, workflow, and README files, and `docs/certification.md:37-53` is honest about offline certification skips.
- The project already contains claim-boundary thinking. `docs/security-model.md:57-61` disclaims FIPS and zero-risk claims, `docs/generic-oci-mode.md:88` says missing evidence remains missing in generic OCI mode, and `docs/service-images.md:59-74` labels service images preview/non-production.
- Competitive positioning can be credible if it centers ownership. Current Docker Hardened Images docs advertise minimal images, near-zero CVEs, SLSA Build L3 provenance, drop-in adoption, FIPS/STIG variants, and SLA-backed patching; Chainguard documents cosign attestation verification; Buildpacks position source-to-image workflows without Dockerfiles. ClearCutt should not pretend those primitives are unique. Its credible differentiator is fork-owned workflow identity, registry, catalog, policy, and review process. Sources: [Docker DHI](https://docs.docker.com/dhi/), [Chainguard provenance](https://images.chainguard.dev/directory/image/task/provenance), [Cloud Native Buildpacks](https://buildpacks.io/).

## 3. Biggest Credibility Risks

1. P0 - Universal evidence claims are ahead of proof. `README.md:3` says every image is signed and attested. Release workflow wiring supports signed and attested publication when configured, but ignored local catalog data and fixture catalogs do not prove universal completeness. `site/.gitignore:5-7` ignores `site/src/data/catalog/index.json`, `site/src/data/catalog/images/`, and `site/src/data/enrichment/`, so local generated catalog state is not clean-clone truth.

2. P0 - Catalog freshness and first-run truth are confused. `README.md:197-201` says catalog data is required and not committed, while `site/README.md:19-21` says the site can read checked-in catalog data. The default missing-catalog error in `cli/internal/catalog/load.go:25-38` recommends `clearcutt catalog gather`, while newer docs emphasize `clearcutt catalog generate` in `README.md:132` and `docs/catalog-generator.md:3`.

3. P0 - `verify image` wording blurs catalog policy checks with cryptographic verification. `README.md:236-255` presents `verify image` near evidence claims, but `cli/internal/commands/verify.go:189`, `verify.go:204`, and `verify.go:220` check catalog-record fields. Real cosign/SBOM/provenance verification is in release evidence paths such as `cli/internal/commands/verify_release_evidence.go:120-155` and `.github/workflows/release.yml:706-773`.

4. P0 - Admission policy is over-presented. `docs/policy-bundles.md:16-27` describes production/strict policies, but `cli/internal/commands/policy.go:105-146` emits a Gatekeeper placeholder that does not cryptographically verify signatures or attestations, and `cli/internal/commands/policy.go:148-226` emits Kyverno rules without the full preview/service policy story implied by docs.

5. P0 - Release workflow may have a real release-blocking permissions issue. `assemble-multiarch` and `assemble-service-multiarch` define job-level permissions without `contents: read` before running `actions/checkout` at `.github/workflows/release.yml:422` and `.github/workflows/release.yml:542`. `actionlint` can pass while the runtime job still fails.

6. P1 - Site labels overstate trust state. `site/src/components/ProvenanceBlock.astro:317-321` says `VERIFIED KEYLESS`, `site/src/components/ProvenanceBlock.astro:398-402` says `SLSA LEVEL`, and `site/src/components/VulnerabilityTable.tsx:402-405` says `Vulnerability Free`. Those labels should distinguish "reported in catalog" from "verified now against registry transparency/evidence."

7. P1 - Service images read more first-class than they are. `README.md:181` says the service lane includes Postgres, Valkey, and oauth2-proxy. `clearcutt.fleet.yaml:86-152` marks services `preview` and `productionAllowed: false`; `docs/service-images.md:59-74` agrees. Treat service images as preview/scaffolded until the default generated catalog and evidence make them first-class.

8. P1 - Release identity rules are ambiguous for non-main dispatch. `.github/workflows/release.yml:27` allows non-main refs, `clearcutt.fleet.yaml:41` pins release identity to `refs/heads/main`, `FORKING.md:79` tells forks to trust main, and `.github/workflows/release.yml:767` verifies dynamically with `${{ github.ref }}`.

## 4. Biggest Comprehension Risks

- The README starts well but does too much. The strong overview lives in `README.md:12-159`; command reference and deployment examples then run through `README.md:607`, turning the first page into product page, operator manual, CLI reference, app guide, schema guide, Kubernetes guide, and OpenShift guide.
- There is no docs front door. The docs directory is flat, and there is no `docs/README.md` that routes app teams, platform owners, security reviewers, managers, and open-source evaluators to the right first path.
- Role paths overlap. `README.md:82-142` has first paths, `docs/getting-started.md:3-31` has an app-focused start, `docs/platform-kit.md:19-53` has an operator golden path, and `FORKING.md:8` has fork setup. Readers have to infer which is canonical.
- Terms are repeated but not canonical. `dev`, `slim`, `distroless`, `fleet`, `lane`, `catalog`, `evidence`, `service image`, `runtime line`, `rebase`, `exception`, and `VEX` are defined across README and several docs but not in one glossary.
- App-team copy still leaks platform-owner machinery. `site/src/components/MatrixGrid.astro:255` exposes "Nix Blueprint" and `site/src/components/UsageTabs.astro:399-404` includes Nix-oriented tabs near app usage.
- Generated portal identity is blurred. `docs/site-generator.md:3-18` calls the site a catalog renderer, but `site/src/pages/about.astro:104` and `site/src/pages/platform-kit.astro:16-18` read like ClearCutt product marketing. A generated portal should identify the fork/catalog owner first and ClearCutt as the renderer/tooling.

## 5. Audience-By-Audience Analysis

| Audience | Score | What works | Main blocker |
|---|---:|---|---|
| Platform engineer | 3/5 | Fork-owned registry/workflow story, release workflow depth, `platform status`, fleet config, catalog generator, and policy/remediation surfaces are real. | First-run path and operational burden are scattered; ignored generated catalog data and release identity ambiguity make evaluation feel fragile. |
| App developer | 3/5 | "No Nix required" promise, app template/devcontainer generation, Docker/Podman/Kubernetes usage snippets, certification docs, and catalog browsing all point in the right direction. | Too many platform concepts before a useful app flow; examples use base images more than app images; template README is thin; Nix leaks into UI. |
| Security/auditor | 3/5 | Release workflow has signing, SBOM, provenance, verification, exceptions, VEX, policy examples, and catalog evidence surfaces. | Catalog flags are conflated with cryptographic verification, admission policies are scaffolded, evidence manifests are decentralized, and claims are too absolute. |
| Engineering manager | 3/5 | Ownership-vs-vendor story is compelling; "no hosted control plane" and two-loop framing help explain why it exists. | Build-vs-buy tradeoffs, operational burden, support responsibilities, and what is currently implemented vs planned are not explicit enough. |
| Open-source evaluator | 3/5 | Repo is coherent, has Go/Astro tests, schemas, workflows, fixtures, and real docs. | Clean-clone first run is not obvious, README is too long, and local generated artifacts can mask what a new evaluator will actually see. |

## 6. Claim-Vs-Proof Table

| Claim | Where claim appears | Current proof | Classification | Gap | Risk | Recommended fix |
|---|---|---|---|---|---|---|
| ClearCutt is a free, open-source, forkable platform kit. | `README.md:12`, `docs/platform-kit.md:1-6`, `site/src/lib/claims.ts:1-14` | Repo contains CLI, workflows, fleet config, catalog schema/site, examples, and fork docs. | Mostly proven | Fork setup success depends on secrets, Actions, registry, and platform capacity. | Keep as lead claim, add operational burden box and first fork validation path. |
| No hosted ClearCutt control plane. | `README.md:19`, `site/src/lib/claims.ts:14` | Workflows and registry are repo/fork-owned; no server component is present. | Proven | Some site copy still reads like a product site rather than a generated portal. | Preserve claim and clarify "your fork is the product surface." |
| Every image is signed and attested. | `README.md:3`, `README.md:58` | Release workflow signs/attests in `.github/workflows/release.yml:499-529`; SLSA verification exists in `.github/workflows/release.yml:686-773`. | Misleading | Ignored local catalog state and fixture data do not prove universal completeness; some surfaces report incomplete evidence. | Reword to "published releases are configured to produce signatures, SBOMs, and provenance; catalog reports missing evidence independently." |
| App developers do not need to learn Nix. | `README.md:36`, `docs/getting-started.md:14-20` | App templates emit Dockerfile/devcontainer/workflow assets in `cli/internal/commands/app_template.go:148-155`; app docs cover Docker-style flows. | Mostly proven | Nix appears in usage tabs and matrix UI; app quickstart still asks too much too soon. | Move Nix to platform-owner docs and make app path Docker/Podman/Cosign first. |
| Catalog generator emits portable evidence data. | `docs/catalog-generator.md:3-11`, `docs/catalog-schema.md:50-68` | `catalog generate`, `validate`, `summarize`, `diff`, and `inspect` exist; schema v2 covers evidence and summaries. | Proven | Command docs and missing-catalog error still mix `gather` and `generate`. | Standardize command guidance and use fixture-backed clean-clone examples. |
| Generated catalog site is a renderer for catalog data. | `docs/site-generator.md:3-18`, `site/src/lib/catalog.ts:15` | Site can read catalog data from `public/catalog` and `src/data/catalog`; generated template exists. | Mostly proven | Product marketing pages blur renderer vs ClearCutt project site. | Add portal identity band and config-driven owner/catalog language. |
| `verify image` verifies trust evidence. | `README.md:236-255`, CLI help under `verify` | CLI checks catalog booleans and vulnerability thresholds; release verifier performs registry-side cosign checks elsewhere. | Partially implemented | Name and docs imply cryptographic verification when command is mostly catalog-policy gating. | Rename docs framing to "catalog policy gate"; add separate release-evidence cryptographic verification path. |
| Admission policies enforce signatures/SLSA. | `docs/policy-bundles.md:16-27`, `examples/k8s-deployment/kyverno-policy.yaml` | Static Kyverno example is stronger; generated Gatekeeper output in `cli/internal/commands/policy.go:105-146` is placeholder. | Scaffolded | Generated policy is not production-complete; tests are mostly substring checks. | Label policies as examples, improve Kyverno tests, caveat or defer Gatekeeper. |
| Service images are part of the platform. | `README.md:181`, `docs/service-images.md:59-88`, `clearcutt.fleet.yaml:86-152` | Config and generator support service records; mixed fixture covers service display. | Scaffolded | Services are preview/non-production and may be absent from default clean catalog. | Present as preview lane until current catalog evidence and workflows prove it. |
| Remediation workflow exists. | `.github/workflows/scheduled-scan.yml`, `docs/platform-kit.md:65-73` | Scheduled scan and remediation dispatcher exist; docs say it drafts PRs and does not silently merge/deploy. | Partially implemented | Fork prerequisites and AI secret requirements are hidden; workflow is write-capable by default. | Split scan/plan from AI patch drafting; document fork-owner prerequisites. |
| Rebase preserves app layers while updating base. | `docs/app-lifecycle.md:68-98`, `.github/workflows/rebase.yml:1-7`, `cli/internal/commands/app_rebase.go` | CLI and workflow encode dual-control and rebase flow. | Mostly proven | Single-artifact path is narrower than product story; raw refs need candidate metadata. | Keep as advanced app path with exact prerequisites and local validation command. |
| Generic OCI mode can inventory external images. | `docs/generic-oci-mode.md:79-88`, `docs/catalog-generator.md:48-50` | Docs explicitly say missing evidence remains missing; generator supports `images.yaml`. | Mostly proven | Could be mistaken for full-trust inventory if surfaced too high. | Keep as degraded-evidence mode and route security claims away from it. |
| BYO base overlay supports enterprise-mandated bases. | `docs/byo-base-images.md:3`, `cli/internal/commands/overlay.go:33` | Generator emits Containerfile, tests, policy, and workflows for overlays. | Partially implemented | Language can imply hardened equivalence to native ClearCutt runtimes. | Position as migration bridge with separate inherited-risk evidence. |
| CLI release assets have release evidence. | `.github/workflows/release.yml:360`, `cli/internal/commands/fleet.go:799` | CLI assets are cross-compiled, signed, checksummed, and uploaded. | Partially implemented | No CLI SBOM/provenance/attestation comparable to images. | Add CLI evidence or narrow "release evidence" wording to image artifacts. |
| Release pipeline is production-oriented. | `.github/workflows/release.yml:69`, `.github/workflows/release.yml:499-773` | Production gate, matrix builds, signatures, attestations, SLSA, verification, and finalization are wired. | Mostly proven | Multi-arch jobs likely miss `contents: read`; non-main identity unclear. | Fix workflow permissions and decide release identity policy before broad feedback. |

## 7. Feature/Readiness Matrix

| Capability | Current state | Evidence | User value | Risk | Next action |
|---|---|---|---|---|---|
| Fork-owned platform kit | Implemented but setup-heavy | `README.md:12-21`, `FORKING.md:8`, `clearcutt.fleet.yaml` | Lets platform teams own registry, workflows, evidence, and review. | Fork prerequisites are scattered. | Add fork validation path and burden checklist. |
| Runtime image factory | Implemented/reference fleet | `.github/workflows/release.yml`, `nix/`, `clearcutt.fleet.yaml:23-39` | Reproducible platform-owned runtime images. | Build infra and release identity complexity. | Keep as platform-owner lane, not app-team first step. |
| Release signing and attestations | Implemented when workflow succeeds | `.github/workflows/release.yml:499-529`, `.github/workflows/release.yml:686-773` | Evidence-backed release path. | Universal claim exceeds observed catalog proof. | Qualify claims and add evidence walkthrough. |
| Catalog generation | Implemented | `docs/catalog-generator.md`, `cli/internal/commands/catalog_generate.go`, schemas | Portable catalog data and validation. | `gather` vs `generate` drift. | Standardize command language. |
| Catalog validation/summarization | Implemented | Local `catalog validate` and `catalog summarize` fixture runs; `docs/catalog-schema.md` | Gives evaluators a small proof path. | Not obvious as first command. | Put fixture-backed path in README/docs index. |
| Astro catalog site | Implemented | `site/src/pages/catalog.astro`, `site/src/pages/images/[id].astro`, `docs/site-generator.md` | Human-readable evidence portal. | Generated portal identity is blurred with product marketing. | Add owner/catalog identity and conservative labels. |
| App template | Implemented but thin docs | `cli/internal/commands/app_template.go:148-155`, `examples/clearcutt-template-java/README.md:3-12` | Paved app-team adoption path. | Output README is too thin for real app teams. | Make app quickstart template-first and expand template README. |
| Devcontainer generation | Implemented/scaffolded | `cli/internal/commands/app_template.go:428`, `clearcutt dev` fixture smoke | App teams can get a dev image path without Nix. | Underexplained; default catalog missing can block it. | Document no-install fixture path and catalog dependency. |
| Certification gate | Implemented with caveats | `docs/certification.md:37-53`, `cli/internal/commands/certify*` | Local app image checks before CI/admission. | PASS can include skipped evidence checks offline. | Make skipped checks visible in first-run docs. |
| `verify image` | Implemented as catalog policy gate | `cli/internal/commands/verify.go` | Quick gate over catalog evidence and vulnerability thresholds. | Name/docs imply cryptographic verification. | Reframe docs; add separate cosign proof path. |
| Policy bundle generation | Scaffolded | `docs/policy-bundles.md`, `cli/internal/commands/policy.go` | Admission-control examples. | Gatekeeper output is placeholder; generated policies not production-complete. | Label examples and strengthen tests. |
| Service images | Preview/scaffolded | `clearcutt.fleet.yaml:86-152`, `docs/service-images.md:59-74` | Shows platform can extend beyond runtimes. | Over-presented as current first-class lane. | Keep preview until catalog/workflow proof is current. |
| Remediation workflow | Scaffolded/partially implemented | `.github/workflows/scheduled-scan.yml`, `docs/platform-kit.md:65-73` | Turns scans into reviewable PRs. | Hidden AI secret and write permissions after fork. | Make AI patch drafting opt-in. |
| App rebase | Implemented advanced path | `.github/workflows/rebase.yml`, `docs/app-lifecycle.md:68-98` | Updates app base without full app rebuild. | Narrow prerequisites and dual-control complexity. | Keep advanced, add exact validation recipe. |
| Generic OCI mode | Implemented degraded mode | `docs/generic-oci-mode.md`, `images.yaml` path | Lets teams catalog non-ClearCutt images. | Could dilute trust story. | Keep lower in docs with missing-evidence warnings. |
| CLI release assets | Partially evidenced | `.github/workflows/release.yml:360`, `cli/internal/commands/fleet.go:799` | Downloadable CLI for users. | Signed/checksummed but not SBOM/provenance like images. | Add CLI provenance or qualify release-evidence wording. |

## 8. Docs/Site/CLI Friction Points

| Surface | Evidence | Friction | Fix direction |
|---|---|---|---|
| README | `README.md:186-607` | Too much command/reference content on first page. | Keep identity, first path, and proof links; move reference deeper. |
| Getting started | `docs/getting-started.md:3-31`, `site/src/pages/getting-started.astro:48` | App start says under 5 minutes but still introduces too many concepts and overclaims verification. | Make fixture/template/certify path first and qualify "verified." |
| Docs IA | No `docs/README.md`; flat docs directory | No audience routing. | Add docs front door with role paths and readiness map. |
| Missing catalog error | `cli/internal/catalog/load.go:25-38` | Recommends `catalog gather` while docs promote `catalog generate`. | Align CLI error, README, and catalog docs. |
| Catalog site build docs | `docs/site-generator.md:72-79` | Documents `catalog site build --include-services`, but `go -C cli run ./cmd/clearcutt catalog site build --help` does not show that flag. | Fix docs or add flag intentionally. |
| CLI root help | `cli/internal/commands/root.go:26-28` | Says "enterprise base images"; this invites broad enterprise-grade expectations. | Use "platform-owned base images" or similar. |
| App help | `cli/internal/commands/app.go:30` | Says only app commands need network, while other surfaces also touch network. | Reword as app-specific note, not global guarantee. |
| Site claims | `site/src/lib/image-metadata.ts:96`, `:112`, `:164`, `:187` | "mission-critical", "highly secure", "maximum protection" exceed proof. | Replace with observable traits such as shell-free, minimal, policy-gated, current scan evidence. |
| Trust UI labels | `site/src/components/ProvenanceBlock.astro:317`, `site/src/components/VulnerabilityTable.tsx:402` | Labels sound verified/current rather than catalog-reported. | Use "catalog reports keyless signature" and "no findings in current scan." |
| Examples | `examples/oci-deployment/docker-compose.yml:7`, `examples/k8s-deployment/deployment.yaml:21` | Examples point directly at base images more than app images. | Add realistic app image examples and keep base-image examples lower. |

## 9. Trust And Security Model Gaps

- Separate evidence record checks from cryptographic verification. `verify image` should be documented as a catalog policy gate unless it actually invokes cosign/SBOM/provenance verification against registry artifacts.
- Add a clear trust walkthrough: source commit to GitHub workflow identity to image digest to SBOM to provenance to signature to catalog record to policy decision. Existing pieces live in `.github/workflows/release.yml`, `docs/security-model.md`, `docs/catalog-generator.md`, `docs/exceptions-and-vex.md`, and `docs/policy-bundles.md`, but no single path lets an auditor trace it end to end.
- Introduce or document an evidence manifest. `docs/catalog-generator.md:115-127` discusses independent evidence channels, and `docs/catalog-schema.md:96-112` allows summary/raw evidence to be empty. Auditors need a per-release index of expected evidence and verification status.
- Soften SLSA and hermetic language. `docs/security-model.md:10` and `docs/security-model.md:27` should describe configured mechanisms and trust boundaries, not absolute guarantees.
- Fix VEX semantics. `docs/exceptions-and-vex.md:24-30` and `cli/internal/commands/vex.go:57` collapse accepted risk into `not_affected`, which can mislead auditors. Accepted risk and false positive are different governance states.
- Label policy bundles as examples until generated policies and tests prove enforcement. Static Kyverno examples are useful; generated Gatekeeper policy is not production-complete.
- Decide release identity policy. Non-main releases should either be blocked or explicitly supported with trusted identities, docs, and policy examples.

## 10. First-Run Evaluator Path Review

Current first-run friction:

1. A clean clone lacks default catalog data because `site/.gitignore:5-7` ignores generated catalog files.
2. `go -C cli run ./cmd/clearcutt list` fails without a catalog and the error recommends `clearcutt catalog gather`, while newer docs recommend `catalog generate`.
3. README later shows default commands without `--catalog`, which can fail before a new evaluator sees value.
4. Site getting-started examples can reference configured future/current lines that local generated catalog data may not contain.
5. The README asks readers to learn platform, release, catalog, app, policy, and Kubernetes concepts before they have one clean success.

Recommended first-run path before human feedback:

```sh
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog catalog validate
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --max-critical 0 --max-high 3 --allow-preview
go -C cli run ./cmd/clearcutt --catalog internal/testdata/dev-catalog dev java21-distroless --devcontainer --print
```

This does not prove the whole platform. It proves the smallest useful loop: catalog data can be read, inspected, validated, and used to make a policy decision, and app teams can derive a devcontainer from catalog data.

Platform-owner first-run should then branch to `go -C cli run ./cmd/clearcutt platform status --output .. --fleet-config ../clearcutt.fleet.yaml`, fork setup in `FORKING.md`, and the release/catalog workflow docs.

Security first-run should branch to a separate digest-pinned release-evidence walkthrough using cosign, SBOM attestation verification, provenance verification, and catalog comparison.

## 11. Human-Feedback Readiness Score

Overall score: 3/5.

ClearCutt is ready for targeted feedback from trusted reviewers who can tolerate caveats and read the repo deeply. It is not ready for broad public feedback from new evaluators because the first-run path and public claims still create avoidable credibility risk.

Readiness by dimension:

| Dimension | Score | Reason |
|---|---:|---|
| Product story | 3/5 | Strong forkable-platform thesis, but README/site still blur product, blueprint, catalog, image factory, and governance CLI. |
| Technical implementation | 3/5 | Real workflows, CLI, schema, site, and fixtures; release permissions, policy generation, and fork prerequisites need hardening. |
| Documentation | 2/5 | Many useful docs, but no docs front door, glossary, readiness matrix, or single canonical first-run path. |
| Site/catalog UX | 3/5 | Evidence pages are useful; generated portal identity and labels need truth cleanup. |
| CLI UX | 3/5 | Command grouping is mostly coherent; examples, missing-catalog guidance, and help text need alignment. |
| Trust/auditability | 3/5 | Evidence machinery exists; claims must distinguish catalog-reported, workflow-configured, and cryptographically verified states. |

## 12. Recommended Next Steps

1. Do Phase 0 truth and positioning cleanup before any implementation polish. Remove or qualify universal signing/SLSA/security claims, label service images preview, distinguish catalog gates from cryptographic verification, and make external-alternative positioning honest.
2. Do Phase 1 first-run comprehension next. Add a docs front door, shorten README, define a fixture-backed first path, add glossary/readiness matrix, and route each audience to one command path.
3. Do Phase 2 proof paths after the story is truthful. Build a trust walkthrough, release-evidence verification recipe, catalog evidence walkthrough, and fork validation checklist.
4. Do Phase 3 product polish only after the truth path is stable. Improve generated portal identity, information architecture, app examples, screenshots/demo script, and service preview story.
5. Do Phase 4 technical hardening in parallel with targeted implementation work. Fix release permissions, command/doc mismatches, policy test depth, docs drift checks, and live installer/fallback reproducibility risks.
