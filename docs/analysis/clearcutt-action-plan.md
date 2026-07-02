# ClearCutt Action Plan: Release-Ready CLI-First Fleet

Date: 2026-06-30

## P0 action items

### CC-P0-01: Normalize release and runtime version references

- **Problem:** App templates, docs, site pages, and examples disagree on current ClearCutt release and Python runtime lines.
- **Evidence:** `cli/internal/commands/app_template.go`, `docs/app-lifecycle.md`, `site/src/pages/app-lifecycle.astro`, `examples/clearcutt-template-python/README.md`.
- **Recommended fix:** Pick canonical current release/runtime examples and update generator constants, checked-in examples, docs, and site together.
- **Audience impacted:** App developers, open-source evaluators, security reviewers.
- **Priority:** P0
- **Effort:** M
- **Risk:** Reviewers infer the project is stale or internally inconsistent.
- **Files likely involved:** `cli/internal/commands/app_template.go`, `docs/app-lifecycle.md`, `docs/certification.md`, `site/src/pages/app-lifecycle.astro`, `site/src/pages/cli.astro`, `examples/clearcutt-template-*`.
- **Acceptance criteria:** `rg "python3\\.1|v0\\."` shows only intentional current or historically explained references.
- **Suggested validation command:** `go -C cli test ./internal/commands -run 'AppTemplate|Catalog' && cd site && npm run typecheck`
- **Type:** cross-cutting

### CC-P0-02: Publish durable release verification artifacts

- **Problem:** `fleet verify-target` now writes and uploads durable `*.release-verification.json` evidence, but catalog ingestion and the public evidence story still need to surface that checklist consistently.
- **Evidence:** `.github/workflows/release.yml` runs verification; `cli/internal/commands/fleet.go` finalizes release assets without a verification checklist artifact.
- **Recommended fix:** Emit `fleet verify-target --format json` per image, upload it to the GitHub Release, and link it from `evidence-manifest.json`.
- **Audience impacted:** Security engineers, auditors, platform engineers.
- **Priority:** P0
- **Effort:** M
- **Risk:** The project can say verification happened, but users cannot inspect a durable verification result later.
- **Files likely involved:** `cli/internal/commands/fleet.go`, `cli/internal/commands/catalog_evidence_manifest.go`, `.github/workflows/release.yml`, `site/src/components/VerifyBlock.astro`.
- **Acceptance criteria:** Each released image has a machine-readable verification artifact linked from catalog evidence.
- **Suggested validation command:** `go -C cli test ./internal/commands -run 'VerifyReleaseEvidence|Fleet|CatalogEvidence'`
- **Type:** CLI, workflow, site

### CC-P0-03: Single-source registry configuration

- **Problem:** Registry host selection must not drift between image naming, release login, catalog enrichment, and default rebase login.
- **Evidence:** `clearcutt.fleet.yaml` has registry config; `platform registry-env` emits host/user/auth-mode outputs consumed by release, catalog, and rebase workflows.
- **Recommended fix:** Keep `registry.host` as the source of truth; add second-registry tests before broadening support claims beyond GHCR.
- **Audience impacted:** Platform engineers, security reviewers.
- **Priority:** P0
- **Effort:** M
- **Risk:** Fork owners misconfigure non-GHCR auth or assume unproven registry evidence behavior.
- **Files likely involved:** `clearcutt.fleet.yaml`, `cli/internal/fleet/config.go`, `cli/internal/commands/platform.go`, `.github/workflows/release.yml`, `.github/workflows/publish-pages.yml`, `docs/registry-swap.md`.
- **Acceptance criteria:** One config value drives image names, workflow auth host, catalog enrichment, and docs examples; non-GHCR support remains tiered until proven.
- **Suggested validation command:** `go -C cli test ./internal/fleet ./internal/commands -run 'Registry|Platform|Fleet'`
- **Type:** cross-cutting

### CC-P0-04: Add fork/platform readiness preflight

- **Problem:** Fork owners need one preflight that combines local wiring with GitHub settings before first release.
- **Evidence:** `platform doctor --github` now runs local `platform status` checks, verifies local workflow permission contracts, and uses `gh` to check repository reachability, default branch, Actions, workflow permissions, production environment, Pages, registry credentials, optional remediation AI secret readiness, and configured Nix cache secrets.
- **Recommended fix:** Keep `platform doctor --github` as the first-release readiness command; next refine it with package policy/package namespace checks and generated-workflow released-CLI install checks.
- **Audience impacted:** Platform engineers, engineering managers, open-source evaluators.
- **Priority:** P0
- **Effort:** M
- **Risk:** First release fails late in CI or requires expert GitHub Actions knowledge.
- **Files likely involved:** `cli/internal/commands/platform.go`, `docs/fork-validation.md`, `docs/platform-kit.md`.
- **Acceptance criteria:** A fork owner gets actionable pass/fail output before first release.
- **Suggested validation command:** `go -C cli test ./internal/commands -run Platform`
- **Type:** CLI, docs

### CC-P0-05: Govern Grype suppressions as expiring evidence

- **Problem:** Ignore evidence has expiry, but `.grype.yaml` suppressions can keep being honored unless a gate rejects stale or unbacked suppressions.
- **Evidence:** `core/.grype.yaml`, `core/overlays/cve/*.ignore.evidence.json`, `cli/internal/commands/remediation_ignore.go`.
- **Recommended fix:** Add a required check that every Grype ignore maps to active, unexpired evidence or VEX; fail expired suppressions.
- **Audience impacted:** Security engineers, auditors.
- **Priority:** P0
- **Effort:** M
- **Risk:** Suppressions become hidden permanent waivers.
- **Files likely involved:** `cli/internal/commands/remediation_*.go`, `core/.grype.yaml`, `.github/workflows/pr-gate.yml`, `.github/workflows/scheduled-scan.yml`.
- **Acceptance criteria:** Expired or unbacked suppressions fail CI.
- **Suggested validation command:** `go -C cli test ./internal/commands -run 'Remediation|Vex|Exceptions'`
- **Type:** CLI, workflow

## P1 action items

### CC-P1-01: Export provenance by immutable or versioned refs

- **Problem:** Provenance export uses rolling tags in places where digest or versioned refs are available.
- **Evidence:** `cli/internal/commands/fleet.go`, `cli/internal/commands/service.go`.
- **Recommended fix:** Use digest manifests to export provenance against immutable refs, falling back to versioned refs only when necessary.
- **Audience impacted:** Security engineers, auditors.
- **Priority:** P1
- **Effort:** M
- **Risk:** Rolling tag evidence is harder to reason about after later releases.
- **Files likely involved:** `cli/internal/commands/fleet.go`, `cli/internal/commands/service.go`, `.github/workflows/release.yml`.
- **Acceptance criteria:** Provenance export path records immutable or versioned image refs.
- **Suggested validation command:** `go -C cli test ./internal/commands -run 'Fleet|Service|Provenance'`
- **Type:** CLI, workflow

### CC-P1-02: Make the catalog matrix app-first

- **Problem:** App developers see Nix blueprint details while selecting images.
- **Evidence:** `site/src/components/MatrixGrid.astro`.
- **Recommended fix:** Move Nix links into platform/audit details and foreground template, dev image, certify, and verify actions.
- **Audience impacted:** App developers, platform engineers.
- **Priority:** P1
- **Effort:** M
- **Risk:** App teams think they need to learn Nix to consume the fleet.
- **Files likely involved:** `site/src/components/MatrixGrid.astro`, `site/src/pages/catalog.astro`.
- **Acceptance criteria:** Catalog selection answers "which image should I use?" before "how is it built?"
- **Suggested validation command:** `cd site && npm run typecheck && npm run build`
- **Type:** site-only

### CC-P1-03: Add a Show HN-friendly app workflow

- **Problem:** The first app path jumps to registry push/sign/certify operations too quickly.
- **Evidence:** `docs/getting-started.md`, `site/src/pages/getting-started.astro`.
- **Recommended fix:** Add a demo-local or public-demo path that proves image selection, template generation, and honest offline certification limits in 10-15 minutes.
- **Audience impacted:** App developers, open-source evaluators.
- **Priority:** P1
- **Effort:** M
- **Risk:** New users bounce before seeing value.
- **Files likely involved:** `docs/getting-started.md`, `docs/demo.md`, `site/src/pages/getting-started.astro`, `examples/`.
- **Acceptance criteria:** A new visitor can run or understand the app path without owning a registry.
- **Suggested validation command:** Run documented fixture-backed commands and `go -C cli test ./internal/commands -run App`
- **Type:** docs, site, examples

### CC-P1-04: Fail remediation drafting when aggregate PR creation fails

- **Problem:** The draft run can warn and succeed even if opening/updating the aggregate PR fails.
- **Evidence:** `cli/internal/commands/remediation_run.go`.
- **Recommended fix:** Treat failure to open/update the aggregate remediation PR as a failed drafting run unless explicitly disabled for local dry runs.
- **Audience impacted:** Platform engineers, security engineers.
- **Priority:** P1
- **Effort:** S
- **Risk:** Scheduled remediation appears healthy while no PR exists.
- **Files likely involved:** `cli/internal/commands/remediation_run.go`, `.github/workflows/scheduled-scan.yml`, `.github/workflows/cve-patch-agent.yml`.
- **Acceptance criteria:** CI fails when requested patch drafting cannot produce or update the aggregate PR.
- **Suggested validation command:** `go -C cli test ./internal/commands -run RemediationRun`
- **Type:** CLI, workflow

### CC-P1-05: Make service image release policy explicit

- **Problem:** Preview/non-production service images are configured, but release matrix behavior needs a clear policy.
- **Evidence:** `clearcutt.fleet.yaml`, `cli/internal/fleet/config.go`, `cli/internal/commands/service.go`, `.github/workflows/release.yml`.
- **Recommended fix:** Decide whether `productionAllowed: false` services publish by default or require opt-in; document and enforce the decision.
- **Audience impacted:** Platform engineers, app developers, security engineers.
- **Priority:** P1
- **Effort:** M
- **Risk:** Preview service images look production-endorsed.
- **Files likely involved:** `clearcutt.fleet.yaml`, `cli/internal/fleet/config.go`, `cli/internal/commands/service.go`, `docs/service-images.md`, `.github/workflows/release.yml`.
- **Acceptance criteria:** Service release behavior matches lifecycle/production policy.
- **Suggested validation command:** `go -C cli test ./internal/fleet ./internal/commands -run Service`
- **Type:** CLI, workflow, docs

## P2 action items

### CC-P2-01: Add a realistic branded site config example

- **Problem:** Catalog customization is capable but abstract.
- **Evidence:** `docs/customization.md`, `site/src/lib/site-config.ts`, `cli/internal/commands/catalog_site.go`.
- **Recommended fix:** Add a copyable example site config under `examples/` or `docs/`.
- **Audience impacted:** Platform engineers, engineering managers.
- **Priority:** P2
- **Effort:** S
- **Risk:** Fork owners do not see how to adapt the portal to their org.
- **Files likely involved:** `examples/`, `docs/customization.md`.
- **Acceptance criteria:** Example config builds a customized portal from mixed fixture catalog.
- **Suggested validation command:** `clearcutt catalog site build --catalog cli/internal/testdata/mixed-catalog --template site --site-config <example> --output /tmp/clearcutt-site --install --clean`
- **Type:** docs, examples

### CC-P2-02: Create registry support tiers

- **Problem:** GHCR is proven; other registries are possible but not equally proven.
- **Evidence:** `docs/registry-swap.md`, `.github/workflows/release.yml`, `cli/internal/commands/catalog_enrich.go`.
- **Recommended fix:** Document GHCR as Tier 1, generic token OCI registries as Tier 2, and cloud registries needing extra auth as Tier 3 until tested.
- **Audience impacted:** Platform engineers, engineering managers.
- **Priority:** P2
- **Effort:** S
- **Risk:** Users mistake parameterization for complete portability.
- **Files likely involved:** `docs/registry-swap.md`, `docs/platform-kit.md`, `README.md`.
- **Acceptance criteria:** Registry support claims match verified behavior.
- **Suggested validation command:** Docs review plus targeted workflow dry-run where possible.
- **Type:** docs-only
