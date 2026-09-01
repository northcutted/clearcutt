# Runbook: Showcase Remediation Plan

Status: **completed (2026-07 status note).** All phases landed on main: showcase/p2–p11
branches merged, Phase 1's substance (writable /tmp via the tmpDir derivation in
core/lib/build-fleet.nix) arrived through the repo-structure refactor, Phase 8 ships as
`clearcutt verify closure-purity` / `verify boundaries`, and Phase 12 was extracted to
docs/analysis/phase-12-horizon-epics.md. The Ground Rules section remains live
institutional knowledge; the phase tasks below are historical.

This runbook is the execution plan for fixing the findings from the 2026-06-10 multi-agent
showcase review (18 agents; every critical/high finding adversarially re-verified against the
code, the pinned nixpkgs, the live Pages site, and the GitHub API). It is written for an agent
with **no prior context**: every task names its files, its change, and its done-condition.

**Source of truth for evidence:** `.agents/runbooks/showcase-review-findings.json` — the full
structured review output (60+ findings with file:line evidence and verifier verdicts). When a
task below feels ambiguous, search that file for the finding title quoted in the task.

---

## 0. Ground Rules (read before any task)

1. **NEVER run `clearcutt platform init --force` in this repository.** It clobbers the upstream
   reference identity. Init is for forks only.
2. **Do NOT "fix" the SLSA generator reference.** `release.yml` pins
   `slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0`
   by **version tag, on purpose** — slsa-verifier requires tag refs for reusable builder
   workflows; SHA-pinning it breaks provenance verification. `scripts/validate-workflow-hardening.sh`
   must keep its existing carve-out for this.
3. **After any edit under `site/src/`**, regenerate the embedded fork template so
   `cli/internal/sitetemplate/template/src` stays byte-identical (there is a drift test,
   `TestEmbeddedTemplateMatchesSite`). Run `go generate ./...` from `cli/` (or copy the changed
   files into the template dir if generate doesn't cover it) and re-run the Go tests.
4. **One phase = one branch = one PR.** Branch names: `showcase/p<N>-<slug>`. Never commit to
   `main` directly. Keep PRs reviewable (< ~500 lines of hand-written diff where possible).
5. **Build outputs are never committed.** `/clearcutt`, `result`, `*.tar.gz`, coverage files,
   and the stray `/cli/{site,core,docs,examples}` trees are gitignored — leave them that way.
6. **Host limits:** this repo is usually worked on from macOS. Linux OCI image attrs
   (`packages.x86_64-linux.*`) cannot be *built* locally — validate Nix changes with
   `nix eval`/`nix flake show` (eval-level) and let the pr-gate matrix do the builds.
7. **GitHub-side state changes (branch protection, environment settings) require explicit
   maintainer sign-off** before running any mutating `gh api` call. Propose the exact command,
   wait for approval.
8. **Verification protocol before opening any PR** (mirrors the pr-gate `go-ci` job):
   ```bash
   make cli-build                                   # builds ./clearcutt at repo root
   (cd cli && go vet ./...)
   gofmt -l cli/cmd cli/internal                    # must print nothing
   (cd cli && COVERAGE_MIN=85.0 ./scripts/go-coverage.sh)
   ./scripts/validate-doc-commands.sh ./clearcutt
   ./scripts/validate-workflow-hardening.sh
   ```
   If the `test-clearcutt` skill is available in your harness, use it — it wraps the above plus
   fixture smoke tests. For Nix-touching phases additionally run:
   ```bash
   source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
   nix --extra-experimental-features 'nix-command flakes' flake show ./core 2>&1 | head -50
   nix --extra-experimental-features 'nix-command flakes' eval ./core#packages.x86_64-linux.java21-distroless.name
   ```

---

## Phase 1 — CRITICAL: read-only /tmp ships in every image

> Finding: "Every image ships a root-owned, non-writable /tmp — the `chmod 1777` is silently
> destroyed by Nix store canonicalization, and the postgres service image cannot start."
> Verified empirically: the `tmpDir` derivation builds to `dr-xr-xr-x` (0555).

**Files:** `core/lib/build-fleet.nix`, `core/tests/structure-test-*.yaml`,
`core/tests/service-image-contract.sh` (or the smoke runner it calls).

1. Remove `tmpDir` from `baseContents` (build-fleet.nix:39-42, 99-104). Create `/tmp` inside
   `extraCommands` in **both** `buildFleetImage` and `buildServiceImage` instead:
   `mkdir -p tmp && chmod 1777 tmp` — extraCommands content is packed by the image builder
   before store canonicalization, so the mode survives (same mechanism as the existing
   `chmod 0750` dataDirs and `chown` calls there).
2. Strengthen the structure tests: in each `core/tests/structure-test-{dev,slim,distroless}.yaml`
   assert `/tmp` exists **with permissions** `dtrwxrwxrwx` (sticky + world-writable), not just
   existence.
3. Add one smoke path that actually boots the postgres entrypoint (not `postgres --version`):
   run the image, wait for `pg_isready`, assert exit 0. Wire it into
   `core/tests/service-image-contract.sh` so the PR gate and release both exercise it.

**Done when:** structure tests assert 1777; a booted postgres16 container reaches ready; the
verify.sh suite passes in CI.

---

## Phase 2 — Evidence integrity quick wins (catalog + portal must not lie)

**Task 2a — Delete the scanner-identity rewrite.**
`site/src/lib/catalog.ts` (`publicArchPayload`, ~lines 26-57) rewrites
`arch.vulnerabilities.scanner` from `grype*` to `"vulnerability-check"` and renames assertion
labels — and this lands in the served machine-readable JSON
(`site/src/pages/catalog/images/[id].json.ts`). Remove the renaming entirely; serve scanner
name/version/dbBuiltAt verbatim. If a friendly label is wanted, add `displayName` *alongside*
the untouched field. Also remove the vestigial `credential broker → credential helper` replace.
Regenerate the embedded template (Ground Rule 3).

**Task 2b — Stamp real generator provenance.**
`cli/internal/commands/catalog_cmd.go` (`stampCatalogIndexMetadata`, ~246-263) hardcodes
`Commit: "unknown"` and falls back to `Version: "dev"`. Use `runtime/debug.ReadBuildInfo()`
to read `vcs.revision` / `vcs.time` as fallback (works on any `go build` from git, no ldflags
needed). Additionally pass the same `-ldflags -X ...Version=` in
`.github/workflows/publish-pages.yml` (both bare `go build` steps, ~lines 54 and 190).

**Task 2c — Emit `kind` on every v2 index summary.**
`catalog-index.v2.schema.json` requires `kind`, but runtime images never set it
(`Kind string \`json:"kind,omitempty"\`` in `cli/internal/catalogbuild/model.go:215`). In the
index-summarize path (`cli/internal/catalogbuild/record.go` ~202 and `index.go:66-82`), set
`kind: "runtime"` explicitly whenever the index is emitted as v2. Add a regression test:
marshal a mixed-catalog index, assert every `images[]` entry has `kind`.

**Task 2d — Fix the `imageSize` mislabel.**
`cli/internal/commands/catalog_enrich.go:397-399` records the OCI manifest-descriptor size
(15.6 kB) as `imageSize` for a 318 MiB image. Populate `imageSize` with the compressed layer
sum (already computed as `total` in the same function); keep the descriptor size under a new
explicit `manifestDescriptorSize` field; add `description`s to both fields in
`schemas/image-record.v2.schema.json`.

**Done when:** a freshly generated catalog shows real scanner identity, real
generator `{version, commit}`, `kind` on all v2 summaries, plausible image sizes; Go tests and
`validate-doc-commands.sh` pass.

---

## Phase 3 — Broken showcase artifacts (the things a reviewer tries first)

**Task 3a — OpenShift example.** `examples/openshift-deployment/deployment.yaml` deploys
`clearcutt-corelts:distroless`, which has **zero executables and no entrypoint** — the pod can
never start — and the README's `oc exec … id` transcript is fabricated. Mirror
`examples/k8s-deployment`: deploy an app image built on the distroless base (or slim with an
explicit `command:`), and rewrite verification honestly (`oc get pod -o jsonpath` for UID,
`oc debug` with ephemeral image; nameless `uid=1000070000 gid=0(root)` output).

**Task 3b — About-page architecture diagram 404.** `site/src/pages/about.astro:119` uses
root-absolute `/supply-chain-flow.svg` but `astro.config.mjs` sets `base: '/clearcutt'`.
Prefix with `import.meta.env.BASE_URL` (see the `hrefFor()` helper in `index.astro` for the
established pattern). Fix in `site/` AND regenerate the embedded template. Also embed
`docs/images/supply-chain-flow.svg` (currently orphaned) in `README.md`.

**Task 3c — ADR #2 vs template Dockerfiles.** `docs/decisions.md` mandates digest-pinned base
refs; every shipped template uses mutable tags (`examples/clearcutt-template-*/Dockerfile:1`,
generator at `cli/internal/commands/app_template.go:176-177`). Minimum fix: soften ADR #2 to
"production posture" and add an explicit "pin your base" step (the catalog exposes
`latestManifestDigest`; make `clearcutt inspect` print a copy-paste `FROM …@sha256:` line).
Better fix (if time): have `app template` resolve digest-pinned FROM lines from the catalog.

**Task 3d — Stale doc version pins.** `docs/certification.md` pins `v0.10.2` (lines ~77, ~162),
`docs/app-lifecycle.md` uses `:v0.2.2-distroless` in 9 examples, and
`site/src/pages/cli.astro` hardcodes `cliReleaseTag = 'v0.10.2'`. Bump all to the current tag
and add a currency check to `scripts/validate-doc-commands.sh` (flag pins older than N releases).

**Done when:** `oc apply` of the example yields a Ready pod (or the example says exactly why
not); the live About page renders the diagram (verify path math locally with `npm run build`);
no doc pins more than one minor behind the latest tag.

---

## Phase 4 — Governance & repo-level trust (partly maintainer-gated)

**Task 4a — SECURITY.md + community files.** Add: `SECURITY.md` (private disclosure channel,
supported versions, response expectations), `.github/CODEOWNERS`, issue templates
(bug / vulnerability-pointer-to-SECURITY.md / docs), `.github/PULL_REQUEST_TEMPLATE.md`,
`CHANGELOG.md` seeded from existing release notes.

**Task 4b — Dependency automation.** Add `.github/dependabot.yml` covering `github-actions`,
`gomod` (`/cli`), `npm` (`/site`). Add a weekly workflow that runs `nix flake update ./core`
and opens a PR (the pr-gate matrix is the safety net). Note the irony being fixed: the
hardening script *enforces* SHA pins that currently nothing bumps.

**Task 4c — Branch protection (MAINTAINER APPROVAL REQUIRED before mutating).** Propose, then
on approval apply via `gh api`: a ruleset on `main` requiring PRs, the pr-gate summary job as a
required status check, and no force pushes; set `prevent_self_review: true` on the `production`
environment. Then document both as **required fork-setup steps** in `docs/fork-validation.md`
and `FORKING.md` (currently "branch protection" has zero mentions in docs/).

**Done when:** GitHub Security tab shows a policy; dependabot opens its first PRs;
`gh api repos/:owner/:repo/branches/main/protection` (or rulesets) no longer 404s; fork docs
cover both controls.

---

## Phase 5 — Workflow tightening

1. `.github/workflows/e2e-runtimes.yml` (~lines 17-21): drop `packages: write` and
   `id-token: write` — the suite only uses `localhost:5001` + a mocked cosign. Leave
   `contents: read`.
2. Move `${{ github.event.inputs.* }}` and `${{ needs.check-version.outputs.version }}`
   interpolations out of `run:` bodies into `env:` blocks in `release.yml` (the
   `Resolve Version Output` and `Create and Push Git Tag` steps) and
   `cve-patch-agent.yml` (`Open Remediation Pull Request` step). Reference them as `"$VAR"`.
3. Replace hardcoded `go-version: '1.26'` with `go-version-file: 'cli/go.mod'` +
   `cache-dependency-path: 'cli/go.sum'` in: `cve-patch-agent.yml:65`,
   `publish-pages.yml:47,183`, and the `verify-release-evidence` job in `release.yml` (~777).
4. Extend `scripts/validate-workflow-hardening.sh` to enforce 2 and 3 (no event-input
   interpolation in run bodies; no hardcoded go-version) so they can't regress.

**Done when:** `validate-workflow-hardening.sh` passes with the new rules and would fail on
the old patterns (add a self-test like the closure-diff gate has).

---

## Phase 6 — CVE overlay on every public Nix surface

> Finding: `overlays.default` and `lib.mkHardenedShell` hand out **unpatched** runtimes; the
> remediation overlay isn't even exported.

**Files:** `core/flake.nix`, `core/lib/nix-native.nix`, `core/tests/verify.sh`.

1. Export the overlay: `overlays.cveRemediation = import ./overlays/cve-remediation.nix;`.
2. Fix `lib.mkHardenedShell` (flake.nix ~190-195): import nixpkgs with the same
   `config.allowUnfree = true` and `overlays = [ (import ./overlays/cve-remediation.nix) ]`
   used by `perSystem` and `graftOntoBase`.
3. Fix `overlays.default`: apply the CVE overlay first, then resolve registry attrs from
   `final` (not `prev`) so downstream consumers get patched packages. Document ordering.
4. Add a verify.sh assertion: resolve a remediated attr through `overlays.default` and assert
   the patched version (pick whichever overlay currently lives in `core/overlays/cve/`).
5. While in the file, fix the eval redundancy: bind `perSystem` once
   (`let evaluated = forAllSystems perSystem; in …`) and thread the imported `registry` into
   `build-fleet.nix` / `nix-native.nix` as an argument (keep self-import as default arg).
6. Fix impure fallbacks: replace `pkgs ? import <nixpkgs> {}` default in
   `core/lib/build-fleet.nix:3`, and make verify.sh's overlay eval checks use the locked input
   instead of the host channel.

**Done when:** `nix eval` shows a CVE-patched version through all three surfaces; verify.sh's
new assertion passes; `nix flake show ./core` evaluates clean.

---

## Phase 7 — Make the registry tell the truth (headless runtimes + matrix drift)

**Files:** `core/lib/registry.nix`, `clearcutt.yaml`, `core/tests/structure-test-*.yaml`,
`core/lib/build-fleet.nix`, `docs/security-model.md`.

1. **Java**: add `distrolessOverride` (and `slimOverride`) using a JRE/headless candidate list
   (`temurin-jre-bin-21`, zulu JRE attrs, `jdk21_headless` — same `getPkg` fallback pattern).
   Today java "distroless" ships javac, jshell, and the full GUI stack (gtk/cups/alsa).
2. **Python**: evaluate `python3Minimal` for the distroless override (check stdlib needs first;
   if rejected, document why in the registry comment).
3. **Node**: resolve `nodejs-slim_22`/`nodejs-slim_24` directly in the candidate lists; keep
   `removeNpm` only as fallback. Add structure tests asserting `/bin/npm`, `/bin/npx`,
   `/bin/corepack` `shouldExist: false` in slim/distroless.
4. **Matrix drift gate**: registry.nix builds python 3.13/3.14 that `clearcutt.yaml` no
   longer lists. Decide with maintainer: prune or re-add. Then add a CI consistency check
   (small Go test or script) diffing `registry.languages` flake eval against
   `matrix.languages` in the fleet config — fail on orphans in either direction.
5. **LD_LIBRARY_PATH**: remove `fhsCompatibilityEnv` from slim/service tiers (the `/lib`
   symlinks alone provide FHS compat via default loader paths) or gate behind a fleet-schema
   opt-in. Add a structure-test assertion that distroless has no `LD_LIBRARY_PATH`. Document
   the DT_RUNPATH-precedence rationale in `docs/security-model.md` §2.1.

**Done when:** published SBOM for java21-distroless (next release) has no gtk/cups/bash; new
structure tests pass; the drift gate fails if registry and fleet.yaml disagree.

---

## Phase 8 — Closure-purity gate (make "distroless" machine-enforced)

> Depends on Phase 7 (otherwise the gate fails immediately on bash-in-closure).

1. Extend the distroless boundary test to walk **store paths**, not just FHS paths:
   `core/tests/nix-store-closure-from-image.py` already extracts store roots from layer tars —
   fail the gate when any `/nix/store/*/bin/{sh,bash,ash,dash}`, package manager (npm, pip,
   apk, dpkg), or setuid binary appears in a distroless closure.
2. Expose it as a flake check: `checks.<system>.distroless-purity` in `core/flake.nix`, so
   `nix flake check` becomes a security gate (currently the flake has zero `checks` outputs).
3. Surface the result: write a `closurePurity` boolean into the per-image test-results JSON the
   pipeline already attests, and render a badge on the catalog image pages.

**Done when:** `nix flake check ./core` (Linux CI) runs the purity check; an intentionally
poisoned image (add bash to a distroless contents list locally) fails it; the badge renders.

---

## Phase 9 — Make the JSON Schemas executable

> Finding: no JSON Schema validator runs anywhere — the schemas are decorative, and the
> published catalog fails its own v2 schema.

1. Add `github.com/santhosh-tekuri/jsonschema/v6` to `cli/go.mod`. In
   `clearcutt catalog validate` (`cli/internal/commands/catalog_validate.go`), validate
   `index.json`, every `images/*.json`, and `evidence-manifest.json` against the **embedded**
   schemas (`cli/internal/catalog/schemas/`) in addition to the existing structural checks.
2. Add a Go test validating all three testdata catalogs + a freshly generated catalog against
   the schemas. Fix the fixtures it flushes out (`cli/internal/testdata/catalog` lacks
   `schemaVersion`/`generator`/`source`/`summary`; SBOM packages lack required `cpes`).
3. Fix the v1 round-trip data-loss: drop `omitempty` from the Lifecycle/RuntimeContract pointer
   fields in `cli/internal/catalog/types.go:146-165` (or relax v1 required lists to match v2).
4. `schemas/clearcutt-fleet.schema.json`: add the missing `runtimeLines` property (it currently
   rejects the documented extension mechanism via `additionalProperties: false`); add a
   `# yaml-language-server: $schema=…` modeline to `clearcutt.yaml`; validate fleet.yaml
   against the schema in a Go test.
5. Root/embedded schema parity: delete orphaned `schemas/catalog.schema.json` and
   `schemas/image-record.schema.json` (legacy duplicates), copy
   `evidence-manifest.v1.schema.json` into root `schemas/`, and add a parity test mirroring
   `TestEmbeddedTemplateMatchesSite`.
6. Add a publish-pages step that schema-validates the catalog artifact before deploy.
7. `tierList()` (`cli/internal/catalogbuild/model.go:115-122`): append a `service` tier entry
   when the index contains service images. Site zod (`site/src/lib/catalog-schema.ts`): add
   `latestManifestDigest`, relax `lifecycle.support` to string — then regenerate the template.

**Done when:** `catalog validate` fails on a catalog that violates the shipped schemas (prove
with a deliberately broken fixture in a test); pr-gate and publish-pages both run schema
validation; fixtures pass.

---

## Phase 10 — CLI DX

1. **Validate `--format`** once in a `PersistentPreRunE` on root (accept table|json|yaml|yml;
   error `unknown --format %q` otherwise). Fix the "Output formatting format" help stutter
   (`cli/internal/commands/root.go:37`).
2. **Structured output for the gating family**: `verify catalog`, `verify rebuild`,
   `verify release-evidence`, `conformance`, `exceptions validate` should emit the same
   `{status, checks[]}` JSON shape `verify image` has (reuse `VerifyResponse`). Commands where
   `--format` genuinely can't apply must error on a non-default value, not ignore it.
3. **Exit codes**: 0 = pass, 1 = operational error, 2 = policy gate failed. Document in
   `docs/cli-reference.md` and use distinct codes throughout the verify family.
4. **Repo-root resolution**: stop trusting cwd for output paths (root cause of the stray
   `cli/{core,site,docs,examples}` trees the `.gitignore` papers over). Walk up for
   `go.work`/`clearcutt.yaml`; refuse mutating commands when no root is found. Delete the
   existing stray trees from local checkouts (they're untracked debris — verify with
   `git ls-files` first). Ensure tests use `t.TempDir()`.
5. **`make check`**: new target mirroring the pr-gate go-ci job exactly (vet, gofmt check,
   coverage with `COVERAGE_MIN=85.0`, `validate-doc-commands.sh`). Make `site-typecheck`/
   `site-build` depend on an `npm ci` sentinel so `make test` is clean-clone safe. Update
   `CONTRIBUTING.md` to name `make check` as the one canonical pre-PR command.
6. **Signed-binary install docs**: README + `docs/cli-reference.md` "Install" section —
   download the release binary + `.sig` bundle, `cosign verify-blob --bundle … 
   --certificate-identity 'https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/heads/main'
   --certificate-oidc-issuer https://token.actions.githubusercontent.com`, then run the fixture
   first-proof commands. Keep build-from-source as the contributor path.
7. **Contributor devShell**: add `go`, `gopls`, `nodejs` to the default devShell in
   `core/flake.nix:150-160`; add a repo devcontainer (the kit ships them for app teams but has
   none itself).

**Done when:** `clearcutt list --format jsno` errors; `verify catalog --format json | jq .status`
works; `make check` passes from a clean clone and predicts a green pr-gate.

---

## Phase 11 — Showcase assets & narrative

1. **Demo recording**: asciinema of the five clean-clone fixture commands
   (list → inspect → verify image → app template → catalog site build), converted to GIF
   (`agg`), embedded as the README hero. The commands are deterministic — scriptable.
2. **Screenshots**: catalog matrix page + java21-distroless evidence page →
   `docs/images/`, embedded in README and `docs/demo.md` (which currently asks the *reviewer*
   to take screenshots).
3. **Rewrite `docs/alternatives.md`**: name the alternatives (apko/Chainguard,
   gcr.io/distroless, plain `pkgs.dockerTools`, Docker multi-stage) and compare on measurable
   axes (closure size, package count, SBOM derivation, CVE counts, which verification commands
   succeed). Static numbers first; CI-generated comparison comes in Phase 12. Also fix the
   manager "first useful command" (`sed -n '1,140p'` of a 43-line file).
4. **Reframe `docs/analysis/`**: move snapshots to `docs/analysis/history/` with a README that
   leads with the post-hardening verdict and frames the audits as the project's QA process.
   Fix the banned phrase "Highly secure production hosting" at `site/src/lib/image-metadata.ts:237`
   (then regenerate the template).
5. **CVE agent allowlist** (small but security-relevant; fits here or Phase 5):
   invert `DANGEROUS_OVERRIDE_ATTRS` in `core/scripts/cve-draft-agent.py` to a closed
   allowlist — `version_bump` may set only `version`/`src`; `fetchpatch` may only append to
   `patches`. Update `docs/trust/cve-agent-threat-model.md` accordingly.

---

## Phase 12 — Horizon epics (each is its own design + PR series; confirm scope with maintainer first)

- **Nix-closure-derived SBOM**: generate SPDX/CycloneDX from the derivation graph
  (`nix path-info -r --json` or sbomnix) in `core/pipeline/pipeline.sh`; attest it as the
  authoritative SBOM; keep syft as cross-check; surface "derived vs scanned" on the portal.
- **"Receipts" comparison workflow**: scheduled job comparing the same Java service on
  clearcutt-distroless vs `eclipse-temurin:21-jre` vs `gcr.io/distroless/java21` vs Chainguard
  JRE — size, package count, CVE counts, verification-command success — rendered on the portal
  and linked from alternatives.md. **Requires Phase 7 first.**
- **Remediation feed**: publish `core/overlays/cve/` overlay+evidence pairs as JSON/RSS from
  the portal; add `clearcutt remediation pull <CVE-ID>`.
- **`clearcutt attest verify <ref>`** + a published composite action (`clearcutt-verify-action`)
  wrapping the exact cosign/slsa-verifier/SBOM checks from `verify_release_evidence.go`, with
  the Phase-10 exit codes.
- **Declarative `hardening:` block** in `clearcutt.yaml` emitting OCI config knobs and
  the matching K8s `securityContext`/Kyverno policy from one source.

---

## Sequencing & parallelism

- Phases 1–5 are independent of each other — safe to run in parallel branches.
- Phase 6 before 7 only if touching the same flake regions bothers you; otherwise independent.
- Phase 7 **must** land before Phase 8 (purity gate) and before the Phase-12 receipts workflow.
- Phase 9 is independent but large — keep it as its own PR.
- Phases 10–11 are independent.
- After each merged PR, re-run the Ground Rule 8 protocol on `main` to catch interaction drift.
