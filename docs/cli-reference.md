# ClearCutt CLI Reference

This page is a compact map of the current CLI surface. It is not a replacement
for `clearcutt --help`; use help output for the final flag contract.

## Exit Codes

The CLI distinguishes "the gate said no" from "the gate could not run":

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; all requested checks passed. |
| `1` | Operational error: bad flags or arguments, IO failure, missing catalog data, or required tooling not available. |
| `2` | Policy gate failed: a verification, conformance, certification, exception, or threshold check evaluated and rejected the input. |

Exit code 2 applies to the gating commands — `verify image`, `verify catalog`,
`verify rebuild`, `verify release-evidence`, `verify boundary-suite`,
`conformance run`, `certify`, and `exceptions validate` — plus the other
check-list gates (`catalog validate`, `overlay verify`, `platform status`,
`runtime validate`, `service validate`, `app diff-base`, `app rebase`). CI
`run:` steps fail on any non-zero code, so existing workflow gates keep working;
scripts that need to branch on "policy failure vs broken pipeline" can now test
the code directly:

```text
clearcutt verify image <id> ...; case $? in
  0) deploy ;;
  2) block release: policy gate rejected the image ;;
  *) investigate: verification could not run ;;
esac
```

## Output Formats

The global `--format` flag accepts `table` (default), `json`, or `yaml`.
Unknown values are rejected before the command runs. The gating commands above
emit a common machine-readable shape for `--format json|yaml`: an overall
`status` (`pass` or `fail`) plus a `checks` array of
`{id, status, message}` objects, with data on stdout and human commentary on
stderr.

## Install

Releases ship cross-compiled binaries (`clearcutt-<os>-<arch>` for
`darwin`/`linux`/`windows` on `amd64`/`arm64`), a keyless Sigstore signature
bundle per binary (`<binary>.sig`), `clearcutt-cli-assets.json`, and a
`SHA256SUMS.txt` manifest. `clearcutt fleet build-cli-assets` owns the release
binary matrix, optional `cosign sign-blob` calls, and checksum manifest; GitHub
Actions supplies the OIDC identity when the release workflow runs it with
`--sign`. Download a binary and its `.sig` bundle from the
[latest release](https://github.com/northcutted/clearcutt/releases/latest)
and verify before use:

```bash
cosign verify-blob \
  --bundle clearcutt-linux-amd64.sig \
  --certificate-identity 'https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  clearcutt-linux-amd64

chmod +x clearcutt-linux-amd64
./clearcutt-linux-amd64 --catalog cli/internal/testdata/catalog list
```

The identity is exact, not a pattern: releases run only from
`refs/heads/main`, and the same string is pinned as
`release.workflowIdentity` in `clearcutt.fleet.yaml` and passed to
`clearcutt verify release-evidence --workflow-identity`. Build from source
(below) when contributing.

## Build

```bash
go -C cli build -o ../clearcutt ./cmd/clearcutt
./clearcutt --help
```

Catalog-backed discovery commands need generated catalog data or a fixture:

```bash
./clearcutt --catalog cli/internal/testdata/catalog list
./clearcutt --catalog cli/internal/testdata/catalog inspect java21-distroless
```

## App-Team Commands

```bash
./clearcutt --catalog cli/internal/testdata/catalog list
./clearcutt --catalog cli/internal/testdata/catalog inspect java21-distroless
./clearcutt app template java --output examples/my-java-service --name my-java-service
./clearcutt --catalog cli/internal/testdata/dev-catalog dev java21-distroless --devcontainer --print
APP_IMAGE=ghcr.io/acme/my-app:1.0.0
APP_DIGEST=$(docker buildx imagetools inspect "$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save "$APP_IMAGE" -o my-app.tar
./clearcutt certify my-app.tar --base java21-distroless --policy certification-policy.yaml --image-ref "${APP_IMAGE%:*}@${APP_DIGEST}"
./clearcutt app build --base java21-distroless --artifact target/app.jar --dest /workspace/app.jar --entrypoint '["java","-jar","/workspace/app.jar"]' --image ghcr.io/acme/payments-api:1.0.0
```

## Catalog And Trust Commands

```bash
./clearcutt catalog generate --config clearcutt.fleet.yaml --include-services --output dist/catalog
./clearcutt --catalog dist/catalog catalog validate
./clearcutt --catalog dist/catalog catalog summarize
./clearcutt --catalog dist/catalog catalog inspect java21-distroless
./clearcutt catalog diff --old previous/catalog --new dist/catalog
./clearcutt catalog site build --catalog dist/catalog --output dist/site --install
./clearcutt catalog workflow-params --github-output "$GITHUB_OUTPUT"
./clearcutt catalog vex-all --output-dir dist/site/vex
./clearcutt catalog build --core-dir core --update-db --include-services

./clearcutt --catalog cli/internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview

./clearcutt verify release-evidence \
  --ref ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_IMAGE:TAG \
  --repo YOUR_ORG/YOUR_REPO \
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main' \
  --core-dir core

./clearcutt verify rebuild ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-distroless \
  --target java21-distroless \
  --rebuild \
  --pull-registry-archive \
  --require-digest-match \
  --require-layer-match \
  --diffoscope-out rebuild.diff.txt \
  --output-predicate

./clearcutt verify boundary-suite --core-dir core
```

For `verify release-evidence`, `--core-dir core` runs core-pinned verifier tools
through the scaffolded Nix backend. The current backend supplies Cosign, GitHub
CLI, and a flake-local SLSA verifier binary derivation.
`verify boundary-suite --core-dir core` is the PR-gate image-security boundary
suite: it realizes missing representative archives through the Nix flake, then
runs native-Go closure-purity and runtime-CVE gates over the same representative
slim/distroless targets the legacy shell suite covered.

## Estate Discovery Commands

Discover and govern an image estate ClearCutt did not build. Every command here is
read-only against the registry: it reads manifests, configs, and tags, and writes
local files.

```bash
# Enumerate a registry namespace into an inventory
./clearcutt registry scan \
  --registry ghcr.io \
  --namespace YOUR_ORG/YOUR_REPO \
  --repository YOUR_BASE_IMAGE \
  --repository YOUR_APP_IMAGE \
  --output dist/scan/images.yaml

# Read each image's manifest, config, layers, and labels
./clearcutt import observe --images dist/scan/images.yaml --output dist/scan/observations.json

# Derive which images are built on which, and how stale each one is
./clearcutt graph build \
  --observations dist/scan/observations.json \
  --output dist/scan/graph.json \
  --report dist/scan/inventory.md

# Use it as a CI gate
./clearcutt graph build --observations dist/scan/observations.json \
  --output dist/scan/graph.json --min-confidence verified --fail-on-stale
```

`registry scan` prefers the distribution `_catalog` endpoint filtered by
`--namespace`; registries that do not implement it (GHCR, Docker Hub) need
`--repository`, which is repeatable. Cosign signature and attestation sidecar tags
are skipped unless `--include-sidecar-tags` is passed.

`graph build` establishes each relationship by layer-digest matching (proof),
`org.opencontainers.image.base.digest`, buildpacks lifecycle metadata,
`org.opencontainers.image.base.name`, or build history — in that order — and labels
every edge with the confidence that method earns. See
[Registry scan and the base image graph](registry-graph.md).

## Platform Owner Commands

```bash
./clearcutt platform init --owner YOUR_ORG --repo YOUR_REPO --force
./clearcutt platform new ./golden-images --owner YOUR_ORG --repo golden-images
./clearcutt platform new ./golden-images --source ./clearcutt-source.zip --owner YOUR_ORG --repo golden-images
./clearcutt platform render ./image-platform --profile catalog-only --owner YOUR_ORG --repo image-platform --registry-base ghcr.io/YOUR_ORG/image-platform
./clearcutt platform render ./release-catalog \
  --profile catalog-only \
  --catalog-source github-release \
  --catalog-source-repo YOUR_ORG/image-factory \
  --catalog-targets java21-distroless,node24-slim \
  --catalog-release-limit 1 \
  --owner YOUR_ORG \
  --repo release-catalog \
  --registry-base ghcr.io/YOUR_ORG/image-factory \
  --pages
./clearcutt platform status
./clearcutt platform release-plan
./clearcutt platform doctor --github
./clearcutt platform setup-nix --core-dir core --write-user-config

./clearcutt fleet certify-target \
  --system x86_64-linux \
  --language java25 \
  --tier slim

./clearcutt fleet publish-target \
  --system x86_64-linux \
  --language java25 \
  --tier slim \
  --version-tag v1.2.3

./clearcutt fleet workflow-matrices --github-output "$GITHUB_OUTPUT"
./clearcutt fleet seed-cache-plan --core-dir core --github-output "$GITHUB_OUTPUT"
./clearcutt fleet build-cli-assets --version-tag v1.2.3 --build-outputs build-outputs --sign

./clearcutt matrix explain java21
./clearcutt matrix add java25
./clearcutt runtime scaffold ruby3.4
./clearcutt runtime validate ruby3.4

./clearcutt service scaffold postgres16 --template postgres --version 16
./clearcutt service validate --all
./clearcutt service build postgres16 --system x86_64-linux
./clearcutt service smoke postgres16 --engine docker
./clearcutt service publish postgres16 --system x86_64-linux --version-tag v1.2.3

./clearcutt overlay generate \
  --runtime java21 \
  --tier slim \
  --base registry.access.redhat.com/ubi9/ubi-minimal@sha256:... \
  --runtime-ref ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-slim@sha256:... \
  --image ghcr.io/YOUR_ORG/java21-ubi:TAG \
  --output overlays/java21-ubi

./clearcutt overlay verify \
  --runtime-archive clearcutt-java21.tar \
  --grafted-archive overlays/java21-ubi/result \
  --runtime-ref ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-slim@sha256:... \
  --grafted-ref ghcr.io/YOUR_ORG/java21-ubi:TAG@sha256:... \
  --target java21-slim \
  --output-predicate
```

Fleet and service build/publish commands default to the Go-owned engine
(`nix build` backend, native boundary gates, Go OCI publish). Use
`--engine shell` only as a temporary legacy `core/pipeline/pipeline.sh`
fallback while investigating parity.
`fleet workflow-matrices` is the release/PR-gate planner used by GitHub
Actions: it reads `clearcutt.fleet.yaml`, emits the runtime release/image
matrices and service release/image matrices, and writes `release_matrix`,
`image_matrix`, `service_release_matrix`, and `service_image_matrix` when
`--github-output` is set.
`fleet seed-cache-plan` is the no-build cache-warming planner used by the
seed-cache workflow: it dry-runs each release matrix cell against the Nix
backend, refuses partial output on eval failures, and writes `seed_matrix` plus
`has_work` for GitHub Actions.
`fleet build-cli-assets` is the release CLI asset builder used by the release
workflow: it cross-compiles the six supported OS/architecture binaries, stamps
the CLI version via ldflags, signs each binary with `cosign sign-blob` when
`--sign` is set, writes `clearcutt-cli-assets.json`, and emits deterministic
`SHA256SUMS.txt` entries for installer verification.

`platform release-plan` is side-effect free. It reads `clearcutt.fleet.yaml` and
local workflow wiring, then prints the registry support tier, matrix size,
required GitHub variables/secrets, local checks, release workflow steps,
verification commands, and the honest boundary between ClearCutt CLI
orchestration, GitHub Actions/SLSA, Nix, Sigstore tools, and remediation PR
drafting. Use `--format json` or `--format yaml` when generating onboarding or
first-release checklists.

`platform render --profile catalog-only` defaults to `--catalog-source
inventory` and writes `images.yaml`. `--catalog-source github-release` instead
requires `--catalog-source-repo OWNER/REPO` and `--catalog-targets`, records the
source and `--catalog-release-limit` in `clearcutt.lock`, and generates workflows
that consume published release evidence without copying the source repository.
Both modes remain Nix-free. `platform bootstrap github` accepts the same flags;
remote repository, settings, and push operations still require both `--apply`
and `--confirm`.

`catalog workflow-params` is the Pages workflow parameter helper. It reads
`catalog.releaseLimit` and `catalog.scanDepth` from `clearcutt.fleet.yaml`,
allows a dispatch-provided release-limit override, and writes `limit` plus
`scan_depth` for GitHub Actions. `catalog site build --generate-vex` generates
per-image OpenVEX JSON from the active catalog before running the Astro build, so
the workflow does not need to parse catalog internals. `catalog build --core-dir
core --update-db` resolves Grype through the scaffolded Nix backend and refreshes
the Grype DB inside the CLI-owned scan step.

## Scan Commands

```bash
./clearcutt scan refresh-kev

./clearcutt scan \
  --mode remediation \
  --sbom-dir site/src/data/sboms \
  --out-dir site/src/data/vulnerabilities \
  --depth 4 \
  --kev-file core/build-outputs/security-intel/known_exploited_vulnerabilities.json \
  --update-db
```

`scan refresh-kev` writes the CISA KEV catalog cache and a small status JSON
under `core/build-outputs/security-intel/` by default. Refresh failures are
non-fatal unless `--fail-on-unavailable` is set.

`scan --update-db` refreshes the local Grype database before scanning. If the
refresh fails, the CLI warns and continues with the active local database, which
matches the scheduled remediation behavior without requiring a separate shell
wrapper.

## Policy And Remediation Commands

```bash
./clearcutt --catalog cli/internal/testdata/catalog policy java21-distroless --engine kyverno --environment production --namespace apps
./clearcutt exceptions validate exceptions.yaml --fail-on-expired-exceptions
./clearcutt vex --help
./clearcutt remediation plan --help
./clearcutt remediation workflow-params --github-output "$GITHUB_OUTPUT"
./clearcutt remediation run --llm off --skip-pr --help
./clearcutt remediation run \
  --package zlib \
  --cve CVE-2026-77777 \
  --installed-version 1.3.1 \
  --fixed-version 1.3.2 \
  --download-url https://example.test/zlib-1.3.2.tar.gz \
  --sha256 sha256-deadbeef \
  --rolling-branch cve-remediation/manual
./clearcutt remediation report --help
```

`remediation run` drafts deterministic evidence-backed campaigns natively before
any retained backend is considered. When the evidence includes a direct `route`
plus `overlay_expression` recipe or explicit source/patch URL plus hash
evidence, the Go CLI writes the overlay, evidence sidecar, and remediation
branch itself. `--llm off` is the deterministic scheduled path: it filters to
evidence-backed campaigns only and skips campaigns that still need hash
iteration or build probing. `--llm auto` may route only those unresolved
campaigns to the retained drafting backend behind the CLI. Core workspace
autodetection uses the Nix backend markers, so deterministic runs do not require
the retained Python backend file. `remediation workflow-params` reads
`clearcutt.fleet.yaml` and emits the scan depth, campaign limits,
dev-tier inclusion, and compact policy JSON used by the scheduled workflow,
so Actions does not parse remediation config with `jq`. `remediation plan` and
`remediation run` also read the same CI env defaults (`VULN_ROOT`,
`MAX_FINDINGS_PER_RUN`, `MAX_PATCH_FAILURES_PER_RUN`,
`INCLUDE_DEV_ONLY_REMEDIATION`, and `REMEDIATION_POLICY_JSON`) used by the
scheduled workflow. `remediation report --allow-missing` preserves always-run
report steps without shell file checks. Manual `workflow_dispatch` remediation
also uses `remediation run` with explicit package/CVE/version/source inputs, so
GitHub Actions no longer invokes `cve-draft-agent.py` directly. The output
remains an aggregated draft PR path, not an auto-merge or production mutation
path.

## Triage And Decision Commands

```bash
./clearcutt remediation triage --plan core/build-outputs/remediation-plan.json --core-dir core
./clearcutt --format json remediation triage > triage-report.json
./clearcutt remediation triage --cve CVE-2026-88888 \
  --decide scanner_ignore \
  --decided-by human \
  --owner platform-team \
  --reason "vulnerable path not reachable from shipped entrypoints" \
  --expires 2026-09-30
./clearcutt remediation status
./clearcutt remediation status --check-retirements --strict
```

`remediation triage` composes materiality, the static route context, and a live
fix-availability probe into one priced decision record per finding. Scope the
run with `--cve` or `--package`, feed it an existing plan (`--plan plan.json`)
or scan output (`--scan-dir`), and point `--core-dir` at the core workspace so
the probe can resolve nixpkgs source paths against the local pin. `--no-probe`
— or any probe failure — degrades to the static route classifier, so triage is
never less available than `remediation plan`. The default table output prints
one block per finding: a CVE header line (severity, exposure tiers, upstream
state) followed by the route table. `--format json` emits the versioned
`clearcutt.triage/v1` report (`schemas/triage.v1.schema.json`) that the
scheduled scan uploads and future agents consume.

Every finding is priced across six routes. Cost is what applying the route
costs today; retirement is the condition recorded at decision time under which
the decision stops being carried:

| Route | Available when | Cost now | Retires |
| --- | --- | --- | --- |
| `version_bump` | the pinned nixpkgs already carries the fix | none (substitutable) | immediately — the fix ships and the evidence closes |
| `substitute_vex` | crypto CVE already provenance-allowlisted | none (substitutable) | pin carries the fix |
| `unstable_optin` | a Hydra-cached ref carries the fix | scoped rebuild of the hopped runtime subtree (conservatively priced — the crypto rebind rebuilds it even when the hop itself substitutes) | pin carries the fix — drop the opt-in |
| `fetchpatch_rebuild` | upstream fix exists but no cached ref carries it | cold from-source build | pin carries the fix — drop the overlay |
| `scanner_ignore` | policy permits per materiality (never KEV) | none | expiry (policy accepted-expiry default) |
| `wait` | fix visible on an uncached ref and severity at or below the policy wait ceiling | none | a cached ref carries the fix, with an expiry backstop |

`--decide ROUTE` applies a route non-interactively and stamps a `triage` block
(`decidedBy`, retirement condition, probe snapshot at decision time) onto the
decision artifact. `scanner_ignore` delegates to the existing ignore writer
(grype rule plus expiring ignore evidence); `unstable_optin` writes the decision
record and prints the exact `remediation.unstable.softOptIns` snippet rather
than rewriting `clearcutt.fleet.yaml`; `wait` writes a standalone
`.decision.evidence.json`; `version_bump`, `fetchpatch_rebuild`, and
`substitute_vex` write the record and hand the mechanical part to
`remediation run`. `--decided-by` accepts `human` (the default), `policy`, or
`agent:<id>`.

`remediation status` is the ledger. It aggregates every carried decision — CVE
overlays and evidence, ignore evidence, fleet soft opt-ins, crypto allowlist
entries, wait records — into one table of what is carried, its route, and when
it retires. `--check-retirements` (probe required) evaluates each
recorded retirement condition now: `pin_carries_fix` and `ref_carries_fix`
probe the watched ref for the fix version, `expiry` is a date compare using the
same rule `validate-overlays` enforces.

Both commands follow the standard exit-code contract above: `0` decided or
informational, `1` operational error. With `--strict`, `remediation triage`
exits `2` when any in-scope finding has no available route under policy — the
escalation signal a pipeline turns into a PR comment or issue — and
`remediation status --check-retirements` exits `2` when any retirement
condition fired, the scheduled hook for opening retirement PRs.

Example table output for a critical production finding whose fix has reached
staging-next but no cached ref:

```text
CVE-2026-88888 openssl 3.6.2 -> 3.6.3  severity=critical  exposure=production(distroless)  disposition=must_fix(severity)
probe: pin ✗ · nixos-unstable ✗ · master ✗ · staging-next ✓ uncached

    ROUTE               AVAILABLE  COST NOW           RISK CARRIED  RETIRES         WHY
    substitute_vex      no         none_substitutable none          -               not a provenance-allowlisted crypto finding; the substitute+VEX bridge does not apply
    version_bump        no         none_substitutable none          -               the pin still builds 3.6.2, below the scanner fix 3.6.3
    unstable_optin      no         scoped_rebuild     none          -               no Hydra-cached ref carries the fix yet
  ▸ fetchpatch_rebuild  yes        cold_source_build  none          pin >= 3.6.3    upstream fix 3.6.3 exists but the pin lacks it; rebuild from source via an in-place override
    wait                no         none               cve_ships_until_ref_lands  -  severity critical is above the wait ceiling (medium)
    scanner_ignore      no         none               cve_ships_until_expiry     -  policy blocks: reachable, materially risky, and fixable in a production tier
```

## Drift Check Scope

The PR gate validates high-traffic command snippets that are expected to be
executable from this checkout. Commands that require registry credentials,
cluster access, or fork-specific values must be marked as examples and should
use placeholders such as `YOUR_ORG`.
