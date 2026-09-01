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
`release.workflowIdentity` in `clearcutt.yaml` and passed to
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
./clearcutt catalog generate --config clearcutt.yaml --include-services --output dist/catalog
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

# What the fleet has in common at the layer level
./clearcutt graph layers \
  --observations dist/scan/observations.json \
  --output dist/scan/layers.json \
  --report dist/scan/commonality.md \
  --mermaid dist/scan/graph.mmd

# Use it as a CI gate
./clearcutt graph build --observations dist/scan/observations.json \
  --output dist/scan/graph.json --min-confidence verified --fail-on-stale

# Persist the snapshot where the images live, and read it back
./clearcutt estate push ghcr.io/acme/clearcutt-estate:2026-08-31 \
  --dir dist/scan --generated-at 2026-08-31T00:00:00Z
./clearcutt estate pull ghcr.io/acme/clearcutt-estate:2026-08-31 --output ./snapshot
```

`estate push` stores observations and both graphs as a single OCI artifact. It is
deterministic — identical content yields an identical digest — so a scheduled push of
an unchanged estate does not create a new version, and drift is a diff between two
tags. `estate pull` rejects any manifest that is not a ClearCutt estate artifact. See
[registry-graph.md](registry-graph.md#persisting-a-snapshot).

`registry scan` prefers the distribution `_catalog` endpoint filtered by
`--namespace`; registries that do not implement it (GHCR, Docker Hub) need
`--repository`, which is repeatable. Cosign signature and attestation sidecar tags
are skipped unless `--include-sidecar-tags` is passed.

`graph layers` is the content view: fleet core, common layers, content-identical
images, similarity clusters, per-image unique content, deduplication accounting, and
a Mermaid diagram. It never implies parentage.

`graph build` also reports shared-layer blast radius: which images carry a given
layer, which is the remediation question for estates whose images share content
without one being built on the other (Nix `dockerTools.buildLayeredImage` output,
notably). Reproducible builders that zero the creation timestamp are detected, and
currency falls back to tag order with a warning rather than ranking every version
equally old.

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
  --catalog-targets java21-distroless,node22-slim \
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
  --language java21 \
  --tier slim

./clearcutt fleet publish-target \
  --system x86_64-linux \
  --language java21 \
  --tier slim \
  --version-tag v1.2.3

./clearcutt fleet workflow-matrices --github-output "$GITHUB_OUTPUT"
./clearcutt fleet seed-cache-plan --core-dir core --github-output "$GITHUB_OUTPUT"
./clearcutt fleet build-cli-assets --version-tag v1.2.3 --build-outputs build-outputs --sign

./clearcutt matrix explain java21
./clearcutt matrix add java25   # adds a line the registry has a recipe for
./clearcutt runtime scaffold ruby3.4
./clearcutt runtime validate ruby3.4

./clearcutt service scaffold postgres16 --template postgres --version 16
./clearcutt service validate --all
./clearcutt service build postgres16 --system x86_64-linux
./clearcutt service smoke postgres16 --engine docker
./clearcutt service publish postgres16 --system x86_64-linux --version-tag v1.2.3

```

Fleet and service build/publish run through the Go-owned engine: a `nix build`
backend, native in-process boundary gates, and a Go OCI publish path. There is
no shell fallback.

The reference fleet builds one runtime line — java25 — in three tiers on two
architectures. `clearcutt.yaml` configures no service images; `service
scaffold` still works if you want them.

`fleet workflow-matrices` is the release/PR-gate planner used by GitHub Actions:
it reads `clearcutt.yaml` and emits the runtime release and image
matrices, writing `release_matrix` and `image_matrix` when `--github-output` is
set.
`fleet seed-cache-plan` is the no-build cache-warming planner used by the
seed-cache workflow: it dry-runs each release matrix cell against the Nix
backend, refuses partial output on eval failures, and writes `seed_matrix` plus
`has_work` for GitHub Actions.
`fleet build-cli-assets` is the release CLI asset builder used by the release
workflow: it cross-compiles the six supported OS/architecture binaries, stamps
the CLI version via ldflags, signs each binary with `cosign sign-blob` when
`--sign` is set, writes `clearcutt-cli-assets.json`, and emits deterministic
`SHA256SUMS.txt` entries for installer verification.

`platform release-plan` is side-effect free. It reads `clearcutt.yaml` and
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
`catalog.releaseLimit` and `catalog.scanDepth` from `clearcutt.yaml`,
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

## Policy And Exception Commands

```bash
./clearcutt --catalog cli/internal/testdata/catalog policy java21-distroless --engine kyverno --environment production --namespace apps
./clearcutt exceptions validate exceptions.yaml --fail-on-expired-exceptions
./clearcutt vex --help
```

`policy` generates Kubernetes admission policy examples. `exceptions` governs
time-boxed vulnerability exceptions. `vex` emits OpenVEX documents.

ClearCutt reports and gates on vulnerabilities; it does not patch images. The
`remediation` and `overlay` command groups, which drafted Nix overlay patches
for the images ClearCutt built, were removed along with the fleet they served.
`remediation.policy` in `clearcutt.yaml` still drives the severity
thresholds `scan` and `verify` gate on.

## Drift Check Scope

The PR gate validates high-traffic command snippets that are expected to be
executable from this checkout. Commands that require registry credentials,
cluster access, or fork-specific values must be marked as examples and should
use placeholders such as `YOUR_ORG`.
