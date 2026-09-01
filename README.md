# ClearCutt

**Point it at a registry. Find out which images are built on what, how stale
they are, and what you can actually prove about them.**

[![Live Catalog Site](https://img.shields.io/badge/Live%20Catalog-Site-blueviolet.svg?logo=astro&logoColor=white)](https://northcutted.github.io/clearcutt)
[![ClearCutt PR Gating](https://github.com/northcutted/clearcutt/actions/workflows/pr-gate.yml/badge.svg)](https://github.com/northcutted/clearcutt/actions/workflows/pr-gate.yml)
[![Nix Flake](https://img.shields.io/badge/Nix-Flake-blue.svg?logo=nixos&logoColor=white)](https://nixos.org)
[![SLSA Provenance](https://img.shields.io/badge/SLSA-Provenance-green.svg)](https://slsa.dev)
[![Cosign Signed](https://img.shields.io/badge/Sigstore-Cosign%20Signed-orange.svg)](https://sigstore.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

ClearCutt is a free, open-source CLI for governing container image estates —
including estates it did not build. It enumerates a registry, works out which
images are layered on which, measures how far each consumer has drifted from its
base, reports what the fleet has in common, and produces an auditable inventory
that is honest about what it cannot prove.

There is no hosted control plane and no image feed to subscribe to. ClearCutt
reads registries you already have and writes files you own.

![Terminal demo of fixture-backed ClearCutt catalog inspection, image verification, app template generation, and catalog site build](docs/images/demo.gif)

## What It Does

| | Command | Question it answers |
| --- | --- | --- |
| **Discover** | `registry scan` | What is actually published under this namespace? |
| **Map** | `graph build` | Which images are built on which, and how stale is each one? |
| **Compare** | `graph layers` | What does the fleet have in common, and what would a fix reach? |
| **Assess** | `import observe` → `import assess` | What evidence exists per image, and what is missing? |
| **Gate** | `verify`, `certify`, `policy` | Does this image meet policy, at CI and at admission? |
| **Publish** | `catalog build`, `catalog site build` | A static evidence portal anyone can read. |

None of that requires ClearCutt to have built the image, or requires anyone to
adopt Nix, buildpacks, or a particular Dockerfile.

### It says what it cannot prove

The distinguishing behaviour is refusal to overclaim. A base relationship found
by comparing layer digests is reported as **proof**; one read from an
`org.opencontainers.image.base.digest` label is reported as a **claim its author
made**, and a self-reported label never outranks layer evidence. Imported images
never gain provenance they did not come with. Images whose base cannot be
determined are listed as findings, with the reason.

## The Reference Fleet

ClearCutt also builds ONE hardened base-image line with Nix — java25, in
`dev`/`slim`/`distroless` tiers, on amd64 and arm64.

The node, python and go recipes ship in `core/lib/registry.nix` as a library a
fork enables by adding a line to `clearcutt.fleet.yaml`. They are evaluated on
every run so an unbuilt recipe cannot rot unnoticed, but they are not built and
not published.

**These are reference fixtures, not a product.** They exist so the build,
signing, attestation and verification paths are demonstrable end to end, and so
the governance commands have real ClearCutt-built images to point at. They are
not a maintained image feed, and you should not depend on them. If you want a
hardened image feed, use one of the [alternatives](docs/alternatives.md) — that
is a market with several serious vendors and one free Apache-2.0 catalog.

What ClearCutt is for is the layer above: knowing what you are running, proving
where it came from, and noticing when it drifts.

## First Proof From A Clean Clone

These commands use the committed catalog fixture, so they work before you
generate or publish your own catalog data:

```bash
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog catalog validate

go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --max-critical 0 \
  --max-high 3 \
  --allow-preview
```

`verify image` is a catalog policy gate. It checks catalog-record evidence flags,
smoke tests, lifecycle status, and vulnerability thresholds. Use
`verify release-evidence`, Cosign, GitHub attestations, and SLSA verification
when you need registry-side cryptographic proof for a published OCI ref.

## Point It At A Registry

The clean-clone commands above read a committed fixture. This reads a real
registry. Every step is read-only: it lists tags and reads manifests and image
configs, and writes local files. Nothing is pulled, mutated, or published.

```bash
go -C cli build -o ../clearcutt ./cmd/clearcutt

# 1. Ask the registry what it holds. Registries without a _catalog endpoint
#    (GHCR, Docker Hub) need --repository, which repeats.
export GHCR_TOKEN=$(gh auth token)
./clearcutt registry scan \
  --registry ghcr.io --namespace YOUR_ORG/YOUR_REPO \
  --repository YOUR_BASE_IMAGE --repository YOUR_APP_IMAGE \
  --username YOUR_USER --password-env GHCR_TOKEN \
  --output dist/scan/images.yaml

# 2. Read each image's manifest, config, layers, and labels.
./clearcutt import observe \
  --images dist/scan/images.yaml --output dist/scan/observations.json

# 3. Work out which images are built on which, and how stale each one is.
./clearcutt graph build \
  --observations dist/scan/observations.json \
  --output dist/scan/graph.json --report dist/scan/inventory.md

# 4. Report what the fleet has in common, with a diagram.
./clearcutt graph layers \
  --observations dist/scan/observations.json \
  --output dist/scan/layers.json --report dist/scan/commonality.md
```

`graph build` writes an auditable inventory: base families, which consumers sit
on which version, how many versions and days behind each one is, and how every
relationship was established. `graph layers` answers the remediation question —
if a layer carries a vulnerable package, which images ship it.

Both can gate CI. `graph build --min-confidence verified --fail-on-stale` exits
2 when anything is on a stale base, and still writes the report.

Pass the results to the site builder to publish them as pages — `/estate` and
`/estate/layers` — with `catalog site build --graph … --layers …`.

See [registry scan and the base image graph](docs/registry-graph.md).

## Install

Each release publishes cross-compiled CLI binaries named
`clearcutt-<os>-<arch>` for `darwin`, `linux`, and `windows` on `amd64` and
`arm64`, a keyless Sigstore signature bundle (`<binary>.sig`) for each, and a
`SHA256SUMS.txt` checksum manifest. Download the binary for your platform and
its `.sig` bundle from the
[latest release](https://github.com/northcutted/clearcutt/releases/latest),
then verify the signature before running anything:

```bash
# Example assets: Apple Silicon macOS. Pick the pair matching your OS/arch.
cosign verify-blob \
  --bundle clearcutt-darwin-arm64.sig \
  --certificate-identity 'https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  clearcutt-darwin-arm64

chmod +x clearcutt-darwin-arm64
```

The certificate identity is the release workflow pinned to `refs/heads/main` —
the same identity recorded in `clearcutt.fleet.yaml` and matched exactly by
`clearcutt verify release-evidence`. From a repo clone, the verified binary
runs the same fixture-backed first proof as above:

```bash
./clearcutt-darwin-arm64 --catalog cli/internal/testdata/catalog list
```

Building from source stays the contributor path; see
[CONTRIBUTING.md](CONTRIBUTING.md) and the clean-clone proof above.

## Where To Start

| Role | First document | First useful command |
| --- | --- | --- |
| Estate owner | [Registry scan and the base image graph](docs/registry-graph.md) | `go -C cli run ./cmd/clearcutt registry scan --registry ghcr.io --namespace YOUR_ORG/YOUR_REPO --repository YOUR_IMAGE --output /tmp/images.yaml` |
| App developer | [Getting started](docs/getting-started.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless` |
| Imported fleet owner | [Imported fleets](docs/imported-fleets.md) | `go -C cli run ./cmd/clearcutt import images --refs ../examples/imported-fleet/refs.txt --output /tmp/clearcutt-import/images.yaml --force` |
| Platform owner | [Platform bootstrap](docs/platform-kit.md) | `go -C cli run ./cmd/clearcutt platform bootstrap github --profile catalog-only --owner YOUR_ORG --repo image-platform --registry-base ghcr.io/YOUR_ORG/image-platform --dir ./image-platform --dry-run --force` |
| Security or auditor | [Trust evidence walkthrough](docs/trust/evidence-walkthrough.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --allow-preview` |
| Engineering manager | [Alternatives and fit](docs/alternatives.md) | `sed -n '1,120p' docs/alternatives.md` |
| Open-source evaluator | [Demo path](docs/demo.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list` |

For a deterministic imported-fleet proof that does not require Nix or registry
access:

```bash
# Offline deterministic demo
./scripts/demo-imported-fleet-offline.sh

# The script prints a unique output directory. To use a fixed path:
OUT=/tmp/clearcutt-import-demo ./scripts/demo-imported-fleet-offline.sh
cat /tmp/clearcutt-import-demo/imported-fleet-report.md
```

ClearCutt can govern imported images without trusting them by default. It
records what can be observed, preserves missing evidence, and only treats
provenance as verified when actual provenance evidence exists.

To prove the two-repository operating model without copying this source tree,
render a release-backed control plane that consumes selected evidence from the
ClearCutt release repository:

```bash
go -C cli run ./cmd/clearcutt platform render /tmp/clearcutt-demo \
  --profile catalog-only \
  --catalog-source github-release \
  --catalog-source-repo northcutted/clearcutt \
  --catalog-targets java21-distroless,node24-slim,python3.14-dev \
  --catalog-release-limit 1 \
  --owner northcutted \
  --repo clearcutt-demo \
  --registry-base ghcr.io/northcutted/clearcutt \
  --visibility public \
  --pages

./scripts/test-generated-release-control-plane.sh
```

The generated repository contains workflows, desired state, operator docs, and
site configuration, but no `cli/`, `core/`, `site/`, or Nix source. Creating a
remote repository remains an explicit `platform bootstrap github --apply
--confirm` action.

The full documentation index is [docs/README.md](docs/README.md).

Contributor note: if the platform-source drift check fails, refresh the
embedded source archive with:

```bash
go -C cli run ./internal/platformsource/internal/genplatformsource
```

## Portal Preview

These screenshots are generated from the committed mixed catalog fixture, not
from ignored local site data.

![Fixture-backed catalog matrix showing runtime and service image records](docs/images/catalog-matrix.png)

![Fixture-backed java21-distroless evidence view showing verification commands and recorded release evidence](docs/images/java21-distroless-evidence.png)

## Proof Map

- [Mental model](docs/concepts/mental-model.md) explains the two loops:
  platform teams publish the fleet; app teams adopt, gate, admit, and update.
- [Glossary](docs/concepts/glossary.md) defines lanes, tiers, evidence,
  certification, verification, exceptions, VEX, rebase, preview, and scaffold.
- [CLI reference](docs/cli-reference.md) maps the current command surface.
- [Catalog generator](docs/catalog-generator.md) explains generated catalog
  data, raw evidence directories, validation, and generic OCI mode.
- [Catalog evidence walkthrough](docs/trust/catalog-evidence.md) explains what
  the portal proves, what it only reports, and how missing evidence appears.
- [Security model](docs/security-model.md) documents trust boundaries and
  non-claims.
- [Policy bundles](docs/policy-bundles.md) covers Kyverno and Gatekeeper policy
  generation.
- [Fork validation](docs/fork-validation.md) lists checks to run before an advanced fork's
  first release.

## Repo Layout

| Workspace | Purpose |
| --- | --- |
| `core/` | Nix build recipes for the four reference-fixture runtime lines. |
| `cli/` | Go governance CLI and tests. |
| `site/` | Astro catalog portal and generated-site template source. |
| `docs/` | Role-routed documentation, trust walkthroughs, and operating guides. |
| `examples/` | App templates, deployment manifests, policy examples, and overlays. |
| `.github/` | Release, catalog/Pages, PR gate, flake update, and cache workflows. |

## Boundaries

ClearCutt is pre-1.0 and intentionally conservative in its claims.

**It reports and gates. It does not patch.** ClearCutt will tell you an image is
on a stale base, is missing a signature, or ships a layer with a known CVE. It
will not rebuild, re-tag, or mutate a published image to fix that. `app rebase`
prepares and proves a base swap; publishing it stays a human decision.

**Currency is measured against what a scan observed**, not against upstream. A
base family that is itself out of date will still report its consumers current.

**The reference fleet is a fixture.** It is built from a nixpkgs pin that moves
when someone merges the update PR. Do not run it in production, and do not read
its single runtime line as a supported image feed.

Use ClearCutt when you need to know what is in your registry and prove things
about it. Do not use it when you primarily want a vendor SLA, a hosted control
plane, a managed patch stream, or FIPS/STIG certification out of the box — see
[alternatives and fit](docs/alternatives.md).

## Security

See [SECURITY.md](SECURITY.md) for the supported-release policy and how to
report vulnerabilities privately.
