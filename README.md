# ClearCutt

**The forkable platform kit and reference implementation for publishing owned,
evidence-backed base images.**

[![Live Catalog Site](https://img.shields.io/badge/Live%20Catalog-Site-blueviolet.svg?logo=astro&logoColor=white)](https://northcutted.github.io/clearcutt)
[![ClearCutt PR Gating](https://github.com/northcutted/clearcutt/actions/workflows/pr-gate.yml/badge.svg)](https://github.com/northcutted/clearcutt/actions/workflows/pr-gate.yml)
[![Nix Flake](https://img.shields.io/badge/Nix-Flake-blue.svg?logo=nixos&logoColor=white)](https://nixos.org)
[![SLSA Provenance](https://img.shields.io/badge/SLSA-Provenance-green.svg)](https://slsa.dev)
[![Cosign Signed](https://img.shields.io/badge/Sigstore-Cosign%20Signed-orange.svg)](https://sigstore.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

ClearCutt is a free, open-source platform kit for teams that want to own their
container image supply chain. Fork it into your organization and operate an
image fleet, release workflows configured for signing and attestation, catalog
data, a static evidence portal, CI/CD gates, admission policy examples,
app-team templates, and remediation workflows under **your** registry, GitHub
Actions OIDC identities, and review process.

There is no hosted ClearCutt control plane. The repository is the control plane:
your fork owns the configuration, builds, evidence, catalog, policies, and
operational burden.

## What It Is

ClearCutt is best understood as a **forkable platform kit and reference
implementation**, not a hosted product. It provides the pieces a platform team
can fork, configure, run, inspect, and adapt:

| Surface | What it does today | Owner |
| --- | --- | --- |
| Runtime base images | Publishes language runtime images in `dev`, `slim`, and `distroless` tiers. | Platform team |
| Service images | Publishes platform-owned service images such as Postgres, Valkey, and oauth2-proxy. | Platform team |
| Catalog and portal | Reports image metadata, evidence channels, vulnerability scans, tests, and missing data. | Platform team |
| App path | Gives app teams templates, devcontainers, local certification, app build, and rebase examples. | App teams |
| Trust controls | Provides signing, SBOM, provenance, policy, exception, VEX, and remediation examples. | Platform and security teams |

Nix is the backend build engine for platform-owned images. App teams consume the
fleet with Docker, Podman, Kubernetes, Cosign, and the ClearCutt CLI; they do
not need to learn Nix.

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

## Where To Start

| Role | First document | First useful command |
| --- | --- | --- |
| App developer | [Getting started](docs/getting-started.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless` |
| Platform owner | [Platform kit](docs/platform-kit.md) | `go -C cli run ./cmd/clearcutt platform status --output "$PWD" --fleet-config clearcutt.fleet.yaml` |
| Security or auditor | [Trust evidence walkthrough](docs/trust/evidence-walkthrough.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --allow-preview` |
| Engineering manager | [Alternatives and fit](docs/alternatives.md) | `sed -n '1,140p' docs/alternatives.md` |
| Open-source evaluator | [Demo path](docs/demo.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list` |

The full documentation index is [docs/README.md](docs/README.md).

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
- [Fork validation](docs/fork-validation.md) lists checks to run before a fork's
  first release.

## Repo Layout

| Workspace | Purpose |
| --- | --- |
| `core/` | Nix image factory, runtime overlays, release pipeline, scans, and conformance tests. |
| `cli/` | Go governance CLI and tests. |
| `site/` | Astro catalog portal and generated-site template source. |
| `docs/` | Role-routed documentation, trust walkthroughs, and operating guides. |
| `examples/` | App templates, deployment manifests, policy examples, and overlays. |
| `.github/` | Release, catalog, Pages, remediation, PR, and rebase workflows. |

## Boundaries

ClearCutt is pre-1.0 and intentionally conservative in its claims. The reference
repo demonstrates a production-oriented blueprint, but fork owners must operate
their own registry, workflow identities, release approvals, catalog data,
admission policies, exception process, and remediation defaults.

Use ClearCutt when owning the full image supply chain is the point. Do not use
it when you primarily want a vendor SLA, hosted control plane, fully managed
patch stream, or FIPS/STIG certification out of the box.
