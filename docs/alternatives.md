# ClearCutt Alternatives And Fit

ClearCutt is a good fit when owning the image supply chain is the requirement.
It is a poor fit when a team primarily wants a vendor SLA or a hosted control
plane.

This page compares ClearCutt with common approaches a platform team might use
instead:

- apko and Chainguard Images
- gcr.io/distroless
- plain `pkgs.dockerTools`
- Docker multi-stage builds

## Manager Readout

Choose ClearCutt when the business value is control and inspectability: your
fork owns the build recipes, registry namespace, GitHub Actions OIDC identity,
catalog shape, policy examples, exceptions, and remediation process.

Choose a managed feed such as Chainguard Images when the business value is
outsourcing operations and buying support, patch cadence, and vendor
accountability.

Choose gcr.io/distroless, Docker multi-stage, or direct `pkgs.dockerTools` when
the team wants narrower base-image or build mechanics without adopting a
repository-backed evidence portal and governance CLI.

## What The Repo Proves Today

The fixture-backed demo path is the clean-clone proof:

```bash
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview
go -C cli run ./cmd/clearcutt catalog site build \
  --catalog internal/testdata/mixed-catalog \
  --template ../site \
  --output /tmp/clearcutt-demo-site \
  --install
```

The committed mixed-catalog fixture used for the README screenshots contains:

| Fixture record | Kind | Evidence shown | Package count shown | Vulnerability status shown |
|---|---:|---|---:|---|
| `java21-distroless` | Runtime | Signature, provenance, SBOM, tests, scan data | 2 packages | Scan data attached |
| `postgres16` | Service | Signature, provenance, SBOM, smoke test, scan data | 3 packages | 0 critical / 0 high in fixture |

Those are fixture numbers, not a claim about the current live release fleet.
For a published fork, use the live catalog and release-evidence commands before
making production decisions.

## Comparison Matrix

| Axis | ClearCutt fork | apko / Chainguard | gcr.io/distroless | Plain `pkgs.dockerTools` | Docker multi-stage |
|---|---|---|---|---|---|
| Primary value | Own the image factory, registry, evidence portal, gates, and remediation workflow. | Consume or build minimal images with a strong security-oriented ecosystem and optional managed feed. | Consume minimal base images maintained by the upstream project. | Build OCI images from Nix derivations with direct control over closures. | Keep app builds familiar to Docker users and CI systems. |
| Control plane | Your Git repository and workflows. | Vendor/service ecosystem or your apko configs. | Upstream image registry plus your app repo. | Your Nix code and CI. | Your Dockerfiles and CI. |
| Evidence surface | Catalog records, SBOM links, signatures, provenance, tests, scans, exceptions, VEX, and portal pages when configured. | Depends on chosen Chainguard/apko workflow and subscription tier. | Upstream image metadata plus whatever your own pipeline adds. | Whatever you generate around the Nix build. | Whatever your CI adds around the Docker build. |
| App-team path | Dockerfile templates, devcontainers, local certify/verify commands, and rebase examples. | Usually app teams consume base images; app workflow depends on your platform design. | App teams consume base images directly. | App teams may need Nix literacy unless platform owners wrap it. | App teams already understand the model. |
| SBOM derivation | Syft-scanned catalog evidence today; Nix-derived SBOM is a planned Phase 12 epic. | Depends on apko/Chainguard workflow. | Not controlled by your fork unless you rescan. | Can be derived from the Nix graph if you build that pipeline. | Usually scanner-derived after image build. |
| Verification command | `clearcutt verify image` for catalog policy; `verify release-evidence` for registry-side proof. | Vendor or apko-specific verification paths. | Standard registry, cosign, and scanner tools where evidence exists. | Nix evaluation/build checks plus any custom scanner/signing scripts. | Scanner/signing scripts added by your CI. |
| Operational burden | Highest among packaged options: the fork owner operates the platform. | Lower if buying managed images; moderate if self-operating apko. | Low for base image consumption. | Medium to high; depends on Nix expertise. | Low to medium; hardening and evidence are your responsibility. |
| Best fit | Platform teams that want ownership and inspectable evidence over convenience. | Teams that want minimal images and are comfortable with the Chainguard/apko model. | Teams that want common minimal upstream bases quickly. | Nix-first teams that want precise closure control. | App teams optimizing for familiarity and speed. |

## Static Measurement Axes

Use these axes when comparing a ClearCutt fork with another base-image strategy.
Phase 12 proposes turning this into a scheduled receipts workflow.

| Measurement | ClearCutt command or source | Why it matters |
|---|---|---|
| Compressed image size | Catalog `imageSize`, per-arch layer sizes, or registry manifest layer sums. | Shows network and startup cost. |
| Package count | Catalog `latestPackageCount` and SBOM package tables. | Provides a rough closure-size and review-surface signal. |
| Critical/high CVEs | Catalog vulnerability summary and scanner output. | Helps compare risk posture, but must include scanner version and DB time. |
| SBOM source | Catalog SBOM links plus future Nix-derived SBOM work. | Separates scanned evidence from build-graph-derived evidence. |
| Signature identity | `verify release-evidence` expected OIDC subject and issuer. | Proves which workflow identity signed a release. |
| Provenance builder | SLSA/GitHub attestation payloads. | Connects source, builder, and subject digest. |
| App adoption friction | Time to generate a template, build an app, certify locally, and rebase. | Keeps the comparison grounded in app-team experience. |

## When To Use ClearCutt

- You want your organization to own the registry namespace, release workflows,
  OIDC identities, catalog, admission policies, exceptions, and remediation
  process.
- Platform engineers can operate a repository-backed image factory.
- App teams need a paved path that uses Docker, Podman, Kubernetes, Cosign, and
  the ClearCutt CLI instead of Nix.
- Security reviewers need inspectable evidence surfaces rather than opaque
  trust in a feed.
- You are willing to treat the upstream repo as a reference implementation and
  validate your fork independently.

## When Not To Use ClearCutt

- You need a vendor support contract or managed patch SLA more than ownership.
- You need FIPS/STIG certification out of the box.
- You do not want to maintain GitHub Actions workflows, registry permissions,
  release approvals, or vulnerability triage.
- Your organization cannot operate Nix-backed platform builds.
- You want a hosted commercial product with centralized policy management.
