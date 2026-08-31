# ClearCutt Reviewer Demo

This demo path is designed for a clean checkout. Steps marked "fixture-backed"
use committed catalog data. Steps marked "live" require a fork, registry, or
local container tooling.

![Terminal demo of the fixture-backed ClearCutt path](images/demo.gif)

## 1. Explain The Project

```bash
sed -n '1,140p' README.md
sed -n '1,120p' docs/README.md
```

Expected readout: ClearCutt is a CLI for bootstrapping user-owned GitHub
container image control planes, generated repos own the operating surface, and
roles have different first paths. Forking remains an advanced/reference path.

## 2. Fixture-Backed Catalog Proof

```bash
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless
go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview
```

Expected readout: the CLI can list, inspect, and gate catalog data without
generated artifacts.

## 3. App-Team Path

```bash
go -C cli run ./cmd/clearcutt app template java \
  --fleet-config ../clearcutt.fleet.yaml \
  --output /tmp/clearcutt-demo-app \
  --name payments-api \
  --force
sed -n '1,120p' /tmp/clearcutt-demo-app/README.md
```

Expected readout: the generated app contains a Dockerfile, devcontainer,
certification policy, release workflow, and rebase workflow.

## 4. Catalog Portal Build

```bash
go -C cli run ./cmd/clearcutt catalog site build \
  --catalog internal/testdata/mixed-catalog \
  --template ../site \
  --output /tmp/clearcutt-demo-site \
  --install
```

Expected readout: static HTML renders from fixture catalog data, including
service records and image detail pages.

Fixture-backed portal screenshots:

![Catalog matrix generated from the mixed fixture catalog](images/catalog-matrix.png)

![java21-distroless evidence section generated from the mixed fixture catalog](images/java21-distroless-evidence.png)

## 5. Generated Control-Plane Proof

Render the repository that a released CLI can create without copying the
ClearCutt source tree:

```bash
go -C cli run ./cmd/clearcutt platform render /tmp/clearcutt-control-plane-demo \
  --profile catalog-only \
  --catalog-source github-release \
  --catalog-source-repo northcutted/clearcutt \
  --catalog-targets java21-distroless,node22-slim,python3.14-dev \
  --catalog-release-limit 1 \
  --owner northcutted \
  --repo clearcutt-demo \
  --registry-base ghcr.io/northcutted/clearcutt \
  --visibility public \
  --pages

./scripts/test-generated-release-control-plane.sh
```

Expected readout: the generated repository contains control-plane desired
state, pinned workflows, operator docs, and Pages configuration. It contains no
`cli/`, `core/`, `site/`, `images.yaml`, or Nix source. The deterministic smoke
build uses committed evidence fixtures; the public demo workflow later consumes
real GitHub release evidence.

## 6. Live Trust Walkthrough

Use [trust/evidence-walkthrough.md](trust/evidence-walkthrough.md) after a fork
has published at least one release. The fixture screenshots above prove local
rendering and catalog wiring; a fork owner should additionally compare them with
the live Pages site for that fork's current registry, OIDC subject, signatures,
SBOMs, provenance, scans, tests, and exception records.

## Feedback Questions

- Can the reviewer explain what ClearCutt is in one minute?
- Can they tell what is fixture-backed versus live registry proof?
- Can an app developer find the template/dev/certify path without learning Nix?
- Can a security reviewer trace a release identity from config to policy?
- Can a platform owner see what their fork must operate?
- Can they distinguish the CLI source repository from the generated catalog
  control-plane repository?
