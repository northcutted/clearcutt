# ClearCutt Mental Model

ClearCutt has three loops. The first is the product; the other two exist because
they were needed to prove the first one works.

## 1. Governance Loop

This is the main path, and it does not require ClearCutt to have built anything:

1. Enumerate a registry namespace into an inventory (`registry scan`).
2. Read each image's manifest, config, layers, and labels (`import observe`).
3. Derive which images are built on which and how stale each is (`graph build`),
   and what the estate has in common (`graph layers`).
4. Assess what evidence each image carries and what is missing
   (`import assess`), without inferring provenance that was never there.
5. Gate on the result at CI (`verify`, `certify`, `graph build --fail-on-stale`)
   and at admission (`policy`).
6. Publish the catalog and evidence portal (`catalog build`,
   `catalog site build`).

Nothing in this loop needs Nix, a particular Dockerfile, or cooperation from
whoever built the images.

## 2. Platform Loop

A platform team that wants to build its own base images can. This is how the
project's single reference fixture is produced:

1. Configure runtime and service lanes in `clearcutt.fleet.yaml`.
2. Build platform-owned images with the Nix backend.
3. Publish images to the fork owner's registry.
4. Attach release evidence when configured: signatures, SBOMs, provenance, test
   results, scans, and release metadata.
5. Generate catalog data and publish the evidence portal.
6. Maintain admission policy examples and exceptions.

This loop is where Nix belongs. It is platform-owner machinery, not an
app-team prerequisite — and it is optional. ClearCutt governs estates it did
not build; this loop only matters if you want to be the builder too.

## 3. App-Delivery Loop

Application teams consume the fleet with normal container tooling:

1. Choose a runtime and tier from the catalog.
2. Generate or copy an app starter.
3. Build with a `dev` image and run with `slim` or `distroless`.
4. Certify the app image locally or in CI.
5. Admit only images that satisfy the platform's evidence and vulnerability
   policy.
6. Rebase compatible app images onto newer bases under review when needed.
   `app rebase` verifies by layer diff_id that the app sits on the old base, so
   it works on any image, not only ones built by ClearCutt or buildpacks.

## Lanes

- Runtime base images are platform-owned language images for application teams.
- Service images are platform-owned backing services such as Postgres, Valkey,
  and oauth2-proxy.
- Application images are downstream products built by app teams on top of the
  fleet. They are not a third platform-owned lane.

## Tiers

- `dev`: toolchains, compilers, shells, and build-time utilities.
- `slim`: smaller runtime tier that keeps a shell for diagnostics.
- `distroless`: production-oriented runtime tier without shells or package
  managers.

## Evidence

The catalog reports evidence channels independently. A signature, SBOM,
provenance record, vulnerability scan, test result, exception, or VEX document
can be present or missing on its own. Do not treat one green signal as proof
that every channel is complete.

## Verification And Certification

- `verify image` is a catalog policy gate. It checks catalog-record evidence
  flags and thresholds.
- `verify release-evidence`, Cosign, GitHub attestation verification, and SLSA
  verifier commands perform registry-side checks for published OCI refs.
- `certify` audits a downstream app image archive against a local hardening
  policy.
