# Phase 12 Horizon Epics

Status: design intake for owner scoping. These epics are not implemented in this
branch. Each item should become its own design note and PR series after the
maintainer confirms scope.

## Executive Readout

Phase 12 is the next layer of showcase work after the fixture-backed demo assets:
turn ClearCutt's evidence story into repeatable, comparable, and externally
inspectable receipts. The highest-leverage first epic is the receipts comparison
workflow, but it depends on the runtime hardening and matrix cleanup from Phase 7.

## Epic Candidates

| Epic | Outcome | Main dependency | First design question |
|---|---|---|---|
| Nix-closure-derived SBOM | Generate SPDX/CycloneDX from the derivation graph and attest it as authoritative, while keeping Syft as a scanner cross-check. | Stable Nix graph extraction for each image target. | Should the authoritative SBOM be SPDX, CycloneDX, or both? |
| Receipts comparison workflow | Scheduled comparison of one Java service on ClearCutt, Eclipse Temurin, gcr.io/distroless, and Chainguard JRE across size, packages, CVEs, and verification outcomes. | Phase 7 headless/runtime cleanup. | Which app fixture and competitor image tags should be pinned? |
| Remediation feed | Publish `core/overlays/cve/` overlay and evidence pairs as JSON/RSS, plus a `clearcutt remediation pull <CVE-ID>` path. | Stable overlay evidence schema and trust policy. | Is the feed advisory-only, signed, or both? |
| `clearcutt attest verify <ref>` and composite action | Package registry-side Cosign, SLSA, SBOM, and test-attestation checks for CI consumers. | Phase 10 structured exit codes. | Should the action verify only ClearCutt images or generic OCI refs with compatible evidence? |
| Declarative `hardening:` block | Emit OCI config expectations, Kubernetes `securityContext`, and Kyverno policy from one fleet-config source. | Fleet schema expansion and policy-bundle compatibility. | Which knobs are required in v1 without overpromising runtime enforcement? |

## Recommended Order

1. Finish Phase 7 first so the receipts workflow compares a credible
   headless/minimal Java runtime line.
2. Design `clearcutt attest verify <ref>` next because it turns existing
   release-evidence code into a reusable app-team and CI surface.
3. Prototype Nix-derived SBOM generation behind an experimental flag, keeping
   Syft-scanned SBOMs as the current published evidence until parity is proven.
4. Add the receipts workflow once the Java fixture, competitor tags, scanner
   versions, and output schema are pinned.
5. Treat remediation feed and declarative hardening as separate PR series after
   the evidence and comparison primitives are stable.

## Decisions Needed

- Pick the first Phase 12 epic to design.
- Confirm whether Phase 12 outputs belong in the public docs, generated portal,
  CLI, GitHub Actions, or all four.
- Decide whether comparison data may depend on network access in scheduled CI or
  must be reproducible from pinned fixtures.
- Decide whether experimental outputs should be hidden from the default catalog
  until release-evidence verification covers them.
