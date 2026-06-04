# ClearCutt Product Story Audit

This document is the current audit surface for homepage and README positioning.
It exists to keep the public story aligned with the product reality in code,
catalog data, and workflows.

## Product Story

ClearCutt should read as one operating model with two connected loops:

- **Platform loop:** fork the kit, configure the fleet, publish signed and
  attested base images, and expose catalog evidence.
- **App delivery loop:** help app teams adopt a base, certify images in CI,
  admit only evidence-backed images, and update compatible apps through reviewed
  rebase/remediation flows.

This framing is intentionally different from a hosted product story. ClearCutt
is a forkable kit run under the adopter's registry, GitHub Actions OIDC
identities, catalog site, and admission policies.

## Current Homepage Alignment

| Surface | Current claim | Audit status |
| :--- | :--- | :--- |
| Hero | Forkable platform kit for hardened base images, with signatures, SBOM attestations, SLSA provenance, catalog evidence, app templates, and governance gates. | Aligned. Avoid implying a hosted ClearCutt control plane. |
| Lifecycle map | Own the fleet, publish evidence, onboard apps, gate delivery, operate updates. | Aligned. This is manager-readable while still naming engineer controls. |
| Evidence coverage | Signatures, provenance, and vulnerability scans are counted independently from catalog data. | Aligned. Missing evidence must remain visible instead of being inferred from another channel. |
| Platform perspective | Fork, publish, catalog, template, certify, and remediate under review. | Aligned. Keep remediation described as approved automation, not silent self-healing. |
| Auditor perspective | Hermetic store closures, structural hardening, and OIDC verification gates. | Aligned when phrased as specific mechanisms, not broad compliance certification. |

## Claim Boundaries

Keep these caveats attached anywhere the same ideas appear:

- **No hosted service implication:** say "forkable kit", "reference catalog", and
  "your OIDC identities"; avoid "managed fleet" unless it clearly means the
  adopter's own fleet.
- **No autonomous remediation claim:** remediation may rank findings and draft
  PRs, but it does not silently merge, deploy, or mutate production workloads.
- **No universal rebase claim:** `app rebase` applies to compatible images with
  ClearCutt rebase labels and a verified developer signature.
- **No zero-risk claim:** scans are point-in-time evidence; distroless reduces
  utility surface but does not eliminate every RCE or future CVE.
- **No FIPS/STIG certification claim:** describe structural checks and optional
  cryptographic customization unless formal validation evidence exists.

## Files That Carry The Story

- `README.md`: canonical manager + engineer SDLC framing.
- `site/src/lib/claims.ts`: homepage claim source of truth.
- `site/src/pages/index.astro`: homepage rendering of the lifecycle map.
- `docs/platform-kit.md`: operator story for forking and running the kit.
- `docs/enterprise-adoption.md`: rollout path from fleet ownership to app
  delivery and operations.
