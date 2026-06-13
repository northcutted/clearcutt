# ClearCutt Documentation

Use this page as the documentation front door. Each role gets one first
document, one first command, and then deeper links.

| Role | First document | First command | Then read |
| --- | --- | --- | --- |
| App developer | [Getting started](getting-started.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog inspect java21-distroless` | [App lifecycle](app-lifecycle.md), [Certification](certification.md) |
| Platform owner | [Platform kit](platform-kit.md) | `go -C cli run ./cmd/clearcutt platform status --output "$PWD" --fleet-config clearcutt.fleet.yaml` | [Fork validation](fork-validation.md), [Site generator](site-generator.md), [Service images](service-images.md) |
| Security or auditor | [Trust evidence walkthrough](trust/evidence-walkthrough.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog verify image java21-distroless --require-signature --require-sbom --require-provenance --allow-preview` | [Catalog evidence](trust/catalog-evidence.md), [Security model](security-model.md), [Policy bundles](policy-bundles.md) |
| Manager | [Alternatives and fit](alternatives.md) | `sed -n '1,120p' docs/alternatives.md` | [Enterprise adoption](enterprise-adoption.md), [Platform kit](platform-kit.md) |
| Open-source reviewer | [Demo path](demo.md) | `go -C cli run ./cmd/clearcutt --catalog internal/testdata/catalog list` | [Mental model](concepts/mental-model.md), [Glossary](concepts/glossary.md), [CLI reference](cli-reference.md) |

## Concept Docs

- [Mental model](concepts/mental-model.md): the platform loop, app-delivery loop,
  lanes, tiers, evidence, and ownership boundaries.
- [Glossary](concepts/glossary.md): canonical definitions for repeated terms.

## Proof Docs

- [Trust evidence walkthrough](trust/evidence-walkthrough.md): trace source,
  release workflow, image digest, SBOM, provenance, catalog record, and policy.
- [Catalog evidence walkthrough](trust/catalog-evidence.md): understand evidence
  badges, missing data, raw evidence, and generic OCI mode.
- [CVE draft agent threat model](trust/cve-agent-threat-model.md): understand
  the untrusted advisory/model-output boundary for remediation drafts.
- [Catalog generator](catalog-generator.md): generate and validate catalog data.
- [Catalog schema](catalog-schema.md): inspect the JSON contract.

## Operating Docs

- [Platform kit](platform-kit.md): fork and operate the platform-owned image
  lanes.
- [Fork validation](fork-validation.md): check identities, workflows, registry,
  Pages, and remediation defaults before release.
- [Site generator](site-generator.md): build and customize a generated evidence
  portal.
- [Policy bundles](policy-bundles.md): generate admission policies.

## App-Team Docs

- [Getting started](getting-started.md): choose an image, generate a starter,
  build, certify, and hand evidence to CI.
- [App lifecycle](app-lifecycle.md): app build, diff-base, rebase, and
  attestation examples across stacks.
- [Certification](certification.md): local/offline app-image checks.
