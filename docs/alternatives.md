# ClearCutt Alternatives And Fit

ClearCutt is a good fit when owning the image supply chain is the requirement.
It is a poor fit when a team primarily wants a vendor SLA or a hosted control
plane.

## Use ClearCutt When

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

## Do Not Use ClearCutt When

- You need a vendor support contract or managed patch SLA more than ownership.
- You need FIPS/STIG certification out of the box.
- You do not want to maintain GitHub Actions workflows, registry permissions,
  release approvals, or vulnerability triage.
- Your organization cannot operate Nix-backed platform builds.
- You want a hosted commercial product with centralized policy management.

## Category Comparison

| Category | Strength | Tradeoff |
| --- | --- | --- |
| Vendor hardened feed | Operationally simple, often paired with support and patch commitments. | Less ownership over workflow identity, build inputs, catalog shape, and release process. |
| Buildpacks | Strong app build ergonomics and common language patterns. | Different control model; not primarily an owned base-image fleet and evidence portal. |
| DIY internal platform | Maximum control and local conventions. | Highest implementation and maintenance cost. |
| ClearCutt fork | Ownable blueprint with image factory, catalog, evidence, policy, and app path. | Fork owner must run, verify, and maintain the platform. |

## Manager-Level Decision

Choose ClearCutt when the business value is control and inspectability. Choose a
managed feed when the business value is outsourcing operations and buying a
support contract.
