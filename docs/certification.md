# Downstream Application Certification

Application teams must certify their final compiled image payloads against the corporate platform security contract before scheduling deployments into production namespaces.

---

## 1. Declarative Certification Policies
Certification policies are specified in YAML files matching `schemas/certification-policy.schema.json`.

Example production policy:
```yaml
apiVersion: clearcutt.dev/v1
kind: CertificationPolicy
metadata:
  name: acme-production-policy
spec:
  base:
    allowedImages:
      - java25-distroless
      - python3.14-slim
    requireDigestPinned: true
    requireKnownBase: true
  supplyChain:
    requireSignature: true
    requireProvenance: true
    requireSbom: true
    minimumSlsaLevel: 3
  runtime:
    requireNonRoot: true
    forbidShell: true
    forbidPackageManagers: true
    forbidDevTier: true
```

---

## 1.5 What `certify` checks offline

`clearcutt certify` operates on a local image tarball with no network access. It
accepts both legacy `docker save` archives and OCI-layout archives (`index.json` +
`blobs/`), and transparently reads gzip-compressed layers.

It **verifies offline**:
- non-root `Config.User`,
- required `org.opencontainers.image.*` / `org.clearcutt.*` labels,
- absence of shells and package managers in distroless tiers,
- declared-base allow-listing, digest pinning, and base-image CVE thresholds (against the catalog).

It **cannot verify offline** — and reports these as `↷ SKIP`, never `PASS`:
- Cosign signatures, SBOM attestations, and SLSA provenance. These live as OCI
  *referrers* in the registry, not inside the tarball, and `minimumSlsaLevel`
  likewise cannot be confirmed offline.

To enforce those, verify against the registry in the same pipeline step, e.g.:
```bash
cosign verify "$IMAGE" --certificate-identity-regexp '<your-workflow>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type slsaprovenance "$IMAGE" ...
```

A certification result of `PASS (N skipped)` means the offline contract held but
N attestation checks were deferred to registry-side verification.

---

## 2. CI/CD Pipeline Enforcement

### 2.1 GitHub Actions Integration
Use our composite GitHub Action to automate certification and archive compliance reports:
```yaml
- uses: northcutted/clearcutt/.github/actions/certify-app@v1
  with:
    image: ghcr.io/acme/my-app@sha256:fedcba...
    policy: policies/production.yaml
    base: java25-distroless
```

### 2.2 GitLab CI Integration
For GitLab CI pipelines, execute the certification audit inside a secure runner stage:
```yaml
certify:
  stage: test
  image: ghcr.io/northcutted/clearcutt/cli:latest
  script:
    - clearcutt certify app-image.tar --policy policy.yaml --base java25-distroless
  artifacts:
    paths:
      - certification-report.json
```
