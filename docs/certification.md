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
