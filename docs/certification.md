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

It **cannot verify offline** and reports these as `SKIP`, never `PASS`:
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
- uses: northcutted/clearcutt/.github/actions/certify-app@v0.11.1
  with:
    image: ghcr.io/acme/my-app@sha256:fedcba...
    policy: policies/production.yaml
    base: java25-distroless
    # Required when the policy requires signature/provenance/SBOM verification —
    # pin the signer identity that built/signed the image (wildcards are refused):
    certificate-identity-regexp: 'https://github.com/acme/.*/.github/workflows/.*'
```

### 2.2 Rebasable Application Images

`clearcutt app build` creates a registry-pushed application image from a prebuilt
artifact and a ClearCutt base. It stamps the OCI config with:
- the catalog base id and version,
- a digest-pinned base reference,
- the compressed digest of the final base layer,
- `dev.clearcutt.app.rebasable=true`.

Those labels define the base/application boundary used later by `clearcutt app
rebase`. The rebase command refuses to continue if the recorded boundary does not
match the old base, and go-containerregistry re-checks the rootfs `diff_ids`
before rewriting config history for the new base.

Example:
```bash
clearcutt app build \
  --base java21-distroless \
  --artifact target/app.jar \
  --dest /workspace/app.jar \
  --entrypoint '["java","-jar","/workspace/app.jar"]' \
  --image ghcr.io/acme/payments-api:1.0.0
```

For stack-specific `app build` examples covering Core/static, Java, Node.js,
Python, Go, .NET, Rust, and C/C++, see
[`docs/app-lifecycle.md`](app-lifecycle.md).

### 2.3 Zero-Rebuild Rebasing

`clearcutt app rebase` is intentionally more privileged than the offline
governance commands: it reads and writes an OCI registry and can call `cosign`.
For production use, run it from a dedicated CI workflow with `id-token: write`.

The default trust model is dual-control at rebase time:
- the source image is verified against `--dev-identity` and `--dev-issuer`,
- the rebased image is signed by the rebase-engine workflow with `--sign`,
- the rebase predicate is attached with `--attest`,
- an `allowed` predicate cannot be emitted unless the developer signature check
  succeeded.

```bash
clearcutt app rebase \
  --image ghcr.io/acme/payments-api:1.0.0 \
  --candidate-base ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless-v0.2.2 \
  --candidate-base-id java21-distroless \
  --tag ghcr.io/acme/payments-api:1.0.0-rebased \
  --dev-identity 'https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main' \
  --sign \
  --attest
```

### 2.4 GitLab CI Integration
For GitLab CI pipelines, execute the certification audit inside a secure runner stage by downloading the compiled release binary:
```yaml
certify:
  stage: test
  image: alpine:latest
  # Pin a released CLI version — never track a moving tag in a supply-chain gate.
  # Bump this as you adopt new releases.
  variables:
    CLEARCUTT_VERSION: "v0.11.1"
  before_script:
    - apk add --no-cache curl
    - curl -fsSL -o /usr/local/bin/clearcutt "https://github.com/northcutted/clearcutt/releases/download/${CLEARCUTT_VERSION}/clearcutt-linux-amd64"
    - chmod +x /usr/local/bin/clearcutt
  script:
    - clearcutt certify app-image.tar --policy policy.yaml --base java25-distroless
  artifacts:
    paths:
      - certification-report.json
```
