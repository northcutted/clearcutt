# Forking ClearCutt: Downstream Base Image Feeds

ClearCutt is a declarative container hardening blueprint. Downstream organization teams are expected to fork this repository to build, sign, and govern their own custom internal OCI base image feeds rather than utilizing our public catalog directly in production.

This guide outlines how to customize the Nix builder closures, configure custom OCI registries, re-key OIDC signatures, and deploy a self-hosted catalog site.

---

## 1. Customize Matrix Runtimes & Tiers

The source-of-truth configuration for all base image closures lives in the `core/` directory:

1. **Overlay Definitions (`core/overlays/`)**:
   - Each language runtime overlay is declared as a Nix derivation. Add custom configuration switches (e.g. security-patched OpenSSL bindings) directly in the relevant overlays directory.
2. **Registry Mapping (`core/lib/registry.nix`)**:
   - Maps language versions, target architectures, package closures, and compliance settings. Edit this mapping to declare custom target image slots or add your company-specific package variations.
3. **Reproducibility Boundary**:
   - *Bit-for-Bit Reproducibility:* Compiling purely from Nix store closures yields a byte-identical archive every time.
   - *Layering Boundary:* Grafting Nix layers onto a non-Nix base OS (like Red Hat UBI or Ubuntu Pro) destroys this bit-for-bit guarantee due to non-deterministic base OS file timestamps.

---

## 2. Reconfigure OCI Registries

To publish base images under your own enterprise registry namespace:

1. **Update GitHub Workflow Variables**:
   - Open `.github/workflows/release.yml` and `.github/workflows/scheduled-scan.yml`.
   - Update the OCI target registry variables:
     ```yaml
     env:
       REGISTRY_BASE: ghcr.io/your-org/clearcutt
     ```
2. **Configure Authentication Secrets**:
   - Ensure the repository has a token with write access to your OCI package registry (`packages: write`).

---

## 3. Re-Key Sigstore OIDC Workflows

ClearCutt uses keyless Sigstore signatures signed via GitHub Actions OIDC tokens. Downstream teams must update their verification anchors:

1. **Verification Regex Update**:
   - Signature checks rely on validating the certificate Subject Alternative Name (SAN). The SAN pins the exact workflow file URL at the ref that signed it.
   - When forked, your OIDC verification subject will change. Update your cluster-side Kyverno admission policy and local scripts to match your forked workflow identity:
     ```bash
     # Expected identity SAN for your fork:
     https://github.com/YOUR-ORG/clearcutt/.github/workflows/release.yml@refs/heads/main
     ```
2. **Kyverno Admission Gates**:
   - Update the Kyverno ClusterPolicy definition inside `site/src/components/VerifyBlock.astro` to reflect your organization's OIDC SAN.

---

## 4. Run Self-Hosted Catalog & OpenVEX Feeds

ClearCutt includes a premium Astro-based catalog site that parses release metadata and serves as a worked-example of a live-refreshing image feed.

### Compiling & Deploying the Site
1. Install dependencies:
   ```bash
   make site-install
   ```
2. Build the site locally or in your CI/CD pipeline:
   ```bash
   make site-build
   ```
3. During static compilation, the pipeline runs the Go CLI to dynamically triage active CVE telemetry, producing OpenVEX JSON documents inside the public directory at `vex/<image-id>.json`.
4. Publish the static output (`site/dist/`) to GitHub Pages, an S3 bucket, or your enterprise developer portal.

---

## 5. Parameterized Composite Actions

Downstream applications can certify their security contracts by calling our composite certifier action. The action automatically resolves CLI binaries from your own forked release assets:

```yaml
- name: Certify App Compliance
  uses: YOUR-ORG/clearcutt/.github/actions/certify-app@v1
  with:
    image: ghcr.io/your-org/my-app:v1.0.0
    policy: .github/clearcutt-policy.yaml
    base: java25-distroless
    certificate-identity-regexp: '^https://github\.com/YOUR-ORG/.*$'
```

---

By owning the fork, your platform engineering team retains full sovereign control over base runtime configurations, cryptographic signing keys, and admission policies.
