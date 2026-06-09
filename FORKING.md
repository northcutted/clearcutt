# Forking ClearCutt

ClearCutt is meant to be forked by a platform team that wants to own its base
image feed, registry namespace, GitHub Actions OIDC identities, catalog site,
and admission policy. The reference repository is a working blueprint, not a
hosted control plane.

This is not a 15-minute app-template setup. The owner team needs enough Nix and
GitHub Actions fluency to maintain the runtime matrix, review releases, and
operate the trust chain. Application teams consuming the published images do not
need Nix.

## First-Run Checklist

1. Fork this repository into the organization that will own the image platform.
2. Enable GitHub Actions for the fork.
3. In **Settings -> Actions -> General**, set workflow permissions to **Read and
   write permissions**. Enable pull-request creation if you plan to use the
   remediation agent.
4. Create a GitHub Environment named `production`. Add required reviewers if
   releases and app rebases should be manually approved.
5. In **Settings -> Pages**, select **GitHub Actions** as the Pages source.
6. Build the CLI and rewrite the platform defaults for your fork:

   ```bash
   make cli-build
   ./clearcutt platform init --owner YOUR_ORG --repo YOUR_REPO --force
   ./clearcutt platform setup-nix --core-dir core --write-user-config
   ./clearcutt platform status
   ```

   `platform init` rewrites the fleet config, Nix image metadata, app-team
   templates, and the consumer example manifests (Kubernetes, OpenShift,
   Compose, and the base-image overlay) so they pull your registry and pin your
   signing identity. App-team placeholder identities (`ghcr.io/acme/*`) are left
   for you to fill in.

7. Review `clearcutt.fleet.yaml` before the first release. At minimum, confirm:

   - `registry.owner` and `registry.repository`
   - `site.basePath`
   - `core/lib/platform-metadata.nix` source URL and vendor strings
   - `release.workflowIdentity`
   - `rebase.workflowIdentity`
   - optional `release.nixCache.publicKey` if you publish a fork cache
   - enabled languages, tiers, and systems
   - admission and remediation policy settings

8. Dispatch `.github/workflows/release.yml` from `main` to publish the first
   fleet release. The reference policy is main-only: `release.workflowIdentity`,
   admission policy examples, and verifier commands all pin `refs/heads/main`.
   If your fork intentionally releases from another ref, update those trust
   anchors together before dispatching.
   The workflow is intentionally thin: it builds the CLI, asks
   `clearcutt platform setup-nix` to apply the fork-specific Nix client config,
   asks `clearcutt fleet publish-target` to build and push each single-arch target,
   asks `clearcutt fleet assemble-target` to assemble/sign/attest each
   multi-arch image, keeps GitHub-native provenance actions for OIDC-backed
   identity, then runs `clearcutt fleet finalize-release` for assets and notes.
9. Dispatch or wait for `.github/workflows/publish-pages.yml` to build the
   catalog and deploy the evidence portal.
10. Point app teams at the generated templates under `examples/clearcutt-template-*`.

## What You Do Not Need To Rewire

The current release workflow derives its matrix from `clearcutt.fleet.yaml` and
delegates release mechanics to `clearcutt fleet ...` commands. A normal GitHub
fork does not need a custom registry secret for GHCR: the workflow uses
`GITHUB_TOKEN`, `github.actor`, and `packages: write`.

Do not edit a hardcoded `REGISTRY_BASE` in the release workflow. If the fork
needs a different GHCR owner/repo path, update `clearcutt.fleet.yaml` and rerun
`clearcutt platform status`.

The optional Nix binary cache is also config-driven. If you want cache
publication, set `release.nixCache.bucket`, `release.nixCache.publicBaseUrl`,
`release.nixCache.signingKeyName`, `release.nixCache.publicKey`, and optionally
`release.nixCache.cloudflareZoneName`; otherwise the CLI skips the cache step
and uses the public NixOS cache for client setup.

## Trust Anchors

ClearCutt signs with GitHub Actions OIDC. Your fork must pin its own workflow
identities in CI, catalog verification, and cluster admission policy:

```text
https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main
https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/rebase.yml@refs/heads/main
```

`clearcutt platform init` rewrites these identities into the shipped Kyverno
admission policy (`examples/k8s-deployment/kyverno-policy.yaml`) and the
deployment examples, and `clearcutt platform status` fails if the admission
policy no longer pins your fork's image namespace. Still review the policy
before enforcing it in a cluster.

The release workflow signs the base-image fleet and publishes SBOM/provenance
evidence. The rebase workflow performs the privileged app-update leg: it verifies
the original developer signature, preserves app layers byte-for-byte, signs the
rebased app image, and attaches the ClearCutt rebase attestation.

Use [`docs/trust/evidence-walkthrough.md`](docs/trust/evidence-walkthrough.md)
to trace one published digest from registry evidence back to the pinned workflow
identity and catalog record.

## Optional Secrets

Most workflows use only `GITHUB_TOKEN`.

Add `CLEARCUTT_REBASE_REGISTRY_TOKEN` only if the platform rebase workflow must
push rebased app images outside packages writable by this repository's
`GITHUB_TOKEN`. If that token should log in as a specific service account, set
the repository variable `CLEARCUTT_REBASE_REGISTRY_USER`.

Add `OPENROUTER_API_KEY` only if you intend to run
`.github/workflows/cve-patch-agent.yml` or opt in to patch drafting in
`.github/workflows/scheduled-scan.yml` for AI-assisted remediation PR drafting.

Add `NIX_CACHE_SECRET_KEY`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and
`CLOUDFLARE_ACCOUNT_ID` only if you want the release workflow to publish signed
Nix derivations to a Cloudflare R2 binary cache. Without those secrets, releases
still build and publish images; `clearcutt fleet publish-cache` skips the
optional cache upload step. The cache bucket, public URL, signing key name, and
public trusted key come from `release.nixCache` in `clearcutt.fleet.yaml`.

## Platform Customization Points

- `clearcutt.fleet.yaml`: registry namespace, site base path, matrix, release
  identity, rebase identity, admission defaults, and remediation limits.
- `core/lib/platform-metadata.nix`: source URL, vendor, and author labels baked
  into the OCI image config by the Nix image compiler.
- `core/lib/registry.nix`: runtime slots, package closures, and tier mapping.
- `core/overlays/`: patched or organization-specific runtime inputs.
- `docs/` and `site/`: operator-facing docs and evidence portal copy.
- `examples/clearcutt-template-*`: app-team starter workflows and policies.
- `examples/k8s-deployment/`, `examples/openshift-deployment/`,
  `examples/oci-deployment/`, `examples/base-image-overlay/`: consumer
  deployment manifests and the Kyverno admission policy. `clearcutt platform
  init` localizes the image namespace and signing identity in these; edit them
  further for cluster-specific settings.

## Readiness Gate

Before advertising the fork as an internal image platform, this command should
pass in the fork:

Use [`docs/fork-validation.md`](docs/fork-validation.md) as the full checklist
for workflow identities, registry permissions, GitHub environments, Pages,
optional secrets, and first-release evidence.

```bash
./clearcutt platform status
```

Then prove one end-to-end release by verifying a published image against your
fork's OIDC identity:

```bash
./clearcutt fleet verify-target \
  --ref ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_IMAGE_PREFIX-java25:vX.Y.Z-distroless \
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main'
```

`YOUR_IMAGE_PREFIX` defaults to the lowercased repository name generated by
`clearcutt platform init`; override it with `registry.imagePrefix` in
`clearcutt.fleet.yaml` if your published image names need a different prefix.
