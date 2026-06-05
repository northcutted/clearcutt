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
   ./clearcutt platform status
   ```

7. Review `clearcutt.fleet.yaml` before the first release. At minimum, confirm:

   - `registry.owner` and `registry.repository`
   - `site.basePath`
   - `core/lib/platform-metadata.nix` source URL and vendor strings
   - `release.workflowIdentity`
   - `rebase.workflowIdentity`
   - enabled languages, tiers, and systems
   - admission and remediation policy settings

8. Dispatch `.github/workflows/release.yml` to publish the first fleet release.
9. Dispatch or wait for `.github/workflows/publish-pages.yml` to build the
   catalog and deploy the evidence portal.
10. Point app teams at the generated templates under `examples/clearcutt-template-*`.

## What You Do Not Need To Rewire

The current release workflow derives its matrix from `clearcutt.fleet.yaml` and
publishes to `ghcr.io/${{ github.repository }}/...`. A normal GitHub fork does
not need a custom registry secret for GHCR: the workflow uses `GITHUB_TOKEN`,
`github.actor`, and `packages: write`.

Do not edit a hardcoded `REGISTRY_BASE` in the release workflow. If the fork
needs a different GHCR owner/repo path, update `clearcutt.fleet.yaml` and rerun
`clearcutt platform status`.

## Trust Anchors

ClearCutt signs with GitHub Actions OIDC. Your fork must pin its own workflow
identities in CI, catalog verification, and cluster admission policy:

```text
https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main
https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/rebase.yml@refs/heads/main
```

The release workflow signs the base-image fleet and publishes SBOM/provenance
evidence. The rebase workflow performs the privileged app-update leg: it verifies
the original developer signature, preserves app layers byte-for-byte, signs the
rebased app image, and attaches the ClearCutt rebase attestation.

## Optional Secrets

Most workflows use only `GITHUB_TOKEN`.

Add `CLEARCUTT_REBASE_REGISTRY_TOKEN` only if the platform rebase workflow must
push rebased app images outside packages writable by this repository's
`GITHUB_TOKEN`. If that token should log in as a specific service account, set
the repository variable `CLEARCUTT_REBASE_REGISTRY_USER`.

Add `OPENROUTER_API_KEY` only if you intend to run
`.github/workflows/cve-patch-agent.yml` for AI-assisted remediation PR drafting.

Add `NIX_CACHE_SECRET_KEY`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and
`CLOUDFLARE_ACCOUNT_ID` only if you want the release workflow to publish signed
Nix derivations to a Cloudflare R2 binary cache. Without those secrets, releases
still build and publish images; the optional cache upload step is skipped.

## Platform Customization Points

- `clearcutt.fleet.yaml`: registry namespace, site base path, matrix, release
  identity, rebase identity, admission defaults, and remediation limits.
- `core/lib/platform-metadata.nix`: source URL, vendor, and author labels baked
  into the OCI image config by the Nix image compiler.
- `core/lib/registry.nix`: runtime slots, package closures, and tier mapping.
- `core/overlays/`: patched or organization-specific runtime inputs.
- `docs/` and `site/`: operator-facing docs and evidence portal copy.
- `examples/clearcutt-template-*`: app-team starter workflows and policies.

## Readiness Gate

Before advertising the fork as an internal image platform, this command should
pass in the fork:

```bash
./clearcutt platform status
```

Then prove one end-to-end release by verifying a published image against your
fork's OIDC identity:

```bash
./clearcutt verify release-evidence \
  --ref ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java25:distroless-vX.Y.Z \
  --repo YOUR_ORG/YOUR_REPO \
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main'
```
