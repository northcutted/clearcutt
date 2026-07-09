# GitHub Control Plane Bootstrap

ClearCutt bootstraps a user-owned GitHub repository that acts as the container
image platform control plane. The upstream `northcutted/clearcutt` repository
remains the CLI and reference implementation source. The generated repository
owns catalog inputs, workflow desired state, evidence publication, policies,
and operating decisions under the platform team's registry and GitHub identity.

There are two profiles:

- `catalog-only`: for teams that already have OCI images and want a generated,
  Nix-free catalog/control-plane repo around `images.yaml`.
- `fleet`: for teams that want ClearCutt to build and operate a base-image
  fleet. This profile currently delegates to the existing `platform new`
  scaffold and adds control-plane metadata.

For the extension model, see
[`docs/extending-clearcutt.md`](extending-clearcutt.md): app teams use templates
and devcontainers, fleet owners edit `clearcutt.fleet.yaml`, and Nix stays in
the backend authoring path.

## Golden Path

1. Build or install the CLI, then dry-run a catalog-only GitHub bootstrap:

   ```bash
   clearcutt platform bootstrap github \
     --profile catalog-only \
     --owner YOUR_ORG \
     --repo image-platform \
     --registry-base ghcr.io/YOUR_ORG/image-platform \
     --pages \
     --environment production \
     --dir ./image-platform \
     --dry-run \
     --force
   ```

   Dry-run mode renders the local repository and prints the GitHub plan without
   calling `gh`, initializing git, or pushing anything.
2. Review the rendered repository:

   ```text
   image-platform/
     images.yaml
     clearcutt.lock
     .clearcutt/github.yaml
     .github/workflows/catalog.yml
     .github/workflows/pr-gate.yml
   ```

   Catalog-only mode does not copy the upstream `cli/`, `core/`, or `site/`
   source tree and does not require Nix.
3. Edit `images.yaml` for OCI images your team already publishes, then generate
   and validate catalog data:

   ```bash
   clearcutt catalog generate \
     --images ./image-platform/images.yaml \
     --output ./image-platform/dist/catalog \
     --owner YOUR_ORG \
     --repo image-platform \
     --registry-base ghcr.io/YOUR_ORG/image-platform

   clearcutt --catalog ./image-platform/dist/catalog catalog validate
   clearcutt catalog site build --catalog ./image-platform/dist/catalog --output ./image-platform/dist/site --install
   ```
4. When the plan is acceptable, apply it explicitly:

   ```bash
   clearcutt platform plan github \
     --dir ./image-platform \
     --owner YOUR_ORG \
     --repo image-platform \
     --profile catalog-only \
     --pages \
     --environment production \
     --output ./image-platform/.clearcutt/clearcutt.plan.json

   clearcutt platform apply github \
     --plan ./image-platform/.clearcutt/clearcutt.plan.json \
     --confirm
   ```

   Apply uses `gh` and `git`, refuses to run without `--confirm`, configures
   non-secret repository variables, and prints any required secrets as manual
   next steps. Catalog-only requires no repository secrets by default.
5. Run the generated `catalog.yml` workflow and inspect the published Pages
   site.

## Fleet Profile

Use the fleet profile when ClearCutt should operate the base-image fleet rather
than catalog images that already exist:

   ```bash
   clearcutt platform render ./golden-images \
     --profile fleet \
     --owner YOUR_ORG \
     --repo golden-images \
     --registry-host ghcr.io \
     --image-prefix golden-images \
     --pages \
     --environment production \
     --force
   ```

   For this implementation, fleet rendering delegates to the existing
   `platform new` scaffold. When run inside the reference checkout this copies local files. When run from
   an installed CLI outside a checkout it uses the embedded ClearCutt source
   archive; `--source` can point at a custom checkout or zip archive when a fork
   wants to scaffold from its own kit. Either way it materializes the reference
   workflows, CLI source, Nix fleet core, site, schemas, docs, and examples, then
   localizes the fleet config, platform-kit doc, metadata, policies, and app
   templates. If you forked the reference repo directly, run `clearcutt platform
   init --owner YOUR_ORG --repo YOUR_REPO --force` inside that fork instead.
1. Push the scaffolded repository to GitHub under the organization that will own
   the image platform.
   The scaffolded workflows use `.github/actions/install-clearcutt` to install a
   verified ClearCutt release binary by default. Set `CLEARCUTT_CLI_VERSION` when
   pinning a newer CLI release, `CLEARCUTT_CLI_REPO` when consuming a forked CLI
   publisher, or `CLEARCUTT_CLI_MODE=local` only when intentionally dogfooding
   the checked-out CLI source. Fleet release, PR-gate, and cache-seeding
   workflows default `CLEARCUTT_BUILD_ENGINE=go`; set it to `shell` only as a
   temporary fallback while debugging parity.
   For remediation, the weekly scan plans and reports by default. Set
   `CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS=true` to let it also draft the single
   rolling remediation PR for deterministic, evidence-backed fixes; scheduled
   drafting runs with LLM escalation off and remains gated by PR review.
2. Edit `clearcutt.fleet.yaml` for enabled runtimes, service images,
   architectures, catalog scan window, admission profile, remediation limits,
   branding, templates, and optional cache settings. Use
   `clearcutt matrix explain java21` and `clearcutt service explain postgres16`
   before adding fleet lines; unsupported IDs fail at the config layer instead
   of later in the Nix backend.
3. In GitHub, enable Actions, grant workflow read/write permissions, create and
   protect the `production` environment, and configure Pages to deploy from
   GitHub Actions.
4. Run `clearcutt platform status` to verify the kit is wired together,
   including fork-local metadata and supported fleet runtime lines.
5. Run `clearcutt platform release-plan` to print the first-release operating
   plan generated from `clearcutt.fleet.yaml`. The plan lists the configured
   registry support tier, matrix size, required GitHub variables/secrets, local
   checks, release steps, verification commands, and the current boundary
   between CLI-owned orchestration, GitHub Actions/SLSA, Nix, Sigstore tooling,
   and remediation PR drafting.
6. Run `clearcutt platform doctor --github` after pushing the repo to GitHub to
   verify Actions, workflow token permissions, the `production` environment,
   Pages, default branch, registry credential readiness, local workflow
   permissions, and optional remediation/cache prerequisites before first
   release.
7. Run `clearcutt platform setup-nix --core-dir core --write-user-config` only
   on machines that will build or publish the fleet. In CI the workflows call
   the same command with `--github-env "$GITHUB_ENV"` so fork cache trust comes
   from `clearcutt.fleet.yaml`, not workflow constants.
8. Run the release workflow from `main` to publish the configured base-image
   fleet to the registry in `registry.host`. The reference trust policy is
   main-only:
   `release.workflowIdentity`, verifier examples, and admission policies pin
   `refs/heads/main`.
   The workflow is a GitHub identity runner; the reusable mechanics live behind
   `clearcutt platform setup-nix`, `clearcutt fleet certify-target`,
   `clearcutt fleet publish-target`, `clearcutt fleet assemble-target`,
   `clearcutt fleet verify-target`, `clearcutt fleet export-provenance`,
   `clearcutt fleet build-cli-assets`, and `clearcutt fleet finalize-release`.
   Runtime and service matrix output is generated by `clearcutt fleet
   workflow-matrices`; Actions consumes those outputs for fan-out instead of
   shaping JSON with inline shell/JQ.
   CLI binary assets are generated by `clearcutt fleet build-cli-assets`; Actions
   supplies Go, Cosign, and OIDC, but the binary matrix, version stamping,
   optional blob-signing loop, asset manifest, and checksum manifest are owned
   by the CLI.
   Cache-seeding analysis uses `clearcutt fleet seed-cache-plan`; Actions only
   carries the approved environment, matrix fan-out, and cache-write secrets.
9. Let the catalog workflow run `clearcutt catalog build --include-services`
   for the full release-evidence pipeline, or
   `clearcutt catalog generate --include-services` when you need portable mixed
   runtime and service catalog artifacts. Pages-specific parameter export uses
   `clearcutt catalog workflow-params`, scanning uses `clearcutt catalog build
   --core-dir core --update-db`, and site packaging uses `clearcutt catalog site
   build --generate-vex` so the workflow does not parse catalog internals or
   install scanner tooling with shell/JQ. Deploy the generated site to GitHub
   Pages or another static host.
10. Give application teams the templates under `examples/clearcutt-template-*`.
11. Gate on required signature, SBOM, provenance, and optional rebase-attestation
   evidence in CI and Kubernetes admission policy.

## Trust Story

- Release images are signed with Sigstore keyless OIDC and verified against the
  configured release workflow identity.
- OCI image source/vendor labels are stamped from `core/lib/platform-metadata.nix`
  so a fork does not publish images that claim the upstream reference repository
  as their source.
- App rebases are signed by `.github/workflows/rebase.yml`; admission policy
  should pin that rebase workflow identity separately from the app developer's
  release workflow identity.
- SBOM and test-result attestations are attached to the OCI manifest.
- SLSA Build L3 provenance is generated by the `slsa-github-generator`
  reusable workflow against the multi-architecture manifest digest.
- Each release target writes a machine-readable
  `*.release-verification.json` checklist from `clearcutt fleet verify-target`
  and uploads it with the GitHub Release assets, so verification results are
  inspectable after the workflow completes.
- The catalog displays each evidence channel independently so missing
  signatures, SBOMs, provenance, test results, or vulnerability scans remain
  visible.
- The trust walkthrough in [`trust/evidence-walkthrough.md`](trust/evidence-walkthrough.md)
  shows how to compare a registry-side verification result with the catalog
  record.
- Remediation is approved automation: the scheduled workflow creates a ranked
  scan/plan/report by default. Fork owners can opt into scheduled deterministic
  draft PRs with `CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS=true`; those scheduled
  drafts run with LLM escalation off and only attempt evidence-backed recipes.
  Direct deterministic overlay recipes and source/patch URL plus hash evidence
  are drafted by the Go CLI; recipes that still need hash iteration or build
  probing can fall back to the retained drafting backend. Manual
  `workflow_dispatch` drafting can use AI assistance when `OPENROUTER_API_KEY`
  is configured. Neither mode silently merges, deploys, or mutates production
  workloads.

## Operator Commands

```bash
# Inspect the forkable platform surface.
clearcutt platform status

# Print the first-release operating plan and trust boundaries.
clearcutt platform release-plan

# Check GitHub first-release readiness after pushing the repo.
clearcutt platform doctor --github

# Scaffold a standalone fleet repo from the reference kit.
clearcutt platform new ./golden-images --owner YOUR_ORG --repo golden-images

# Explain a runtime line from the public fleet config contract.
clearcutt matrix explain java21

# Add or remove a built-in runtime line from the fleet config.
clearcutt matrix add java25
clearcutt matrix remove python3.13

# Scaffold and validate a custom runtime line.
clearcutt runtime scaffold ruby3.4
clearcutt runtime validate ruby3.4

# Add and validate platform-owned service images.
clearcutt service scaffold postgres16 --template postgres --version 16
clearcutt service scaffold valkey8 --template valkey --version 8
clearcutt service scaffold oauth2-proxy7 --template oauth2-proxy --version 7
clearcutt service validate --all

# Emit the runtime and service matrices used by GitHub Actions.
clearcutt fleet workflow-matrices --github-output "$GITHUB_OUTPUT"

# Build, optionally sign, and checksum released CLI binaries.
clearcutt fleet build-cli-assets --version-tag v1.2.3 --build-outputs build-outputs --sign

# Configure and warm the Nix client on fleet-builder machines only.
clearcutt platform setup-nix --core-dir core --write-user-config

# Build and gate one single-architecture fleet target without publishing.
clearcutt fleet certify-target --system x86_64-linux --language java25 --tier slim

# Build and publish one single-architecture fleet target.
clearcutt fleet publish-target --system x86_64-linux --language java25 --tier slim --version-tag v1.2.3

# Build, smoke, and publish one service target.
clearcutt service build postgres16 --system x86_64-linux
clearcutt service smoke postgres16 --engine docker
clearcutt service publish postgres16 --system x86_64-linux --version-tag v1.2.3

# Assemble, sign, attest, and write the digest manifest for one multi-arch image.
clearcutt fleet assemble-target --language java25 --tier slim --version-tag v1.2.3

# Verify one released target against the fork-configured release identity.
clearcutt fleet verify-target --ref ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_PREFIX-java25:v1.2.3-slim

# Generate an app-team starter.
clearcutt app template java --output examples/my-java-service

# Build catalog data from release evidence, registry metadata, SBOMs, and scans.
clearcutt catalog build --limit 10 --scan-depth 4 --core-dir core --update-db --include-services

# Emit catalog workflow parameters for GitHub Actions.
clearcutt catalog workflow-params --github-output "$GITHUB_OUTPUT"

# Or generate portable catalog artifacts for policy, audit, and site rendering.
clearcutt catalog generate --config clearcutt.fleet.yaml --include-services --output ./dist/catalog

# Render a static evidence portal from those artifacts.
clearcutt catalog site build --catalog ./dist/catalog --output ./dist/site --install --generate-vex
```

## App-Team Flow

Application teams should build in the dev tier, run in slim or distroless, and
certify the resulting image before deployment. The generated templates include:

- a devcontainer pinned to the matching ClearCutt dev image,
- a Dockerfile using the dev tier as builder and distroless as runtime,
- a certification policy requiring signatures, SBOMs, provenance, non-root
  execution, and bounded vulnerability counts,
- a release workflow that signs, attests, and certifies the app image,
- an optional rebase workflow for moving the unchanged app layer onto a patched
  ClearCutt base.
