# Fork Setup Validation

Run this before the first release from a fork. The goal is to prove the fork is
wired for its own registry, workflow identities, catalog, and policies before it
publishes images.

## 1. Local Platform Status

```bash
go -C cli build -o ../clearcutt ./cmd/clearcutt
./clearcutt platform status
```

Or run the command without writing a binary:

```bash
go -C cli run ./cmd/clearcutt platform status --output "$PWD" --fleet-config clearcutt.fleet.yaml
```

Review any failed checks before release. The command should identify missing
workflow files, stale example namespaces, unsupported runtime lines, and
fork-local metadata mismatches.

## 2. Fleet Config

Confirm:

- `registry.owner`
- `registry.repository`
- `registry.imagePrefix`
- `site.basePath`
- `release.sourceBranch`
- `release.workflowIdentity`
- `rebase.workflowIdentity`
- enabled runtime and service lanes
- admission policy defaults
- remediation defaults
- optional Nix cache settings

The reference policy is main-only. If you intentionally release from another
branch, update workflow identities, admission policies, and verification
commands together.

## 3. GitHub Repository Settings

- Actions enabled.
- Workflow permissions set to read/write for release workflows.
- Pull-request creation enabled only if remediation PR drafting is enabled.
- `production` environment exists and has required reviewers if releases need
  approval.
- Pages source set to GitHub Actions.
- Packages enabled for GHCR publication.

## 4. Secrets And Variables

Most workflows use `GITHUB_TOKEN`. Add optional secrets only when the matching
feature is enabled:

- `OPENROUTER_API_KEY`: only for AI-assisted remediation PR drafting.
- `CLEARCUTT_REBASE_REGISTRY_TOKEN`: only when rebase pushes outside
  `GITHUB_TOKEN` package scope.
- Nix cache/R2/Cloudflare secrets: only when publishing a fork-owned binary
  cache.

## 5. Release Identity

Use exact workflow identities:

```text
https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main
https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/rebase.yml@refs/heads/main
```

These must agree across:

- `clearcutt.fleet.yaml`,
- `.github/workflows/release.yml`,
- `.github/workflows/rebase.yml`,
- generated Kyverno/Gatekeeper policy,
- `verify release-evidence` commands,
- app rebase commands.

## 6. First Release Proof

After publishing one release:

```bash
./clearcutt verify release-evidence \
  --ref ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_IMAGE:TAG \
  --repo YOUR_ORG/YOUR_REPO \
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main'

./clearcutt catalog generate --config clearcutt.fleet.yaml --include-services --output dist/catalog
./clearcutt --catalog dist/catalog catalog validate
./clearcutt catalog site build --catalog dist/catalog --output dist/site --install
```

If any evidence channel is missing, keep it visible in the catalog and document
whether it is expected, a setup gap, or a release failure.
