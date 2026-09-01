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
go -C cli run ./cmd/clearcutt platform status --output "$PWD" --config clearcutt.yaml
```

Review any failed checks before release. The command should identify missing
workflow files, stale example namespaces, unsupported runtime lines, and
fork-local metadata mismatches.

Before configuring GitHub settings, generate the first-release operating plan:

```bash
./clearcutt platform release-plan
```

This is a side-effect-free runbook generated from `clearcutt.yaml` and
local workflow wiring. It lists the registry support tier, required GitHub
variables/secrets, local checks, release steps, verification commands, and which
parts are owned by the ClearCutt CLI versus GitHub Actions/SLSA, Nix, Sigstore
tooling, and remediation PR drafting.

After pushing the scaffolded or forked repository to GitHub, run:

```bash
./clearcutt platform doctor --github
```

This includes the local `platform status` checks, then uses the `gh` CLI to
verify that the repository is reachable, the default branch matches
`release.sourceBranch`, Actions are enabled, workflow token permissions allow
read/write, the `production` environment exists, Pages is configured for
Actions, and non-GHCR registry credentials are present when needed. It also
checks local workflow permission contracts for release, catalog Pages, app
rebase, and remediation PR drafting. Optional readiness gaps, such as missing
production protection rules, selected third-party action policy, missing
`OPENROUTER_API_KEY`, or missing configured Nix cache secrets, are reported as
warnings so platform owners can decide whether those features are in scope for
the first release.

For non-GHCR registries, `platform status` reports a warning rather than a pass:
the workflows resolve the login host from `registry.host`, but the fork still
needs `CLEARCUTT_REGISTRY_USER` and `CLEARCUTT_REGISTRY_TOKEN` plus a
registry-specific proof that Cosign referrers, SBOM attestations, SLSA
verification, and catalog enrichment work.

`platform status` also checks that release, PR-gate, rebase, and catalog
workflows use `.github/actions/install-clearcutt`. The default mode installs a
verified ClearCutt release binary; use repository variables
`CLEARCUTT_CLI_VERSION` and `CLEARCUTT_CLI_REPO` to pin a release or CLI fork.
Set `CLEARCUTT_CLI_MODE=local` only for source dogfooding, not as the normal
operator path for a scaffolded fleet repo. Build and publish workflows run
through the Go-owned build engine; there is no shell fallback. Cache-seed analysis
uses `clearcutt fleet seed-cache-plan` so matrix export, Nix dry-run parsing,
and GitHub output shaping stay in the released CLI. Release and PR-gate matrix
fan-out uses `clearcutt fleet workflow-matrices` so runtime/service matrix
aggregation and GitHub output shaping also stay in the released CLI. Catalog
Pages uses `clearcutt catalog workflow-params` and `clearcutt catalog site build
--generate-vex` so catalog parameter extraction, site packaging, and OpenVEX
publication stay in the released CLI. The catalog build step uses
`clearcutt catalog build --core-dir core --update-db`, so Grype resolution and
DB refresh run through the CLI and scaffolded Nix backend rather than workflow
tarball install shell.

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

- Actions enabled (`platform doctor --github` checks this).
- Workflow permissions set to read/write for release workflows (`platform
  doctor --github` checks this).
- Pull-request creation/approval enabled only if remediation PR drafting is
  enabled (`platform doctor --github` warns when this is not proven).
- `production` environment exists and has required reviewers if releases need
  approval (`platform doctor --github` checks existence and warns when no
  protection rules are configured).
- Pages source set to GitHub Actions (`platform doctor --github` checks this).
- Packages enabled for GHCR publication.

## 4. Secrets And Variables

Most workflows use `GITHUB_TOKEN`. Add optional secrets only when the matching
feature is enabled:

- `OPENROUTER_API_KEY`: only for optional LLM fallback remediation drafting.
- `CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS`: set to `true` only when the weekly
  remediation workflow should attempt deterministic, evidence-backed draft PRs
  without human dispatch.
- `CLEARCUTT_SCHEDULED_REMEDIATION_LIMIT`: optional cap for scheduled
  deterministic draft campaigns; defaults to `1`.
- `CLEARCUTT_REMEDIATION_LLM`: optional manual-dispatch setting. Scheduled
  drafting runs with LLM escalation off; manual `draft_patches=true` can use
  `auto` when `OPENROUTER_API_KEY` is configured.
- `CLEARCUTT_REGISTRY_USER` / `CLEARCUTT_REGISTRY_TOKEN`: only when the target
  registry cannot use `GITHUB_TOKEN`.
- `CLEARCUTT_REBASE_REGISTRY_HOST`: only when app rebase operations need to log
  in to a different app registry than `registry.host`.
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

- `clearcutt.yaml`,
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
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main' \
  --core-dir core

./clearcutt catalog generate --config clearcutt.yaml --include-services --output dist/catalog
./clearcutt --catalog dist/catalog catalog validate
./clearcutt catalog site build --catalog dist/catalog --output dist/site --install
```

If any evidence channel is missing, keep it visible in the catalog and document
whether it is expected, a setup gap, or a release failure.
