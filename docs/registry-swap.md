# Swapping the Container Registry

ClearCutt defaults to **GHCR** (`ghcr.io`) authenticated with the workflow's
built-in `GITHUB_TOKEN`. The release, pages, and rebase pipelines no longer
hardcode the registry host or credentials — they read three repository settings,
so a fork can point the whole supply chain at another registry **without editing
any workflow YAML**.

## The three knobs

Set these as GitHub Actions **repository (or organization) variables/secrets**
(`Settings → Secrets and variables → Actions`):

| Setting | Kind | Default when unset | Purpose |
| --- | --- | --- | --- |
| `CLEARCUTT_REGISTRY_HOST` | Variable | `ghcr.io` | Registry hostname used by every `docker login` and the SLSA provenance push. |
| `CLEARCUTT_REGISTRY_USER` | Variable | `github.actor` | Login username / robot account. |
| `CLEARCUTT_REGISTRY_TOKEN` | Secret | `GITHUB_TOKEN` | Login password / token. |

The rebase pipeline additionally honors `CLEARCUTT_REBASE_REGISTRY_USER` /
`CLEARCUTT_REBASE_REGISTRY_TOKEN` when app images live in a different registry
than the platform fleet; it falls back to the three knobs above, then to the
GitHub defaults.

Because these default to the GitHub built-ins, **the canonical GHCR setup keeps
working with nothing set.**

## Also update the fleet config

The knobs above control *authentication* in CI. Image **naming and push paths**
are controlled by the CLI from `clearcutt.fleet.yaml`:

```yaml
registry:
  host: ghcr.io          # <-- set to the same value as CLEARCUTT_REGISTRY_HOST
  owner: your-org
  repository: your-fleet
  imagePrefix: yourbrand
```

Run `clearcutt platform init --owner your-org --repo your-fleet` to localize the
config, docs, admission policy, and app templates to the new identity. Keep
`registry.host` and `CLEARCUTT_REGISTRY_HOST` in sync (a planned refinement will
have the CLI emit the host as a workflow job output so there is a single source —
see [analysis/cli-pivot-plan.md](analysis/cli-pivot-plan.md)).

## Per-backend notes

- **GHCR (default):** nothing to do.
- **Generic token registries** (Harbor, Artifactory, Quay, Nexus, GitLab
  Container Registry, Docker Hub): create a robot/service account, set
  `CLEARCUTT_REGISTRY_HOST`, `CLEARCUTT_REGISTRY_USER`, and the
  `CLEARCUTT_REGISTRY_TOKEN` secret. No workflow edits required.
- **AWS ECR:** ECR issues short-lived tokens rather than a static password, so
  the static-secret model does not fit directly. Until an `authMode` knob exists
  (tracked in the pivot plan), add an `aws-actions/amazon-ecr-login` step (or set
  `CLEARCUTT_REGISTRY_TOKEN` from `aws ecr get-login-password` in a preceding
  step) ahead of the fleet jobs.
- **Google Artifact Registry (GAR):** authenticate with
  `google-github-actions/auth` (Workload Identity Federation recommended) and use
  `oauth2accesstoken` as `CLEARCUTT_REGISTRY_USER` with the access token as the
  token secret.

## Known limitations

- **SLSA provenance generator.** The release workflow's provenance job uses
  `slsa-framework/slsa-github-generator` with `private-repository: true`; its
  registry credentials are parameterized from the same knobs, but confirm the
  reusable workflow supports your target registry before relying on it.
- **Host double-source.** `CLEARCUTT_REGISTRY_HOST` (a CI variable) and
  `registry.host` (in `clearcutt.fleet.yaml`) must currently be set
  consistently. The pivot plan replaces this with a CLI-emitted job output.
- **ECR/GAR short-lived auth** needs an extra auth step today (no `authMode`
  selector yet).

## Verify the swap

After configuring the knobs, run a release and confirm evidence resolves against
the new host:

```bash
clearcutt fleet verify-target --system x86_64-linux --language java21 --tier distroless
# or, for a consumer of a published image:
clearcutt certify <your-host>/<org>/<repo>/<image>:<tag> --require-signature --require-provenance
```
