# ClearCutt CLI Reference

This page is a compact map of the current CLI surface. It is not a replacement
for `clearcutt --help`; use help output for the final flag contract.

## Exit Codes

The CLI distinguishes "the gate said no" from "the gate could not run":

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; all requested checks passed. |
| `1` | Operational error: bad flags or arguments, IO failure, missing catalog data, or required tooling not available. |
| `2` | Policy gate failed: a verification, conformance, certification, exception, or threshold check evaluated and rejected the input. |

Exit code 2 applies to the gating commands — `verify image`, `verify catalog`,
`verify rebuild`, `verify release-evidence`, `conformance run`, `certify`, and
`exceptions validate` — plus the other check-list gates (`catalog validate`,
`overlay verify`, `platform status`, `runtime validate`, `service validate`,
`app diff-base`, `app rebase`). CI `run:` steps fail on any non-zero code, so
existing workflow gates keep working; scripts that need to branch on "policy
failure vs broken pipeline" can now test the code directly:

```text
clearcutt verify image <id> ...; case $? in
  0) deploy ;;
  2) block release: policy gate rejected the image ;;
  *) investigate: verification could not run ;;
esac
```

## Output Formats

The global `--format` flag accepts `table` (default), `json`, or `yaml`.
Unknown values are rejected before the command runs. The gating commands above
emit a common machine-readable shape for `--format json|yaml`: an overall
`status` (`pass` or `fail`) plus a `checks` array of
`{id, status, message}` objects, with data on stdout and human commentary on
stderr.

## Install

Releases ship cross-compiled binaries (`clearcutt-<os>-<arch>` for
`darwin`/`linux`/`windows` on `amd64`/`arm64`), a keyless Sigstore signature
bundle per binary (`<binary>.sig`, produced by `cosign sign-blob --bundle` in
the release workflow), and a `SHA256SUMS.txt` manifest. Download a binary and
its `.sig` bundle from the
[latest release](https://github.com/northcutted/clearcutt/releases/latest)
and verify before use:

```bash
cosign verify-blob \
  --bundle clearcutt-linux-amd64.sig \
  --certificate-identity 'https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  clearcutt-linux-amd64

chmod +x clearcutt-linux-amd64
./clearcutt-linux-amd64 --catalog cli/internal/testdata/catalog list
```

The identity is exact, not a pattern: releases run only from
`refs/heads/main`, and the same string is pinned as
`release.workflowIdentity` in `clearcutt.fleet.yaml` and passed to
`clearcutt verify release-evidence --workflow-identity`. Build from source
(below) when contributing.

## Build

```bash
go -C cli build -o ../clearcutt ./cmd/clearcutt
./clearcutt --help
```

Catalog-backed discovery commands need generated catalog data or a fixture:

```bash
./clearcutt --catalog cli/internal/testdata/catalog list
./clearcutt --catalog cli/internal/testdata/catalog inspect java21-distroless
```

## App-Team Commands

```bash
./clearcutt --catalog cli/internal/testdata/catalog list
./clearcutt --catalog cli/internal/testdata/catalog inspect java21-distroless
./clearcutt app template java --output examples/my-java-service --name my-java-service
./clearcutt --catalog cli/internal/testdata/dev-catalog dev java21-distroless --devcontainer --print
APP_IMAGE=ghcr.io/acme/my-app:1.0.0
APP_DIGEST=$(docker buildx imagetools inspect "$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"')
docker save "$APP_IMAGE" -o my-app.tar
./clearcutt certify my-app.tar --base java21-distroless --policy certification-policy.yaml --image-ref "${APP_IMAGE%:*}@${APP_DIGEST}"
./clearcutt app build --base java21-distroless --artifact target/app.jar --dest /workspace/app.jar --entrypoint '["java","-jar","/workspace/app.jar"]' --image ghcr.io/acme/payments-api:1.0.0
```

## Catalog And Trust Commands

```bash
./clearcutt catalog generate --config clearcutt.fleet.yaml --include-services --output dist/catalog
./clearcutt --catalog dist/catalog catalog validate
./clearcutt --catalog dist/catalog catalog summarize
./clearcutt --catalog dist/catalog catalog inspect java21-distroless
./clearcutt catalog diff --old previous/catalog --new dist/catalog
./clearcutt catalog site build --catalog dist/catalog --output dist/site --install

./clearcutt --catalog cli/internal/testdata/catalog verify image java21-distroless \
  --require-signature \
  --require-sbom \
  --require-provenance \
  --allow-preview

./clearcutt verify release-evidence \
  --ref ghcr.io/YOUR_ORG/YOUR_REPO/YOUR_IMAGE:TAG \
  --repo YOUR_ORG/YOUR_REPO \
  --workflow-identity 'https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/release.yml@refs/heads/main'

./clearcutt verify rebuild ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-distroless \
  --target java21-distroless \
  --rebuild \
  --pull-registry-archive \
  --require-digest-match \
  --require-layer-match \
  --diffoscope-out rebuild.diff.txt \
  --output-predicate
```

## Platform Owner Commands

```bash
./clearcutt platform init --owner YOUR_ORG --repo YOUR_REPO --force
./clearcutt platform status
./clearcutt platform setup-nix --core-dir core --write-user-config

./clearcutt matrix explain java21
./clearcutt matrix add java25
./clearcutt runtime scaffold ruby3.4
./clearcutt runtime validate ruby3.4

./clearcutt service scaffold postgres16 --template postgres --version 16
./clearcutt service validate --all
./clearcutt service build postgres16 --system x86_64-linux
./clearcutt service smoke postgres16 --engine docker

./clearcutt overlay generate \
  --runtime java21 \
  --tier slim \
  --base registry.access.redhat.com/ubi9/ubi-minimal@sha256:... \
  --runtime-ref ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-slim@sha256:... \
  --image ghcr.io/YOUR_ORG/java21-ubi:TAG \
  --output overlays/java21-ubi

./clearcutt overlay verify \
  --runtime-archive clearcutt-java21.tar \
  --grafted-archive overlays/java21-ubi/result \
  --runtime-ref ghcr.io/YOUR_ORG/YOUR_REPO/clearcutt-java21:TAG-slim@sha256:... \
  --grafted-ref ghcr.io/YOUR_ORG/java21-ubi:TAG@sha256:... \
  --target java21-slim \
  --output-predicate
```

## Policy And Remediation Commands

```bash
./clearcutt --catalog cli/internal/testdata/catalog policy java21-distroless --engine kyverno --environment production --namespace apps
./clearcutt exceptions validate exceptions.yaml --fail-on-expired-exceptions
./clearcutt vex --help
./clearcutt remediation plan --help
./clearcutt remediation report --help
```

## Drift Check Scope

The PR gate validates high-traffic command snippets that are expected to be
executable from this checkout. Commands that require registry credentials,
cluster access, or fork-specific values must be marked as examples and should
use placeholders such as `YOUR_ORG`.
