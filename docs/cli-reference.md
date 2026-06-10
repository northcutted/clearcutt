# ClearCutt CLI Reference

This page is a compact map of the current CLI surface. It is not a replacement
for `clearcutt --help`; use help output for the final flag contract.

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
