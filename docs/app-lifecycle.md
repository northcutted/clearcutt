# Rebasable Application Lifecycle

This guide shows the supported end-to-end flow for application teams that want
to build once, sign the application payload, and later move that payload onto a
patched ClearCutt base without recompiling.

The important boundary is simple: `clearcutt app build` packages one prebuilt
artifact file into one OCI layer. That layer is preserved byte-for-byte during
`clearcutt app rebase`; the base layers underneath it are swapped only after the
CLI verifies runtime compatibility and the developer signature over the source
image.

If your service needs a whole publish directory, runtime package installation,
or multiple sidecar files inside the image, keep using a normal Containerfile
and run `clearcutt certify` until directory artifact support exists.

---

## The Contract

- `app build` is daemonless and registry-direct. It needs registry credentials
  but no Docker daemon and no Nix installation.
- The artifact is a single file placed at `--dest`.
- Native binaries should pass `--executable` so the file lands with mode `0755`.
- `--entrypoint` and `--cmd` use OCI JSON exec form. Do not rely on a shell in
  `distroless`.
- `--base` can be a catalog id such as `java21-distroless` or a raw registry
  reference. A catalog id resolves to a digest-pinned ClearCutt base from the
  local catalog.
- `app diff-base` checks runtime-line compatibility and, when both bases are in
  the catalog, reports the offline CVE delta.
- `app rebase` verifies the developer signature over the exact source digest,
  swaps the base, signs the rebased result with the rebase workflow identity, and
  attaches a signed rebase attestation when `--sign --attest` are set.

Supported base families:

| Stack | Base ids |
| --- | --- |
| Core/static | `coreLTS-dev`, `coreLTS-slim`, `coreLTS-distroless` |
| Java | `java21-*`, `java25-*` |
| Node.js | `node22-*`, `node24-*` |
| Python | `python3.14-*` |
| Go | `go1.25-*`, `go1.26-*` |
| .NET | `dotnet8-*`, `dotnet10-*` |
| Rust | `rust1.95-*` |
| C/C++ | `cc15-*` |

Use `dev` for toolchains, `slim` when you need a diagnostic shell, and
`distroless` for the hardened production target.

---

## Common End-to-End Flow

These variables are used by the stack-specific examples below:

```bash
export APP_IMAGE="ghcr.io/acme/payments-api:1.0.0"
export REBASED_IMAGE="ghcr.io/acme/payments-api:1.0.0-rebased"
export DEV_SIGNER="https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main"
export ENGINE_SIGNER="https://github.com/acme/platform/.github/workflows/rebase.yml@refs/heads/main"
```

Each stack section builds a source image. After that, the signed rebase loop is
the same:

```bash
# 1. The developer release workflow signs the original application image.
cosign sign --yes "$APP_IMAGE"

# 2. Compare the patched base before changing the image.
clearcutt app diff-base \
  --image "$APP_IMAGE" \
  --candidate-base "$PATCHED_BASE" \
  --candidate-base-id "$BASE_ID" \
  --fail-on-incompatible

# 3. Rebase from a dedicated CI workflow with id-token: write.
clearcutt app rebase \
  --image "$APP_IMAGE" \
  --candidate-base "$PATCHED_BASE" \
  --candidate-base-id "$BASE_ID" \
  --tag "$REBASED_IMAGE" \
  --dev-identity "$DEV_SIGNER" \
  --sign \
  --attest

# 4. Verify the rebase-engine signature and signed predicate in deployment gates.
cosign verify "$REBASED_IMAGE" \
  --certificate-identity "$ENGINE_SIGNER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation "$REBASED_IMAGE" \
  --type https://clearcutt.dev/attestations/rebase/v1 \
  --certificate-identity "$ENGINE_SIGNER" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

When `--candidate-base` is a catalog id, `--candidate-base-id` can be omitted.
When it is a raw registry reference, pass `--candidate-base-id` so the
compatibility gate can enforce the runtime family and major/minor line.

---

## Stack Examples

### Java 21 or Java 25

Use a fat JAR or another single executable JAR as the artifact.

```bash
./mvnw -DskipTests package
cp target/payments-api-*-all.jar target/app.jar

export BASE_ID="java21-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact target/app.jar \
  --dest /workspace/app.jar \
  --entrypoint '["java","-jar","/workspace/app.jar"]' \
  --image "$APP_IMAGE"
```

For Java 25, use `java25-distroless` and the matching
`clearcutt-java25:distroless-<tag>` patched base.

### Node.js 22 or Node.js 24

Bundle the service into one server file. This works best for API services that
can be bundled with esbuild, ncc, or Rollup.

```bash
npm ci
npx esbuild src/server.ts \
  --bundle \
  --platform=node \
  --target=node22 \
  --format=esm \
  --outfile=dist/server.mjs

export BASE_ID="node22-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-node22:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact dist/server.mjs \
  --dest /workspace/server.mjs \
  --entrypoint '["node","/workspace/server.mjs"]' \
  --image "$APP_IMAGE"
```

If the application depends on native addons or runtime files that cannot be
bundled into one artifact, use a Containerfile and certify the finished image.

### Python 3.14

Package the application as a zipapp, PEX, or shiv artifact.

```bash
python -m pip install --upgrade build pex
pex . \
  -m payments_api.main \
  -o dist/payments-api.pyz

export BASE_ID="python3.14-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-python3.14:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact dist/payments-api.pyz \
  --dest /workspace/payments-api.pyz \
  --entrypoint '["python","/workspace/payments-api.pyz"]' \
  --image "$APP_IMAGE"
```

### Go 1.25 or Go 1.26

Produce a Linux executable and mark it executable in the image layer.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/payments-api ./cmd/payments-api

export BASE_ID="go1.25-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-go1.25:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact dist/payments-api \
  --dest /workspace/payments-api \
  --entrypoint '["/workspace/payments-api"]' \
  --executable \
  --image "$APP_IMAGE"
```

For Go 1.26, use `go1.26-distroless` and `clearcutt-go1.26`.

### .NET 8 or .NET 10

`app build` needs one artifact file. For .NET, use a single-file publish that
does not require sidecar files.

```bash
dotnet publish src/Payments.Api/Payments.Api.csproj \
  -c Release \
  -r linux-x64 \
  --self-contained false \
  -p:PublishSingleFile=true \
  -p:PublishTrimmed=true \
  -o out

mkdir -p dist
cp out/Payments.Api dist/payments-api

export BASE_ID="dotnet8-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-dotnet8:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact dist/payments-api \
  --dest /workspace/payments-api \
  --entrypoint '["/workspace/payments-api"]' \
  --executable \
  --image "$APP_IMAGE"
```

If your framework-dependent publish output still needs `.deps.json`,
`.runtimeconfig.json`, or other sidecar files, use a Containerfile and certify
that image instead. For .NET 10, use `dotnet10-distroless` and
`clearcutt-dotnet10`.

### Rust 1.95

Build a Linux binary. A musl target is the most portable option.

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
mkdir -p dist
cp target/x86_64-unknown-linux-musl/release/payments-api dist/payments-api

export BASE_ID="rust1.95-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-rust1.95:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact dist/payments-api \
  --dest /workspace/payments-api \
  --entrypoint '["/workspace/payments-api"]' \
  --executable \
  --image "$APP_IMAGE"
```

### C/C++ 15

Build a Linux executable. Prefer a static or fully self-contained binary when
targeting `distroless`.

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS="-static"
cmake --build build --target payments-api

export BASE_ID="cc15-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-cc15:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact build/payments-api \
  --dest /workspace/payments-api \
  --entrypoint '["/workspace/payments-api"]' \
  --executable \
  --image "$APP_IMAGE"
```

Use `cc15-dev` as the builder image when you want the GCC/CMake/Ninja toolchain
inside a containerized build stage.

### Core LTS Static Utility

Use the Core line when the application artifact is already a static Linux binary
or tiny utility and only needs CA certificates in the runtime image.

```bash
zig cc -target x86_64-linux-musl -O2 -static \
  -o dist/worker src/worker.c

export BASE_ID="coreLTS-distroless"
export PATCHED_BASE="ghcr.io/northcutted/clearcutt/clearcutt-corelts:distroless-v0.2.2"

clearcutt app build \
  --base "$BASE_ID" \
  --artifact dist/worker \
  --dest /workspace/worker \
  --entrypoint '["/workspace/worker"]' \
  --executable \
  --image "$APP_IMAGE"
```

---

## CI Rebase Workflow

Run rebases from a dedicated workflow identity. The developer workflow signs the
source image; the platform workflow verifies that signature, performs the base
swap, signs the result, and attaches the rebase predicate.

```yaml
name: Rebase application image

on:
  workflow_dispatch:
    inputs:
      image:
        required: true
        type: string
      tag:
        required: true
        type: string
      base_id:
        required: true
        type: string
      patched_base:
        required: true
        type: string

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  rebase:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v4
      - name: Build clearcutt
        run: make cli-build
      - name: Check candidate base
        run: |
          ./clearcutt app diff-base \
            --image "${{ inputs.image }}" \
            --candidate-base "${{ inputs.patched_base }}" \
            --candidate-base-id "${{ inputs.base_id }}" \
            --fail-on-incompatible
      - name: Rebase, sign, and attest
        run: |
          ./clearcutt app rebase \
            --image "${{ inputs.image }}" \
            --candidate-base "${{ inputs.patched_base }}" \
            --candidate-base-id "${{ inputs.base_id }}" \
            --tag "${{ inputs.tag }}" \
            --dev-identity "$DEV_SIGNER" \
            --sign \
            --attest
        env:
          DEV_SIGNER: https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main
```

Admission policy should pin the rebase workflow identity and require the signed
predicate to carry `rebaseDecision: allowed`, `developerSignatureVerified: true`,
and the expected developer signer. See
[`examples/k8s-deployment/`](../examples/k8s-deployment/) for the Kyverno policy
shape.

---

## Multi-Architecture Notes

The examples above produce one Linux application image for the artifact you pass
to `app build`. For multi-architecture applications, build one artifact per
platform and publish an index using your release tooling. `app rebase` can rebase
multi-arch indexes when each child image carries the ClearCutt rebase labels and
uses a compatible platform-specific base.
