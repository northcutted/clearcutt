# ClearCutt Getting Started Guide

This guide gets you up and running with ClearCutt secure container base images in under 5 minutes. You will learn how to consume our hardened runtimes inside your application OCI configurations, run a multi-stage build, and set up the local governance CLI.

---

## ⚡ Do I Need Nix to Use ClearCutt?

> [!IMPORTANT]
> **No, application developers do NOT need Nix installed to use ClearCutt base images.**
>
> * **OCI / Container Consumption (Standard Developers):** You pull, run, and verify our pre-built base images using standard, everyday container tools (such as `docker`, `podman`, `skopeo`, `cosign`, or Kubernetes manifests). Nix is entirely optional.
> * **Nix Package Manager (Platform Engineers):** Nix is only used if you want to fork this blueprint repository, customize the underlying libraries, or compile your own secure enterprise base image OCI matrix layers from scratch.

---

## 🚀 Step 1: Write a Hardened Multi-Stage Dockerfile

To satisfy both developer debugging speed and production security minimality, ClearCutt publishes three distinct matrix tiers:
*   **`dev`**: Toolchains, compilers, interactive shells (`bash`), standard utilities, and a transient credential broker.
*   **`slim`**: Lean execution layer retaining `bash`, `/bin/sh`, dynamic runtime interpreters, and CA certificates.
*   **`distroless`**: Hardened production target with **exactly zero shells or package managers** (No `/bin/sh`, `apk`, `apt`, `ls`, or `cat`).

The recommended approach is to use the `dev` tier as a compiler stage, then copy the compiled outputs into `distroless` for execution.

### Example A: Java 25 (Fat JAR) Multi-Stage Build
```dockerfile
# 1. Compiler Stage (using the ClearCutt dev tier)
FROM ghcr.io/northcutted/clearcutt/clearcutt-java25:dev-latest AS builder
WORKDIR /app
COPY . .
# Run gradle/maven build natively using the secure, gated dev toolchain
RUN ./gradlew bootJar --no-daemon

# 2. Execution Stage (using the hardened distroless tier)
FROM ghcr.io/northcutted/clearcutt/clearcutt-java25:distroless-latest
WORKDIR /app
# Copy only the compiled JAR from the builder stage
COPY --from=builder /app/build/libs/app.jar app.jar
# The image enforces unprivileged user 10001:10001 natively.
# Execute JRE directly (no shell invocation)
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### Example B: Python 3.14 (Virtual Environment) Multi-Stage Build
```dockerfile
# 1. Builder Stage (using the dev tier to build wheels)
FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.14:dev-latest AS builder
WORKDIR /app
COPY requirements.txt .
# Compile dependencies into a clean, isolated virtualenv
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# 2. Runtime Stage (using the slim tier to run python)
FROM ghcr.io/northcutted/clearcutt/clearcutt-python3.14:slim-latest
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY . .
ENV PATH="/opt/venv/bin:$PATH"
# Run FastAPI, Flask, or standard python applications
ENTRYPOINT ["python", "main.py"]
```

---

## 🛠️ Step 2: Set Up the Governance CLI (`clearcutt`)

The `clearcutt` CLI is a single, zero-daemon Go governance engine designed to enforce supply chain policies and audit application artifacts locally.

### 1. Build or Download the CLI

* **Build from Source (Requires Go 1.26+):**
  ```bash
  git clone https://github.com/northcutted/clearcutt.git
  cd clearcutt
  make cli-build
  ```
* **Install to PATH:**
  ```bash
  chmod +x clearcutt
  sudo mv clearcutt /usr/local/bin/
  ```

> [!IMPORTANT]
> **Catalog data is required (and not committed).** `verify`, `inspect`, `list`, and the other discovery commands read a generated catalog of image records. Generate it from a clone with `node core/scripts/gather-catalog.mjs` (writes to `site/src/data/catalog`, the default `--catalog` path), or pass `--catalog cli/internal/testdata/catalog` to try the commands against the bundled fixture image.

### 2. Verify Your Security Gates

Run policy checks on target base images before integrating them in your builds:
```bash
# Check that an image satisfies strict production gates
clearcutt verify java25-distroless \
  --require-signature \
  --require-sbom \
  --max-critical 0 \
  --max-high 3
```

### 3. Declarative Compliance Audit (Local/CI)

Before deploying downstream container images, audit them completely offline to
verify the absence of shells, dynamic package managers, and root access:
```bash
# Save your application OCI image as an offline tarball
docker save my-app:latest -o my-app.tar

# Certify the application against a custom security contract
clearcutt certify my-app.tar \
  --base java25-distroless \
  --policy certification-policy.yaml
```

### 4. Build a Rebasable App Image

For downstream services that publish a single prebuilt artifact, `clearcutt app
build` can assemble the application layer directly on top of a ClearCutt base:
```bash
clearcutt app build \
  --base java21-distroless \
  --artifact target/app.jar \
  --dest /workspace/app.jar \
  --entrypoint '["java","-jar","/workspace/app.jar"]' \
  --image ghcr.io/acme/payments-api:1.0.0
```

When the base is patched later, use `clearcutt app diff-base` to check runtime
compatibility and `clearcutt app rebase --sign --attest` from a CI workflow with
OIDC enabled.

The full stack guide has end-to-end examples for Core/static, Java, Node.js,
Python, Go, .NET, Rust, and C/C++:
[`docs/app-lifecycle.md`](app-lifecycle.md).

---

## 💡 Top 3 Tips for a Smooth Onboarding

1.  **Direct Execution only:** The `distroless` tier has no shell, meaning Docker/OCI entries like `CMD "java -jar app.jar"` will fail because they attempt to evaluate via shell execution. **Always use JSON syntax** `ENTRYPOINT ["java", "-jar", "app.jar"]`.
2.  **No Package Managers:** If you need an extra system library (like `ffmpeg` or `imagemagick`), you cannot run `apk add` or `apt-get install` inside a ClearCutt container. Instead, declare it inside your customized `flake.nix` package list or build it in the `dev` stage.
3.  **Local Conformance Auditing:** Run `clearcutt conformance run` *inside* a container (e.g. as its ENTRYPOINT, or `docker run --entrypoint clearcutt <image> conformance run`) to prove CA trust, zoneinfo, unprivileged execution, and `/tmp` writability offline. It audits the current environment, not a remote image; add `--expect-runtime java` (or `python`, `node`, …) to also assert the language interpreter is present.
