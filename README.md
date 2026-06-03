# ClearCutt

**The forkable platform kit for hardened base images — every image signed, attested, and yours to own.**

[![Live Catalog Site](https://img.shields.io/badge/Live%20Catalog-Site-blueviolet.svg?logo=astro&logoColor=white)](https://northcutted.github.io/clearcutt)
[![ClearCutt PR Gating](https://github.com/northcutted/clearcutt/actions/workflows/pr-gate.yml/badge.svg)](https://github.com/northcutted/clearcutt/actions/workflows/pr-gate.yml)
[![Nix Flake](https://img.shields.io/badge/Nix-Flake-blue.svg?logo=nixos&logoColor=white)](https://nixos.org)
[![SLSA Build L3](https://img.shields.io/badge/SLSA-Build%20L3-green.svg)](https://slsa.dev)
[![Cosign Signed](https://img.shields.io/badge/Sigstore-Cosign%20Signed-orange.svg)](https://sigstore.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**ClearCutt** is a free, open-source kit for platform and security engineers who need to **own** their container base images instead of trusting someone else's. You fork it once, and out of the box you get a hardened multi-language base-image fleet built with Nix, a signing-and-attestation pipeline, a catalog site, app-team templates, CI/CD policy gates, Kubernetes admission policies, and an approved remediation workflow — all running under **your** GitHub OIDC identities, with no hosted control plane to depend on.

By leveraging **Nix**, ClearCutt compiles target language runtimes (e.g., Java, Node.js, Python) as isolated `/nix/store` closures. While we provide secure, distroless images from-scratch, the blueprint also natively supports grafting these isolated layers directly on top of existing, government-mandated enterprise base OS configurations (such as Red Hat UBI, Amazon Linux, or Ubuntu Pro) as a compliance on-ramp. This lets platform teams stand up a strong, auditable container-security posture — a traceable cryptographic signature and attestation chain from source-code checkout to the Kubernetes admission gateway — while still satisfying legacy corporate image constraints.

---

## ClearCutt across the SDLC

ClearCutt does a lot, but it's one tool with one job per phase of the delivery lifecycle. Read the **outcome** to see the value; the **commands & evidence** column points at the section that proves it.

| Phase | What you get (the outcome) | Commands & evidence |
| :--- | :--- | :--- |
| **1. Author** | Own your base-image fleet as code — fork it, don't depend on a vendor. | `clearcutt.fleet.yaml` · Nix matrix · `platform init` |
| **2. Publish** | Every image ships signed, SBOM'd, and SLSA-attested — automatically. | GitHub Actions · `cosign` keyless · SPDX · SLSA Build L3 |
| **3. Discover** | One catalog shows exactly what's signed and scanned — no guessing. | `clearcutt list` · `inspect` · `matrix` |
| **4. Adopt** | App teams onboard in minutes — no Nix, no Dockerfile archaeology. | `clearcutt app template` · `dev` tier · devcontainers |
| **5. Certify** | Block non-compliant images before they leave CI. | `clearcutt certify` · `verify` · `certification-policy.yaml` |
| **6. Admit** | Only signed, attested images run in your clusters. | Kyverno / OPA admission policies |
| **7. Operate** | Patch a base once, move every app onto it — **no rebuild**. | `clearcutt app rebase` · VEX/exception triage · `mirror` |

> [!TIP]
> **Application developers don't need Nix.** Pull, run, and verify the published images with plain Docker, Podman, or Kubernetes. Nix is only for the platform team authoring the fleet in phase 1.

---

## Monorepo Layout

ClearCutt is organized as a three-part monorepo:

| Workspace | Purpose | Common commands |
| :--- | :--- | :--- |
| `core/` | Nix image factory, runtime overlays, release pipeline, vulnerability scanning, and image conformance tests. | `cd core && nix develop`, `make core-verify` |
| `cli/` | Go governance CLI (`clearcutt`) and its tests. | `make cli-build`, `make cli-test` |
| `site/` | Astro catalog site and generated catalog data. | `make site-dev`, `make site-build` |

Shared contracts and consumer material remain at the root: `schemas/`, `docs/`,
`examples/`, and `.github/`.

---

## Technical Architecture, Core Decisions & Security Trade-offs

Traditional base images force platform teams to choose between bloated operating systems (raising the CVE attack surface) or complex base image migrations. ClearCutt addresses this using the following architectural paradigms and documented trade-offs:

<p align="center">
  <img src="docs/images/supply-chain-flow.svg" alt="ClearCutt Supply Chain Flow" width="800" />
</p>


### 1. Injected Runtime Overlay (Nix-Store Hermeticity)
Instead of forcing downstream applications to migrate to a new OS, ClearCutt packages runtimes into isolated Nix store layers. 
* **Dynamic Linking Isolation:** Nix compiles target binaries (such as Python interpreters or Node runtimes) with their dynamic links (`RPATH`/`RUNPATH`) and interpreters bound strictly to Nix store subpaths. They execute in isolation from the host filesystem's `/lib` or `/usr/lib`, preserving mandated host configurations, monitoring daemons, and security agents.

> [!IMPORTANT]
> **Technical Assumption:** This architecture assumes downstream applications have no hard dependencies on host operating system libraries outside the Nix store closure. Any application that performs runtime discovery of `/usr/lib` paths, requires host-specific graphic drivers, or loads shared system libraries dynamically will break under this isolated hermetic model.

> [!WARNING]
> **macOS Cross-Compilation Constraint:** Nix native development shells seamlessly support both Linux and macOS (`x86_64` and `aarch64`) for running local command utilities and development runtimes on your host machine. However, cross-compiling heavy runtime systems (such as Java JDK, .NET SDK, or Python) from macOS to Linux target OCI layers via `pkgsCross` is unstable and unsupported by many upstream Nixpkgs derivations. For building the production `slim` and `distroless` image matrix tiers, compiling on a native Linux host (e.g., standard Linux virtual machine or CI runner) is strictly recommended.

### 2. Multi-Tiered Matrix Lifecycle
ClearCutt generates three distinct lifecycle tiers tailored for different stages of the delivery pipeline:
*   **`dev` (Builder Tier):** Equipped with raw runtime packages, interactive debugging shells (`bash`), standard utilities (`git`, `curl`), and CA certificates. Includes our integrated transient credential broker.
*   **`slim` (Diagnostic Runtime Tier):** A lean production execution environment that retains CA certificates, the target language runtime, and basic troubleshooting capabilities (`busybox`, `/bin/bash`).
*   **`distroless` (Hardened Zero-Utility Tier):** The most minimal production target. Contains no interactive shells or coreutils (No `/bin/sh`, `/bin/bash`, `ls`, or `cat`).

> [!WARNING]
> **Mitigation Boundary:** Removing shell binaries prevents `exec()`-based spawning of system shells (a common vector in remote command injection). However, it **does not mitigate other forms of Remote Code Execution (RCE)**. Code injection that executes direct system calls, spawns bundled executables, utilizes dynamic interpreter APIs (such as Python's `os.execve`), or launches Java processes using a custom-packaged shell binary is unaffected by this boundary.

### 3. Layer-Splitting & Caching Overhead
ClearCutt utilizes Nix's `buildLayeredImage` mechanism with a layer limit set to `maxLayers = 100`. 
* **Granular Layers:** Dependencies are split into individual OCI store layers. If a Python image and a Java image share identical store paths (such as `glibc` or `openssl`), registry mirrors download and cache these layers exactly once.

> [!NOTE]
> **Network Performance Trade-off:** Caching efficiency assumes a warm registry mirror or a shared network layer cache. In cold-start, highly distributed, or air-gapped environments, having up to 100 layers may introduce connection latency and metadata pull overhead compared to single-layer container archives.

### 4. Transient Credential Broker
To secure enterprise builds without exposing build secrets, the `dev` environment includes a credential broker that intercepts environment variables (`ENTERPRISE_MIRROR_*`) and dynamically generates isolated Maven `settings.xml`, NPM `.npmrc`, Pip `.netrc` routing tables, and Gradle configurations inside `.nix-enterprise-auth-cache/`. 
* The credentials folder is automatically added to Git exclusions (`.git/info/exclude`) to prevent commits, and is wiped cleanly via bash exit traps upon shell termination.

> [!CAUTION]
> **Security Risk:** Sourcing bootstrap credentials via environment variables is a potential exposure vector in environments where child processes or host `/proc` directories are readable. Platform teams should ensure environment variables are cleared or scrubbed immediately after the broker materializes the configuration files.

### 5. Why Nix? (Platform-Level Reproducibility vs. Imperative Dockerfiles)
Traditional container images are built using imperative package managers (`apt`, `apk`, `yum`) within a `Dockerfile`. This pattern presents significant challenges for enterprise-grade platform engineering:
* **Nondeterminism:** An `apt-get install` or `apk add` executed today may yield a different set of package versions and sub-dependencies than the same build run next month, resulting in silent drift and unverified changes.
* **Implicit Bloat & Hidden CVEs:** Imperative package managers pull in massive dependency trees, including shell utilities, package management databases, and library configurations that are completely unused by the runtime interpreter but continuously flag CVE scanner warnings.
* **Nix Solution:** ClearCutt uses Nix to build declarative, reproducible `/nix/store` closures.
  1. **Strict Hermeticity:** Nix ensures that every build dependency is pinned down to the exact input commit hash. The build has no internet access during compilation, preventing external tampering.
  2. **Mathematical Minimal Closures:** Nix builds a directed acyclic graph (DAG) of direct and transitive package dependencies. Only files that are strictly required by the application runtime are written into the OCI layers. This eliminates unused system bloat, reducing the vulnerabilities and keeping the container footprint extremely light.
  3. **Multi-Stage Overlay Scaffolding:** Because Nix compiles packages with fully isolated pathing, platform teams can graft a safe ClearCutt language runtime closure directly on top of legacy base OS layers.

---

## Supported Matrix & Offering

ClearCutt maintains and continuously gates a wide matrix of modern target language runtimes. **Note on point-in-time metrics:** Gating reduces the CVE attack surface through minimal dependency closures, but cannot guarantee "Zero CVEs"—especially when tracking cutting-edge or pre-release runtimes:

| Language | Supported Versions | dev Tier | slim Tier | distroless Tier |
| :--- | :--- | :--- | :--- | :--- |
| **Java** | `21`, `25` (LTS) | JDK + Compiler | JRE | Minimal JRE (No JShell) |
| **Node.js** | `22`, `24` (LTS) | Node + NPM + Yarn | Node Runtime | Pure Node Binary |
| **Python** | `3.13`, `3.14` (Pre-release) | Python + Pip + DevHeaders | Python Runtime | Pure Python Interpreter |
| **Go** | `1.25`, `1.26` (Pre-release) | Full Go Toolchain | Go Runtime | Binary Execution Layer |
| **.NET** | `8.0`, `10.0` | Full .NET SDK | ASP.NET Runtime | Hardened ASP.NET Layer |
| **Rust** | `1.95` | rustc + Cargo + Clippy + rustfmt | Static-binary base | Static-binary base |
| **C/C++** | `15` (GCC) | GCC + Make + CMake + Ninja | Static-binary base | Static-binary base |
| **Core** | `LTS` | Coreutils + Bash | Bash + BusyBox | CA Certificates Only |

> [!NOTE]
> **Compiled-language runtime tiers:** Rust and C/C++ produce statically-linkable binaries, so their `slim`/`distroless` tiers ship a minimal hardened base (CA certificates, plus a shell on `slim`) for you to drop your compiled artifact into — they intentionally omit the compiler toolchain, which lives only in the `dev` tier.

---

## Quickstart & Local Development

### 1. Enter the Gated Development Environment
Ensure you have Nix installed with flakes enabled. Enter the secure workspace shell:
```bash
cd core
nix develop --extra-experimental-features "nix-command flakes"
```
This drops you into a workspace shell preloaded with all necessary build and security binaries (including `patchelf`, `trivy`, `cosign`, and `container-structure-test`).

### 2. Run the Gated Automated Test Suite
ClearCutt implements a comprehensive gating test suite to verify dynamic dynamic linker safety, non-privileged boundaries, distroless shell absence, and credential brokerage leaks:
```bash
make core-verify
```

---

## Go Governance CLI (`clearcutt`)

To simplify local image discovery, platform inspection, and supply-chain policy verification, ClearCutt includes a statically compiled, operationally boring Go CLI named `clearcutt`.

### Build the CLI

Compile the binary from the root of the repository:
```bash
make cli-build
```

> [!NOTE]
> **Catalog data is required (and not committed).** The discovery/governance commands (`list`, `inspect`, `verify`, `diff`, `mirror`, `policy`, `vex`, `matrix`) read a generated catalog of image records. Generate it with `./clearcutt catalog build` (writes to `site/src/data/catalog`, the default `--catalog` path), or point `--catalog` at any catalog directory — e.g. the bundled fixture `cli/internal/testdata/catalog` for a quick offline demo:
> ```bash
> ./clearcutt list --catalog cli/internal/testdata/catalog
> ```

### CLI Command Reference

The `clearcutt` CLI is divided into purpose-built subcommands. Catalog and governance commands are offline; `app` commands are registry-direct and network-touching, but still require no Docker daemon or Nix installation.

#### 1. `list` (Catalog Image Discovery)
List all base images available in the local catalog index, with rich support for filtering by runtime language, matrix tier, and production readiness:
```bash
# List all images in clean, tabular format
./clearcutt list

# Filter images to only those allowed in production running Java
./clearcutt list --runtime java --production-only

# Filter images specifically by tier
./clearcutt list --tier distroless

# Output full images metadata in standard JSON format for pipeline parsing
./clearcutt list --format json
```

#### 2. `inspect` (Image Metadata Auditer)
Query high-fidelity security metadata, dynamic entrypoints, non-root user settings, compiled architectures, vulnerability counts, exception details, and release asset URLs:
```bash
# Inspect the latest release of Java 25 Distroless
./clearcutt inspect java25-distroless

# Inspect a specific release version tag
./clearcutt inspect java25-distroless --tag v0.6.2

# Inspect and output as structured YAML
./clearcutt inspect java25-distroless --format yaml
```

#### 3. `verify` (Policy Gate Enforcement)
Enforce software supply chain compliance checks locally or inside CI/CD gates. Validate OIDC signatures, SBOM attestations, SLSA levels, smoke test status, active support lifecycles, and maximum vulnerability counts. Can verify images, local catalog indexes, or published release evidence:
```bash
# Enforce strict supply chain gates locally on a catalog image
./clearcutt verify image java25-distroless \
  --require-signature \
  --require-sbom \
  --max-critical 0 \
  --max-high 3 \
  --exceptions exceptions.yaml

# Verify published OCI release evidence against Cosign + SLSA
./clearcutt verify release-evidence \
  --ref ghcr.io/northcutted/clearcutt/clearcutt-java25:distroless-v0.6.2 \
  --repo northcutted/clearcutt \
  --workflow-identity 'https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main'

# Verify the local catalog structure and database schema compliance
./clearcutt verify catalog
```

#### 4. `certify` (Downstream Container Auditor)
Audit downstream application image tarballs completely offline. Unpacks layered filesystems in-memory to verify the absence of shells, interactive package managers, and root UIDs, matching a declarative security policy:
```bash
# Export the target OCI container archive
docker save ghcr.io/acme/my-app:latest -o my-app.tar

# Run offline certification compliance audits
./clearcutt certify my-app.tar \
  --base java25-distroless \
  --policy certification-policy.yaml
```

#### 5. `conformance run` (Offline Spec Verification)
Runs local assertions against the current host or container environment completely offline. Validates timezone configurations, CA certificate link pathways, unprivileged execution permissions, and executes dynamic interpreter assertions:
```bash
# Execute standard conformance suite asserting Java is present on PATH
./clearcutt conformance run --expect-runtime java
```

#### 6. `dev` (Pinned Local Development Environments)
Launch the dev-tier sibling for any ClearCutt runtime line. The command pins the release tag, writes VS Code/Codespaces devcontainer definitions, or opens the same environment through a local container engine or Nix:
```bash
# Commit a release-tag-pinned devcontainer definition
./clearcutt dev java21-distroless --devcontainer

# Run the dev image locally with a writable bind mount
./clearcutt dev java21-distroless --container --engine docker

# Run a non-interactive CI smoke inside the dev image
./clearcutt dev java21-distroless --container --command 'java -version'

# Prefer the current Nix native runtime closure
./clearcutt dev java21-distroless --nix
```

#### 7. `overlay generate` (Nix Overlay Scaffolder)
Generates a self-contained Nix multi-stage grafting workspace to overlay ClearCutt secure runtimes directly on top of corporate base OS layers (e.g., Red Hat UBI, Ubuntu Pro, Amazon Linux). Includes Makefile, smoke tests, Containerfile, and GHA workflows:
```bash
# Scaffold workspace to graft Java 25 JRE onto RHEL UBI9
./clearcutt overlay generate \
  --runtime java25 \
  --tier distroless \
  --base registry.access.redhat.com/ubi9/ubi-minimal \
  --output my-java25-overlay/
```

#### 8. `exceptions validate` (Exceptions Schema Auditor)
Audits local declarative `exceptions.yaml` triage files against standard governance schemas. Verifies active owners, reference tags, and immediately flags any expired exception mappings:
```bash
# Audit exceptions configurations for syntax and expiration
./clearcutt exceptions validate exceptions.yaml --fail-on-expired-exceptions
```

#### 9. `mirror` / `mirror verify` (Secure OCI Layer Replication)
Generates high-fidelity `skopeo` and `cosign` shell script templates to securely replicate multi-arch base layers into internal registries while preserving Sigstore OIDC signatures, attestations, and OCI referrers. Supports verification of replicated artifacts:
```bash
# Generate replication script
./clearcutt mirror --source ghcr.io/acme/java25 --target my-registry.internal/java25

# Verify referrers and signatures of mirrored OCI elements
./clearcutt mirror verify --source ghcr.io/acme/java25 --target my-registry.internal/java25
```

#### 10. `app build` / `app diff-base` / `app rebase` / `app template` (Downstream Application Lifecycle)
Build, update, and scaffold downstream application images on ClearCutt bases without a Docker daemon. The rebase path swaps only base layers and preserves application layers byte-for-byte; it refuses runtime major/minor changes and requires a verified developer signature before emitting a signed "allowed" rebase attestation. The `template` command scaffolds starter projects.

For language-specific examples across Core/static, Java, Node.js, Python, Go,
.NET, Rust, and C/C++, see the aligned end-to-end guide in
[`docs/app-lifecycle.md`](docs/app-lifecycle.md).

```bash
# Scaffold an app-team starter project using ClearCutt
./clearcutt app template java --output clearcutt-template-java --name my-java-app

# Assemble a prebuilt artifact onto a ClearCutt base and push it
./clearcutt app build \
  --base java21-distroless \
  --artifact target/app.jar \
  --dest /workspace/app.jar \
  --entrypoint '["java","-jar","/workspace/app.jar"]' \
  --image ghcr.io/acme/payments-api:1.0.0

# Compare a candidate base before rebasing
./clearcutt app diff-base \
  --image ghcr.io/acme/payments-api:1.0.0 \
  --candidate-base java21-distroless

# Rebase, sign with the rebase-engine identity, and attach a rebase attestation
./clearcutt app rebase \
  --image ghcr.io/acme/payments-api:1.0.0 \
  --candidate-base ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless-v0.2.2 \
  --candidate-base-id java21-distroless \
  --tag ghcr.io/acme/payments-api:1.0.0-rebased \
  --dev-identity 'https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main' \
  --sign \
  --attest
```

---

### Declarative Governance Schemas

ClearCutt standardizes compliance policies and vulnerability triages using declarative YAML configurations that the CLI validates and parses.

#### 1. Exceptions Schema (`exceptions.yaml`)
Documents accepted CVE risks, owner mappings, and active expiration dates:
```yaml
apiVersion: clearcutt.dev/v1
kind: VulnerabilityExceptions
metadata:
  name: app-triage-exceptions
spec:
  exceptions:
    - id: "CVE-2026-9999"
      package: "openssl"
      image: "*"
      release: "*"
      status: "accepted_risk"
      reason: "inherited_from_base"
      owner: "eddie-northcutt"
      createdAt: "2026-05-30"
      expiresAt: "2026-08-30"
      references:
        - "https://nvd.nist.gov/vuln/detail/CVE-2026-9999"
      notes: "Vulnerable functions are completely sealed and unreachable in our distroless runtime closures."
```

#### 2. Certification Policy Schema (`certification-policy.yaml`)
Configures downstream OCI compliance gates dynamically:
```yaml
apiVersion: clearcutt.dev/v1
kind: CertificationPolicy
metadata:
  name: production-hardening-contract
spec:
  base:
    allowedImages:
      - "java25-distroless"
      - "python3.14-slim"
    requireDigestPinned: true
    requireKnownBase: true
  supplyChain:
    requireSignature: true
    requireProvenance: true
    requireSbom: true
    minimumSlsaLevel: 3
  runtime:
    requireNonRoot: true
    forbidShell: true
    forbidPackageManagers: true
    forbidDevTier: true
  lifecycle:
    allowPreview: false
    allowDeprecated: false
    allowExperimental: false
  vulnerabilities:
    maxCritical: 0
    maxHigh: 3
    allowExceptions: true
    exceptionFile: "exceptions.yaml"
```

#### 3. Rebase Attestation Schema
`schemas/rebase-attestation.schema.json` defines the full in-toto statement shape for `clearcutt app rebase --attest`. The CLI gives cosign the predicate body and cosign wraps it with the subject digest; an `allowed` predicate requires `developerSignatureVerified: true`, a pinned developer identity, the source image digest, compressed preserved app-layer digests, and the base-layer add/remove accounting.

---

## Consumption & Integration Patterns

### 1. CI/CD: Reusable GitHub Action Composite Block
You can easily build, certify, and sign your downstream applications using our composite action:

```yaml
# .github/workflows/build-app.yml
name: Build Application
on: [push]

permissions:
  contents: read
  packages: write
  id-token: write # Required for keyless OIDC Cosign signing

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... your own build + push steps that produce the image referenced below ...
      - name: Certify Application Against ClearCutt Contracts
        uses: northcutted/clearcutt/.github/actions/certify-app@v0.11.1
        with:
          image: 'ghcr.io/${{ github.repository }}/my-app:latest'
          base: 'java25-distroless'
          policy: 'certification-policy.yaml'
          # Pin the signer identity that built/signed the app image — never a wildcard:
          certificate-identity-regexp: 'https://github.com/${{ github.repository }}/.github/workflows/.*'
```

### 1.5 CI/CD: Zero-Rebuild Base Rebasing
After a developer workflow signs the original application image, a separate rebase workflow can move the image onto a patched ClearCutt base without recompiling the app layer:
```yaml
permissions:
  contents: read
  packages: write
  id-token: write

steps:
  - uses: sigstore/cosign-installer@v4
  - run: |
      clearcutt app rebase \
        --image ghcr.io/acme/payments-api:1.0.0 \
        --candidate-base ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless-v0.2.2 \
        --candidate-base-id java21-distroless \
        --tag ghcr.io/acme/payments-api:1.0.0-rebased \
        --dev-identity 'https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main' \
        --sign \
        --attest
```
Run this from CI with GitHub Actions OIDC (`id-token: write`) so cosign can sign keylessly as the rebase-engine workflow.
For the full app-build, developer-sign, diff, rebase, verify, and admission
pattern for every supported stack, see
[`docs/app-lifecycle.md`](docs/app-lifecycle.md).

### 2. Adopting ClearCutt Under a Base-Image Mandate
ClearCutt images are built **from scratch** for maximum hardening, but if your organization mandates a sanctioned base OS (Amazon Linux, UBI, Ubuntu Pro), you don't have to migrate to start benefiting. Because each runtime is a self-contained, `RPATH`-bound `/nix/store` closure, you can graft it directly onto the mandated base without modifying any OS layer or its bundled monitoring/security agents:

```dockerfile
# examples/base-image-overlay/Dockerfile
FROM ghcr.io/northcutted/clearcutt/clearcutt-java21:distroless AS clearcutt
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4

# Graft the hardened runtime closure on top — no /lib, /usr, or /etc/passwd
# from the mandated base is overwritten.
COPY --from=clearcutt /nix /nix
USER 10001:10001
```

See [`examples/base-image-overlay/`](examples/base-image-overlay/) for the full Dockerfile and an honest comparison of this overlay approach (Path A) versus full migration to the from-scratch images (Path B).

### 3. OCI Deployment: Secure Docker Compose Blueprint
For container runtimes, the project provides a hardened Compose blueprint enforcing strict Sandboxing:

```yaml
# examples/oci-deployment/docker-compose.yml
services:
  secure-app:
    image: ghcr.io/northcutted/clearcutt/clearcutt-python3.14:distroless
    read_only: true               # Locks container root (Nix store is immutable)
    security_opt:
      - no-new-privileges:true    # Prevents runtime privilege escalation
    cap_drop:
      - ALL                       # Drops all Linux kernel capabilities
    user: "10001:10001"           # Enforces unprivileged rootless boundaries
    tmpfs:
      - /tmp:mode=1777            # Mounts ephemeral /tmp into memory
```

### 4. Nix Native Flake overlay
For Nix native developers and downstream clusters, ClearCutt publishes packages and devShell libraries natively. Import ClearCutt in your `flake.nix` and apply the default overlay:

```nix
{
  inputs.clearcutt.url = "github:northcutted/clearcutt";
  outputs = { self, nixpkgs, clearcutt }: {
    devShells.x86_64-linux.default = let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [ clearcutt.overlays.default ];
      };
    in pkgs.mkShell {
      # Instantly overrides environment runtimes with ClearCutt verified layers
      buildInputs = [ pkgs.clearcuttJava25 ];
    };
  };
}
```

### 5. Kubernetes Native Deployment & Kyverno Admission Gating
ClearCutt provides complete deployment and policy manifests under `examples/k8s-deployment/` to enforce signature and SBOM verification.

* **Hardened Deployment (`deployment.yaml`):** Uses the secure unprivileged context (`runAsUser: 10001`), drops kernel capabilities, disables privilege escalation, and locks the root layer.
* **Admission Verification (`kyverno-policy.yaml`):** Enforces Kyverno `ClusterPolicy` rules that intercept Pod creation requests and traceably verify image signatures, signed SPDX SBOMs, and optional ClearCutt rebase attestations.

> [!CAUTION]
> **Webhook Availability Trade-off:** The provided Kyverno policy defaults to a fail-closed configuration (enforced via `validationFailureAction: Enforce`). If the Kyverno admission controller webhook becomes unavailable or crashes, all pod deployment operations matching this policy will be blocked on the cluster. Organizations must evaluate whether to fall back to auditing mode (`validationFailureAction: Audit`) depending on their high-availability and business continuity requirements.

### 6. Red Hat OpenShift Production Deployment
For deployment onto **Red Hat OpenShift (OCP)**, the project provides dedicated blueprints complying with strict **Security Context Constraints (SCC)** under `examples/openshift-deployment/`.

* **Arbitrary User ID Compliance:** OpenShift's `restricted-v2` SCC allocates random, high-range namespace UIDs at runtime and assigns membership to the `root` group (`gid: 0`). 
* **Optimized Manifest (`deployment.yaml`):** Omit hardcoded UIDs by removing the `runAsUser` pod spec parameter, enabling `runAsNonRoot: true`, and assigning `runAsGroup: 0` alongside emptyDir ephemeral volume mounts on writeable target paths (`/tmp`, `/app/logs`) to ensure maximum execution compliance.

> [!WARNING]
> **Root Group Security Implications:** Running with `runAsGroup: 0` (root group membership) alongside `runAsNonRoot: true` is standard practice on OpenShift to facilitate directory write access for dynamically assigned dynamic UIDs. However, it represents a security trade-off: any host filesystem file or system resource configured with group-write permissions (`g+w`) owned by `root` will be writeable by the unprivileged container user. Platform teams must ensure strict file permission audit controls on host systems to mitigate this risk.

---

## Fast path: adopt → certify → admit

The quickest way to feel the value is to walk one app team through phases 4–6 of the [lifecycle above](#clearcutt-across-the-sdlc). (Phases 1–3 — authoring and publishing the fleet — are a one-time platform-team setup.) Each step is incremental; you don't have to migrate everything at once:

### Step 1: Scaffold App Starters
Instead of writing complex custom Dockerfiles, use the Go CLI to bootstrap standard, secure project layouts for app teams:
```bash
./clearcutt app template node --output clearcutt-template-node --name payments-api
```
This scaffolds a project layout preconfigured with:
* Multi-stage build targetting ClearCutt `dev` and `distroless` runtimes.
* A strict declarative compliance policy (`certification-policy.yaml`).
* Automated GitHub Action release pipelines and rebase loops.

### Step 2: Integrate CI Verification Gates
Add the `clearcutt certify` check into your application PR pipelines completely offline (requiring no docker daemon or Nix):
```bash
# Save container build output
docker save my-app:latest -o my-app.tar

# Run compliance checks against policy gates
./clearcutt certify my-app.tar \
  --base node22-distroless \
  --policy certification-policy.yaml
```
This gates against accidental inclusion of shell utilities, package managers, root users, and high-severity CVEs before the image leaves CI.

### Step 3: Enforce Cluster Admission Gating
Deploy Kyverno policies in your Kubernetes namespaces to enforce supply chain integrity. Reject any deployment trying to run an unsigned container or one lacking a signed SBOM:
```bash
kubectl apply -f examples/k8s-deployment/kyverno-policy.yaml
```
This establishes a cryptographic security gate ensuring only certified and signed base overlays run in production.

---

## License

This project is open-source software licensed under the **Apache License, Version 2.0**.
