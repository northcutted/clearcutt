# ClearCutt Hardened Fleets

[![Nix Flake](https://img.shields.io/badge/Nix-Flake-blue.svg?logo=nixos&logoColor=white)](https://nixos.org)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-green.svg)](https://slsa.dev)
[![Cosign Signed](https://img.shields.io/badge/Sigstore-Cosign%20Signed-orange.svg)](https://sigstore.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**ClearCutt Hardened Fleets** is a free, open-source base image blueprint and declarative packaging framework designed for platform and security engineers. Rather than shipping a closed, opinionated operating system, ClearCutt operates as a customizable template built with Nix. You can use our secure, hardened runtimes straight out of the box, or easily fork the blueprint to customize and compile your own enterprise-wide base image fleet.

By leveraging **Nix**, ClearCutt compiles target language runtimes (e.g., Java, Node.js, Python) as isolated `/nix/store` closures. While we provide secure, distroless images from-scratch, the blueprint also natively supports grafting these isolated layers directly on top of existing, government-mandated enterprise base OS configurations (such as Red Hat UBI, Amazon Linux, or Ubuntu Pro) as a robust compliance bandaid. This empowers platform teams to achieve elite container security postures—establishing a traceable cryptographic signature and attestation chain from source code checkout to the Kubernetes admission gateway—while seamlessly satisfying legacy corporate image constraints.

---

## Technical Architecture, Core Decisions & Security Trade-offs

Traditional base images force platform teams to choose between bloated operating systems (raising the CVE attack surface) or complex base image migrations. ClearCutt addresses this using the following architectural paradigms and documented trade-offs:

### 1. Injected Runtime Overlay (Nix-Store Hermeticity)
Instead of forcing downstream applications to migrate to a new OS, ClearCutt packages runtimes into isolated Nix store layers. 
* **Dynamic Linking Isolation:** Nix compiles target binaries (such as Python interpreters or Node runtimes) with their dynamic links (`RPATH`/`RUNPATH`) and interpreters bound strictly to Nix store subpaths. They execute in isolation from the host filesystem's `/lib` or `/usr/lib`, preserving mandated host configurations, monitoring daemons, and security agents.
* > [!IMPORTANT]
  > **Technical Assumption:** This architecture assumes downstream applications have no hard dependencies on host operating system libraries outside the Nix store closure. Any application that performs runtime discovery of `/usr/lib` paths, requires host-specific graphic drivers, or loads shared system libraries dynamically will break under this isolated hermetic model.
* > [!WARNING]
  > **macOS Cross-Compilation Constraint:** Nix native development shells seamlessly support both Linux and macOS (`x86_64` and `aarch64`) for running local command utilities and development runtimes on your host machine. However, cross-compiling heavy runtime systems (such as Java JDK, .NET SDK, or Python) from macOS to Linux target OCI layers via `pkgsCross` is unstable and unsupported by many upstream Nixpkgs derivations. For building the production `slim` and `distroless` image matrix tiers, compiling on a native Linux host (e.g., standard Linux virtual machine or CI runner) is strictly recommended.

### 2. Multi-Tiered Matrix Lifecycle
ClearCutt generates three distinct lifecycle tiers tailored for different stages of the delivery pipeline:
*   **`dev` (Builder Tier):** Equipped with raw runtime packages, interactive debugging shells (`bash`), standard utilities (`git`, `curl`), and CA certificates. Includes our integrated transient credential broker.
*   **`slim` (Diagnostic Runtime Tier):** A lean production execution environment that retains CA certificates, the target language runtime, and basic troubleshooting capabilities (`busybox`, `/bin/bash`).
*   **`distroless` (Hardened Zero-Utility Tier):** The ultimate production target. Contains **exactly zero interactive shells or coreutils** (No `/bin/sh`, `/bin/bash`, `ls`, or `cat`).
* > [!WARNING]
  > **Mitigation Boundary:** Removing shell binaries prevents `exec()`-based spawning of system shells (a common vector in remote command injection). However, it **does not mitigate other forms of Remote Code Execution (RCE)**. Code injection that executes direct system calls, spawns bundled executables, utilizes dynamic interpreter APIs (such as Python's `os.execve`), or launches Java processes using a custom-packaged shell binary is unaffected by this boundary.

### 3. Layer-Splitting & Caching Overhead
ClearCutt utilizes Nix's `buildLayeredImage` mechanism with a layer limit set to `maxLayers = 100`. 
* **Granular Layers:** Dependencies are split into individual OCI store layers. If a Python image and a Java image share identical store paths (such as `glibc` or `openssl`), registry mirrors download and cache these layers exactly once.
* > [!NOTE]
  > **Network Performance Trade-off:** Caching efficiency assumes a warm registry mirror or a shared network layer cache. In cold-start, highly distributed, or air-gapped environments, having up to 100 layers may introduce connection latency and metadata pull overhead compared to single-layer container archives.

### 4. Transient Credential Broker
To secure enterprise builds without exposing build secrets, the `dev` environment includes a credential broker that intercepts environment variables (`ENTERPRISE_MIRROR_*`) and dynamically generates isolated Maven `settings.xml`, NPM `.npmrc`, Pip `.netrc` routing tables, and Gradle configurations inside `.nix-enterprise-auth-cache/`. 
* The credentials folder is automatically added to Git exclusions (`.git/info/exclude`) to prevent commits, and is wiped cleanly via bash exit traps upon shell termination.
* > [!CAUTION]
  > **Security Risk:** Sourcing bootstrap credentials via environment variables is a potential exposure vector in environments where child processes or host `/proc` directories are readable. Platform teams should ensure environment variables are cleared or scrubbed immediately after the broker materializes the configuration files.

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
nix develop --extra-experimental-features "nix-command flakes"
```
This drops you into a workspace shell preloaded with all necessary build and security binaries (including `patchelf`, `trivy`, `cosign`, and `container-structure-test`).

### 2. Run the Gated Automated Test Suite
ClearCutt implements a comprehensive gating test suite to verify dynamic dynamic linker safety, non-privileged boundaries, distroless shell absence, and credential brokerage leaks:
```bash
./tests/verify.sh
```

---

## Go Governance CLI (`clearcutt`)

To simplify local image discovery, platform inspection, and supply-chain policy verification, ClearCutt includes a statically compiled, operationally boring Go CLI named `clearcutt`.

### Build the CLI

Compile the binary from the root of the repository:
```bash
go build -o clearcutt ./cmd/clearcutt
```

### CLI Command Reference

The `clearcutt` CLI is divided into zero-daemon, purpose-built subcommands. Below is the complete reference of core commands and their real-world usage patterns:

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
Enforce software supply chain compliance checks locally or inside CI/CD gates. Validate OIDC signatures, SBOM attestations, SLSA levels, smoke test status, active support lifecycles, and maximum vulnerability counts:
```bash
# Enforce strict supply chain gates locally
./clearcutt verify java25-distroless \
  --require-signature \
  --require-sbom \
  --max-critical 0 \
  --max-high 3 \
  --exceptions exceptions.yaml
```

#### 4. `certify` (Downstream Container Auditor)
Audit downstream application image tarballs completely offline. Unpacks layered filesystems in-memory to verify the absolute absence of shells, interactive package managers, and root UIDs, matching a declarative security policy:
```bash
# Export the target OCI container archive
docker save ghcr.io/acme/my-app:latest -o my-app.tar

# Run offline certification compliance audits
./clearcutt certify my-app.tar \
  --base java25-distroless \
  --policy certification-policy.yaml
```

#### 5. `conformance run` (Offline Spec Verification)
Runs local assertions against OCI base images or active containers completely offline. Validates timezone configurations, CA certificate link pathways, unprivileged execution permissions, and executes dynamic interpreter assertions:
```bash
# Execute standard conformance suite against Java 25 Distroless
./clearcutt conformance run --image java25-distroless
```

#### 6. `overlay generate` (Nix Overlay Scaffolder)
Generates a self-contained Nix multi-stage grafting workspace to overlay ClearCutt secure runtimes directly on top of corporate base OS layers (e.g., Red Hat UBI, Ubuntu Pro, Amazon Linux). Includes Makefile, smoke tests, Containerfile, and GHA workflows:
```bash
# Scaffold workspace to graft Java 25 JRE onto RHEL UBI9
./clearcutt overlay generate \
  --runtime java25 \
  --tier distroless \
  --base registry.access.redhat.com/ubi9/ubi-minimal \
  --output my-java25-overlay/
```

#### 7. `exceptions validate` (Exceptions Schema Auditor)
Audits local declarative `exceptions.yaml` triage files against standard governance schemas. Verifies active owners, reference tags, and immediately flags any expired exception mappings:
```bash
# Audit exceptions configurations for syntax and expiration
./clearcutt exceptions validate exceptions.yaml --fail-on-expired
```

#### 8. `mirror` / `mirror verify` (Secure OCI Layer Replication)
Generates high-fidelity `skopeo` and `cosign` shell script templates to securely replicate multi-arch base layers into internal registries while preserving Sigstore OIDC signatures, attestations, and OCI referrers. Supports verification of replicated artifacts:
```bash
# Generate replication script
./clearcutt mirror --source ghcr.io/acme/java25 --target my-registry.internal/java25

# Verify referrers and signatures of mirrored OCI elements
./clearcutt mirror verify --source ghcr.io/acme/java25 --target my-registry.internal/java25
```

---

### Declarative Governance Schemas

ClearCutt standardizes compliance policies and vulnerability triages using declarative YAML configurations that the CLI validates and parses.

#### 1. Exceptions Schema (`exceptions.yaml`)
Documents accepted CVE risks, owner mappings, and active expiration dates:
```yaml
apiVersion: clearcutt.dev/v1
kind: Exceptions
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
      - name: Build and Certify Application
        uses: ./.github/actions/build-certify
        with:
          language: 'java25'
          tier: 'distroless'
          image-name: 'ghcr.io/${{ github.repository }}/my-app:latest'
```

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
* **Admission Verification (`kyverno-policy.yaml`):** Enforces a Kyverno `ClusterPolicy` that intercepts Pod creation requests and traceably verifies image signatures and signed SPDX SBOMs.
* > [!CAUTION]
  > **Webhook Availability Trade-off:** The provided Kyverno policy defaults to a fail-closed configuration (enforced via `validationFailureAction: Enforce`). If the Kyverno admission controller webhook becomes unavailable or crashes, all pod deployment operations matching this policy will be blocked on the cluster. Organizations must evaluate whether to fall back to auditing mode (`validationFailureAction: Audit`) depending on their high-availability and business continuity requirements.

### 6. Red Hat OpenShift Production Deployment
For deployment onto **Red Hat OpenShift (OCP)**, the project provides dedicated blueprints complying with strict **Security Context Constraints (SCC)** under `examples/openshift-deployment/`.

* **Arbitrary User ID Compliance:** OpenShift's `restricted-v2` SCC allocates random, high-range namespace UIDs at runtime and assigns membership to the `root` group (`gid: 0`). 
* **Optimized Manifest (`deployment.yaml`):** Omit hardcoded UIDs by removing the `runAsUser` pod spec parameter, enabling `runAsNonRoot: true`, and assigning `runAsGroup: 0` alongside emptyDir ephemeral volume mounts on writeable target paths (`/tmp`, `/app/logs`) to ensure maximum execution compliance.
* > [!WARNING]
  > **Root Group Security Implications:** Running with `runAsGroup: 0` (root group membership) alongside `runAsNonRoot: true` is standard practice on OpenShift to facilitate directory write access for dynamically assigned dynamic UIDs. However, it represents a security trade-off: any host filesystem file or system resource configured with group-write permissions (`g+w`) owned by `root` will be writeable by the unprivileged container user. Platform teams must ensure strict file permission audit controls on host systems to mitigate this risk.

---

## License

This project is open-source software licensed under the **Apache License, Version 2.0**.
