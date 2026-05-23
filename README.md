# ClearCutt Hardened Fleets

[![Nix Flake](https://img.shields.io/badge/Nix-Flake-blue.svg?logo=nixos&logoColor=white)](https://nixos.org)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-green.svg)](https://slsa.dev)
[![Cosign Signed](https://img.shields.io/badge/Sigstore-Cosign%20Signed-orange.svg)](https://sigstore.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**ClearCutt Hardened Fleets** is a next-generation declarative supply chain framework and platform engineering blueprint. It compiles, validates, certifies, and cryptographically signs a matrix of zero-CVE target language runtimes across multiple lifecycle tiers (`dev`, `slim`, and `distroless`).

By leveraging the declarative power of **Nix**, ClearCutt allows secure runtime layers (e.g. Java, Node.js, Python) to be injected as fully isolated `/nix/store` subpaths directly on top of your existing, mandated corporate base images (such as Amazon Linux 2023, RedHat UBI, or Ubuntu Pro). This completely bypasses the **"OS Migration Tax"** while establishing a traceable, cryptographically verified "Keyboard to Cloud" trust loop.

---

## Technical Architecture & Core Design Decisions

Traditional base images force platform teams to choose between bloated operating systems (raising the CVE attack surface) or complex base image migrations. ClearCutt solves this using the following architectural paradigms:

### 1. Injected Runtime Overlay (No OS Migration Tax)
Instead of forcing downstream applications to migrate to a new OS, ClearCutt packages runtimes into isolated Nix store layers. 
* Nix compiles target binaries (such as Python interpreters or Node runtimes) with their dynamic links (`RPATH`/`RUNPATH`) and interpreters explicitly bound strictly to the Nix store subpaths.
* These runtimes execute in complete isolation from the host filesystem's `/lib` or `/usr/lib`, ignoring host OS library mismatches while preserving mandated host configurations, monitoring daemons, and security agents.

### 2. Multi-Tiered Matrix Lifecycle
ClearCutt generates three distinct lifecycle tiers tailored for different stages of the delivery pipeline:
*   **`dev` (Builder Tier):** Equipped with raw runtime packages, interactive debugging shells (`bash`), standard utilities (`git`, `curl`), and CA certificates. Includes our integrated transient credential broker.
*   **`slim` (Diagnostic Runtime Tier):** A lean production execution environment that retains CA certificates, the target language runtime, and basic troubleshooting capabilities (`busybox`, `/bin/bash`).
*   **`distroless` (Hardened Zero-Utility Tier):** The ultimate production target. Contains **exactly zero interactive shells or coreutils** (No `/bin/sh`, `/bin/bash`, `ls`, or `cat`). It packages only the target runtime binary and CA certificates. Any potential shell-injection vulnerabilities inside application code are rendered completely inert because there is no shell to spawn.

### 3. Granular Layer-Splitting Caching
ClearCutt utilizes Nix's `buildLayeredImage` mechanism with a layer limit set to `maxLayers = 100`. 
* Instead of copying a monolithic runtime package, dependencies are split into individual OCI store layers.
* If a Python 3.14 image and a Java 25 image share identical cryptographic store paths (like `glibc` or `openssl`), registry mirrors and cloud nodes download and cache these layers exactly once, drastically reducing deployment times and network overhead.

### 4. Transient Credential Broker
To secure enterprise builds without exposing build secrets, the `dev` environment includes a credential broker that intercepts environment variables (`ENTERPRISE_MIRROR_*`) and dynamically generates isolated Maven `settings.xml`, NPM `.npmrc`, Pip `.netrc` routing tables, and Gradle configurations inside `.nix-enterprise-auth-cache/`. 
* The credentials folder is automatically added to Git exclusions (`.git/info/exclude`) to prevent commits, and is wiped cleanly via bash exit traps upon shell termination.

---

## Supported Matrix & Offering

ClearCutt maintains and continuously gates a wide matrix of modern target language runtimes:

| Language | Supported Versions | dev Tier | slim Tier | distroless Tier |
| :--- | :--- | :---: | :---: | :---: |
| **Java** | `21`, `25` (LTS) | JDK + Compiler | JRE | Minimal JRE (No JShell) |
| **Node.js** | `22`, `24` (LTS) | Node + NPM + Yarn | Node Runtime | Pure Node Binary |
| **Python** | `3.13`, `3.14` (Prerelease) | Python + Pip + DevHeaders | Python Runtime | Pure Python Interpreter |
| **Go** | `1.25`, `1.26` | Full Go Toolchain | Go Runtime | Binary Execution Layer |
| **.NET** | `8.0`, `10.0` | Full .NET SDK | ASP.NET Runtime | Hardened ASP.NET Layer |
| **Core** | `LTS` | Coreutils + Bash | Bash + BusyBox | CA Certificates Only |

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
        uses: ./#/.github/actions/build-certify
        with:
          language: 'java25'
          tier: 'distroless'
          image-name: 'ghcr.io/${{ github.repository }}/my-app:latest'
```

### 2. OCI Deployment: Secure Docker Compose Blueprint
For container runtimes, the project provides a hardened Compose blueprint enforcing strict Sandboxing:

```yaml
# examples/oci-deployment/docker-compose.yml
services:
  app:
    image: clearcutt-core-lts:distroless
    read_only: true               # Locks container root (Nix store is immutable)
    security_opt:
      - no-new-privileges:true    # Prevents runtime privilege escalation
    cap_drop:
      - ALL                       # Drops all Linux kernel capabilities
    user: "10001:10001"           # Enforces unprivileged rootless boundaries
    tmpfs:
      - /tmp:mode=1777            # Mounts ephemeral /tmp into memory
```

### 3. Nix Native Flake overlay
For Nix native developers and downstream clusters, ClearCutt publishes packages and devShell libraries natively. Import ClearCutt in your `flake.nix` and apply the default overlay:

```nix
{
  inputs.clearcutt.url = "github:eddie-northcutt/clearcutt-images";
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

### 4. Kubernetes Native Deployment & Kyverno Admission Gating
ClearCutt provides complete deployment and policy manifests under `examples/k8s-deployment/` to enforce **Keyboard to Cloud** verification.

* **Hardened Deployment (`deployment.yaml`):** Uses the secure unprivileged context (`runAsUser: 10001`), drops kernel capabilities, disables privilege escalation, and locks the root layer.
* **Admission Verification (`kyverno-policy.yaml`):** Enforces a Kyverno `ClusterPolicy` that intercepts Pod creation requests and traceably verifies:
  1. The container image signature is cryptographically signed keylessly by our GitHub Actions OIDC identity.
  2. The image registry metadata contains a valid, signed SPDX SBOM attestation before letting the container deploy on the cluster.

### 5. Red Hat OpenShift Production Deployment
For deployment onto **Red Hat OpenShift (OCP)**, the project provides dedicated blueprints complying with strict **Security Context Constraints (SCC)** under `examples/openshift-deployment/`.

* **Arbitrary User ID Compliance:** OpenShift's `restricted-v2` SCC allocates random, high-range namespace UIDs at runtime and assigns membership to the `root` group (`gid: 0`). 
* **Optimized Manifest (`deployment.yaml`):** Omit hardcoded UIDs by removing the `runAsUser` pod spec parameter, enabling `runAsNonRoot: true`, and assigning `runAsGroup: 0` alongside emptyDir ephemeral volume mounts on writeable target paths (`/tmp`, `/app/logs`) to ensure maximum execution compliance.

---

## License

This project is open-source software licensed under the **Apache License, Version 2.0**.
