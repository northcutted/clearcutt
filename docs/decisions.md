# ClearCutt Hardened Fleets Architecture Decisions (ADR)

This document traces the design logic and rationale behind the key security constraints and architectural choices implemented across the ClearCutt ecosystem.

---

## 1. Rootless Context & Hardcoded UID/GID `10001`

* **Decision**: All container images in the slim and distroless tiers are statically configured to run as unprivileged user `10001` and group `10001` (`appuser`).
* **Rationale**: Running as `root` (UID 0) inside container namespaces remains the single largest risk vector for container escape vulnerabilities (such as CVE-2024-21626). Hardcoding the unprivileged UID `10001` ensures that even if an attacker successfully achieves remote code execution, they remain sandboxed under an unprivileged user space. 
* **Enterprise Alignment**: The `10001` UID complies directly with the Kubernetes Pod Security Standards (`restricted` profile) and aligns seamlessly with RedHat OpenShift's SCC dynamic group `gid: 0` constraints, allowing both standard K8s clusters and OCP platforms to admit and run the images securely.

---

## 2. Cryptographic Digest-Pinning (`@sha256`)

* **Decision**: All base image templates and production deployments must pin OCI image references using their immutable SHA-256 digest rather than standard mutable version tags.
* **Rationale**: In standard container registries, tags (like `:latest` or `:1.0.0`) are fully mutable. An attacker who gains write access to a registry can overwrite the tag with a compromised layer graph without altering downstream deployment configurations. In contrast, digest-pinning locks the exact cryptographic signature of the compiled Nix store layers.
* **Reproducibility**: Pinned digests ensure that every deployment, whether local, CI, or production, runs on the exact same bit-identical image archive, fully preventing tag-drift and man-in-the-middle container substitution attacks.

---

## 3. Selecting Java (JVM) as the Premier Template Runtime

* **Decision**: Java (specifically Java 21 LTS) was selected as the first comprehensive end-to-end template implementation.
* **Rationale**: The JVM ecosystem represents the largest enterprise application footprint and has historically been the target of catastrophic classloader injection vulnerabilities (like Log4Shell). Hardening Java applications presents the highest immediate business value.
* **Hermetic class paths**: By wrapping the Java runtime natively in a Nix store overlay on top of our zero-utility Distroless tier, we ensure that classloading cannot resolve external binaries, dynamic libraries, or temporary directories that are not explicitly gated and cryptographically verified at build time.

---

## 4. Total Elimination of Shells and Utilities in Distroless

* **Decision**: The `distroless` tier strips out every interactive shell (`/bin/sh`, `/bin/bash`, `/bin/ash`, `/bin/zsh`) and core utility binary (`ls`, `cat`) in both `/bin` and `/usr/bin`.
* **Rationale**: The vast majority of remote code execution (RCE) exploits rely on spawning a local shell binary (such as executing `exec("/bin/sh")` or utilizing shell pipe redirects) to download malware, crawl networks, or extract credentials. By ensuring there are literally no shell binaries present on disk, shell-injection attacks are rendered completely inert.
* **Attack Surface Reduction**: Stripping core utilities removes the developer's "convenience tools" (like `cat` or `ls`), which is a necessary trade-off to ensure attackers have zero discovery capability if they successfully breach the runtime process space.
