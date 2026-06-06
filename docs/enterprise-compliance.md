# Enterprise Compliance Layering: Nix Closures on Corporate Base Images

ClearCutt is designed with architectural flexibility at its core. By default, we recommend using the **slim** or **distroless** tiers, which keep the runtime closure small and remove package-manager bloat from the production image.

However, in many regulated enterprise environments, corporate security mandates require that all container images derive from a specific, certified operating system baseline—such as **Red Hat Universal Base Image (UBI)**, **Ubuntu Pro / Ubuntu Minimal**, or **Amazon Linux 2023**.

With ClearCutt's Nix-based compilation architecture, you can meet those base-image mandates without giving up a separately governed language-runtime closure. The trade-off is explicit: the final image still inherits the mandated base's shell, package manager, and CVE footprint.

---

## 🏗️ Architectural Concept: Stacking Nix Store Closures

In a standard Dockerfile build, updating a runtime on a mandated OS base requires running package manager commands (e.g. `apt-get` or `dnf`) that write files into the host's `/usr`, `/lib`, and `/var` directories. This introduces:
1. **Layer bloat** and non-deterministic package drift.
2. **Version conflicts** between the base OS packages and the application runtime.
3. **Weaker reproducibility and traceability** for the runtime layer.

ClearCutt leverages Nix's `dockerTools.buildLayeredImage` and the `fromImage` parameter to stack self-contained `/nix/store` closures **directly on top** of the mandated base image. 

Because `/nix/store` paths are immutable and dynamically linked to their own isolated dependencies (including minimal, pinned builds of `glibc` and `openssl`), **they do not overwrite or modify the host operating system's own libraries and configuration**.

```
+-------------------------------------------------------+
| Nix Store Layer: nodejs-24 / openjdk-21 / python-3.15  | <-- ClearCutt Hardened Closure
+-------------------------------------------------------+
| Mandated Enterprise OS Base: RedHat UBI / AL2023      | <-- Statically Pinned OS Layers
+-------------------------------------------------------+
```

---

## 3 Enterprise Base OS Injection Examples

Below are concrete Nix flake patterns for stacking ClearCutt-style closures on top of Red Hat UBI, Ubuntu, and Amazon Linux 2023. Treat them as starting points for your platform fork and policy requirements.

### 1. Layering on Red Hat Universal Base Image (UBI 9)
The standard choice for enterprise environments utilizing Red Hat OpenShift or Red Hat Enterprise Linux.

```nix
# ubi-flake.nix
{
  description = "Red Hat UBI 9 Hardened Base Image Stacking";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system}.hardenedUbiJava = let
      # Pull the official mandated RedHat UBI 9 minimal base image
      ubiBase = pkgs.dockerTools.pullImage {
        imageName = "registry.access.redhat.com/ubi9/ubi-minimal";
        imageDigest = "sha256:73922c2a93268c12bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74"; # Mandated digest
        sha256 = "1a8m9f8h23kl32m31z... (Nix content-addressable hash)";
      };
    in pkgs.dockerTools.buildLayeredImage {
      name = "clearcutt-ubi-java";
      tag = "v21-slim";
      
      # Stack runtime directly on top of the mandated RHEL baseline
      fromImage = ubiBase;

      contents = [
        pkgs.jdk21.jre         # Isolated Java 21 JRE closure
        pkgs.cacert            # Immutable root certificates
      ];

      config = {
        Cmd = [ "${pkgs.jdk21.jre}/bin/java" "-jar" "/app/application.jar" ];
        WorkingDir = "/app";
        User = "10001:10001";  # Compliant rootless execution
        Env = [
          "PATH=${pkgs.jdk21.jre}/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          "HOME=/app"
          "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        ];
      };
    };
  };
}
```

### 2. Layering on Ubuntu (Ubuntu Minimal / Ubuntu Pro)
Commonly mandated in environments aligned with Canonical standards.

```nix
# ubuntu-flake.nix
{
  description = "Ubuntu Hardened Base Image Stacking";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system}.hardenedUbuntuNode = let
      # Pull the official Ubuntu Minimal baseline
      ubuntuBase = pkgs.dockerTools.pullImage {
        imageName = "ubuntu";
        imageDigest = "sha256:2b74ae08cc895b6c8cd1e0285b6c8cd1e0285b6c8cd1e0285b6c8cd1e0285b6"; # Approved Ubuntu digest
        sha256 = "12ab34cd56ef... (Nix content-addressable hash)";
      };
    in pkgs.dockerTools.buildLayeredImage {
      name = "clearcutt-ubuntu-node";
      tag = "v24-slim";

      fromImage = ubuntuBase;

      contents = [
        pkgs.nodejs_24
        pkgs.cacert
      ];

      config = {
        Cmd = [ "${pkgs.nodejs_24}/bin/node" "/app/index.js" ];
        WorkingDir = "/app";
        User = "10001:10001";
        Env = [
          "PATH=${pkgs.nodejs_24}/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          "HOME=/app"
          "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        ];
      };
    };
  };
}
```

### 3. Layering on Amazon Linux 2023 (AL2023)
The standard choice for AWS native services like Amazon ECS, EKS, and AWS Fargate.

```nix
# al2023-flake.nix
{
  description = "Amazon Linux 2023 Hardened Base Image Stacking";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system}.hardenedAmazonLinuxPython = let
      # Pull the official Amazon Linux 2023 minimal base image
      al2023Base = pkgs.dockerTools.pullImage {
        imageName = "public.ecr.aws/amazonlinux/amazonlinux";
        imageDigest = "sha256:d81cdde4bca07a1b7e4a... (AWS-mandated AL2023 minimal digest)";
        sha256 = "09k3m4n8klm12... (Nix content-addressable hash)";
      };
    in pkgs.dockerTools.buildLayeredImage {
      name = "clearcutt-al2023-python";
      tag = "v3.15-slim";

      fromImage = al2023Base;

      contents = [
        pkgs.python315
        pkgs.cacert
      ];

      config = {
        Cmd = [ "${pkgs.python315}/bin/python" "/app/main.py" ];
        WorkingDir = "/app";
        User = "10001:10001";
        Env = [
          "PATH=${pkgs.python315}/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          "HOME=/app"
          "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        ];
      };
    };
  };
}
```

---

## 🛡️ Cryptographic Signature & Attestation Traceability

By standardizing on this stacking architecture, your enterprise supply chain gets clearer evidence boundaries:

1. **Runtime closure evidence**: Nix builds the `/nix/store` runtime overlay from pinned inputs and produces an SBOM for that closure.
2. **Release attestations**: Your release workflow can generate signed build provenance and SBOM attestations under your GitHub Actions OIDC identity.
3. **Referrers copy**: Promotion scripts must preserve signatures and attestations when copying images into internal registries.
4. **Admission control enforcement**: Kyverno or OPA policies can verify image digests, signatures, and selected attestations before scheduling workloads. This narrows the set of images allowed into the cluster, but it does not replace base OS patching, runtime CVE triage, or application-layer controls.
