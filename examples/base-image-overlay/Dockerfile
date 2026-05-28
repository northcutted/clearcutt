# =========================================================================
# ClearCutt — Layer a hardened runtime ON TOP OF a mandated base image
# =========================================================================
#
# ClearCutt's own images are built from scratch (pure /nix/store closure +
# CA certs + rootless account), which is what makes the distroless tier
# shell-less and minimal. But some organizations *mandate* a specific base OS
# (Amazon Linux 2023, Red Hat UBI, Ubuntu Pro) for compliance, CVE tracking,
# or a required monitoring/security agent baked into that base.
#
# Because a ClearCutt runtime is a self-contained, RPATH-bound /nix/store
# closure, you can copy it straight onto the mandated base without touching
# the base OS's libraries, package manager, or agents. This is the
# "anti-migration-tax" path: keep your sanctioned base, gain a hardened,
# reproducible language runtime on top of it.
#
# Build:
#   docker build \
#     --build-arg BASE_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal:9.4 \
#     --build-arg CLEARCUTT_RUNTIME=ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:distroless \
#     -t my-org/java21-on-ubi:latest \
#     examples/base-image-overlay
#
# Pin both build args to immutable @sha256 digests in production (see
# docs/decisions.md §2 — Cryptographic Digest-Pinning).

# The mandated enterprise base image. Swap for your org's pinned digest.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal:9.4

# The ClearCutt runtime whose /nix/store closure we want to graft on top.
# Any tier works; distroless gives the smallest, most hardened closure.
ARG CLEARCUTT_RUNTIME=ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:distroless

# ---- Stage 1: pull the ClearCutt runtime image so we can copy its store -----
FROM ${CLEARCUTT_RUNTIME} AS clearcutt

# ---- Stage 2: graft the runtime onto the mandated base ----------------------
FROM ${BASE_IMAGE}

# Copy the immutable Nix store closure. This brings the entire hardened runtime
# (interpreter + every shared library, each RPATH-bound to /nix/store) onto the
# mandated base. We deliberately DO NOT overwrite /etc/passwd, /lib, /usr, or
# any base OS layer — the sanctioned monitoring agents and host config survive.
COPY --from=clearcutt /nix /nix

# Expose the runtime entrypoint on PATH. We resolve the concrete store path once
# at build time and stabilize it behind /usr/local/bin so downstream ENTRYPOINTs
# don't have to change when the runtime store hash bumps. Adjust `java` to the
# binary your chosen ClearCutt runtime provides (node, python3, dotnet, ...).
RUN set -eux; \
    runtime_bin="$(find /nix/store -maxdepth 3 -type f -path '*/bin/java' | head -n1)"; \
    test -n "$runtime_bin"; \
    ln -sf "$runtime_bin" /usr/local/bin/java; \
    /usr/local/bin/java -version

# Run as the same unprivileged UID/GID ClearCutt images use. The numeric ID
# needs no matching /etc/passwd entry, so the base image's account database is
# left intact.
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/java"]
