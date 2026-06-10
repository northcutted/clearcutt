# Hardening & Trade-Offs of BYO Base Image Overlays

The `clearcutt overlay generate` command provides an adoption bridge for
platform teams constrained by enterprise base-image mandates such as RHEL,
Amazon Linux, or SLES.

This document explains the flake-based grafting mechanism, the offline
closure-equivalence check, and the security trade-offs of the overlay pattern.

## 1. Nix store grafting mechanism

ClearCutt runtime environments are built as closed `/nix/store` closures. Their
internal libraries, compilers, and interpreters are linked back into store paths
with `RPATH` / `RUNPATH`, so the runtime can be layered onto a mandated base
without relying on `/lib`, `/usr/lib`, or `/bin` from that base.

Use `clearcutt.lib.graftOntoBase` for the graft:

```nix
clearcutt.lib.graftOntoBase {
  inherit system;
  fromImage = mandatedBase;
  runtime = "java21";
  tier = "slim";
  name = "acme-java21-ubi";
  tag = "v2.1.0";
}
```

The helper uses the same fleet image builder as native ClearCutt images and
passes the mandated image through `buildLayeredImage`'s `fromImage` support.
That keeps the graft in Nix evaluation and build output instead of a hand-written
copy step.

## 2. Closure-equivalence attestation

After building the overlay image, compare the native ClearCutt runtime archive
with the grafted overlay archive:

```bash
clearcutt overlay verify \
  --runtime-archive clearcutt-java21.tar \
  --grafted-archive acme-java21-ubi.tar \
  --runtime-ref ghcr.io/acme/clearcutt-java21:v2.1.0-slim@sha256:... \
  --grafted-ref ghcr.io/acme/java21-ubi:v2.1.0@sha256:... \
  --target java21-slim \
  --output-predicate > closure-equivalence.intoto.json
```

The emitted in-toto predicate proves that the materialized `/nix/store` closure
inside the grafted image is byte-identical to the closure in the native runtime
archive. It does not prove the mandated base is minimal, distroless, or free of
its own vulnerabilities. The predicate subjects are the digest-pinned runtime
and grafted image refs; the closure hashes are recorded inside the predicate.

## 3. Hardening Trade-Offs

| Criteria | Pure ClearCutt Image | BYO Base Overlay |
| :--- | :--- | :--- |
| **Guaranteed Shell-Free** | Yes, for distroless tier | No, inherits parent shell if present |
| **Vulnerability Footprint** | Runtime-only | Base OS plus runtime closure |
| **Security Agents in Base** | Must attach separately | Preserved from mandated base |
| **Runtime Equivalence Proof** | Native release attestations | Closure-equivalence predicate plus final image attestation |
| **SLSA Provenance Scope** | Fully attested from source Nix | Runtime closure and final overlay must be attested separately |

## 4. Strict Compliance Instructions

- **Do Not Claim Distroless Guarantees**: overlay images are only distroless if
  the mandated base OS image is also distroless.
- **Keep Base Patching Separate**: updating the ClearCutt runtime closure does
  not patch the inherited corporate base layers.
- **Pin Inputs by Digest**: both the mandated base and the source runtime image
  should be digest-pinned in the generated flake and verification commands.
- **Gate on the Predicate**: admission policy should require the
  closure-equivalence predicate for the final grafted image digest when the
  runtime identity matters.
