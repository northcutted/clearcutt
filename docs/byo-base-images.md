# Hardening & Trade-Offs of BYO Base Image Overlays

The `clearcutt overlay generate` command provides an adoption bridge for platform teams constrained by enterprise base-image mandates (e.g. mandated RHEL, Amazon Linux, or SLES). 

This document explains the technical architecture, grafting mechanism, and security trade-offs of the overlay pattern.

---

## 1. Nix store grafting mechanism
Because ClearCutt runtime environments are compiled using the Nix package manager, they represent a self-contained, closed loop `/nix/store` closure. All internal shared libraries, compilers, and interpreters are strictly linked via `RPATH` / `RUNPATH` directly into `/nix/store` entries.

This permits a multi-stage grafting build:
1. **Stage 1**: Pull the ClearCutt runtime image containing the target store closure (`/nix/store`).
2. **Stage 2**: Pull the corporate-mandated base image.
3. **Graft**: Copy the entire `/nix` folder from Stage 1 into Stage 2. Since nothing in the Nix store conflicts with standard OS library paths (`/lib`, `/usr/lib`, `/bin`), the graft completes cleanly without affecting any host utilities, package managers, or installed security daemons.

---

## 2. Hardening Trade-Offs

| Criteria | Pure ClearCutt (Scratch) | BYO Base Overlay |
| :--- | :--- | :--- |
| **Guaranteed Shell-Free** | Yes (in distroless) | No (inherits parent shell) |
| **Vulnerability Footprint** | Smallest (runtime-only) | Large (Base OS + runtime libraries) |
| **Security Agents in Base** | Must attach manually | Automatically preserved |
| **SLSA Provenance Scope** | Fully attested from source Nix | Attested separately for the final image |

---

## 3. Strict Compliance Instructions
- **Do Not Claim Distroless Guarantees**: Overlay images are **never** distroless unless the corporate base OS image is also distroless.
- **Independent Patching**: While the language runtime `/nix` closure can be updated independently by bumping the `--runtime-ref`, the underlying corporate base layer still requires standard OS security patching and vulnerability monitoring.
