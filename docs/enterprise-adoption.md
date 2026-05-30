# ClearCutt Enterprise Adoption Roadmap

Adopting a hardened, digest-pinned, and supply-chain attested base image catalog requires an incremental strategy to minimize application downtime while systematically reducing attack surface.

---

## 1. Step 1: Establish Policy Visibility (Development Tier)
Start by migrating test environments and development pipelines to ClearCutt's `dev` tier images (e.g. `java25:dev` and `python3.14:dev`):
- Maintain full shell and package manager availability for local debugging.
- Enable `clearcutt list` and `clearcutt inspect` to analyze package counts and SBOM contents in CI.

---

## 2. Step 2: Graft Onto Mandated Bases (Adoption Bridge)
If your organization mandates a sanctioned operating system base (e.g., Red Hat UBI or Ubuntu Pro):
- Use `clearcutt overlay generate` to layer ClearCutt's reproducible `/nix` closure onto your mandated base OS.
- This preserves pre-baked host agents and host compliance daemons while standardising language runtime interpreters.
- *Trade-off*: Note that overlays inherit the base OS vulnerabilities and interactive shells.

---

## 3. Step 3: Graduate to Production Minimality (Slim/Distroless)
Identify core applications that do not require shell-based execution at runtime:
- Transition to the `slim` tier (package-manager-free) or `distroless` tier (shell-free, package-manager-free).
- Enforce strict unprivileged operators (`UID 10001:10001`) natively.

---

## 4. Step 4: Enforce Admission Gating (Strict Verification)
Deploy Kyverno ClusterPolicies or OPA Gatekeeper constraints:
- Require Cosign keyless signatures and SLSA level-3 provenance attestations.
- Run `clearcutt certify` inside GitHub Actions or GitLab CI pipelines to mathematically block compliance drifts before pushing to production registries.
