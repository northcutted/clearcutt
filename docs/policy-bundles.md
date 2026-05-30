# Kubernetes Admission Control Policy Bundles

To enforce supply-chain governance at the cluster boundary, platform teams should generate and deploy declarative Kubernetes admission policies.

---

## 1. Kyverno Policy Generation
Kyverno policies are generated dynamically using `clearcutt policy` and include mutating digest parameters:
```bash
clearcutt policy java25-distroless \
  --format kyverno \
  --environment production \
  --namespace apps
```

### Key Policy Features:
- **Cosign Signature Gating**: Blocks pod scheduling if the container image lacks a valid keyless signature from the corporate Github OIDC identity.
- **Mutate Digests**: Automatically translates mutable tags (`:latest`, `:v1.0.0`) to cryptographically immutable digests (`@sha256:`) at the admission boundary, preventing tag modification attacks.
- **SLSA Provenance Verification**: Verifies that the SLSA level-3 provenance attestation matches the OIDC build workflow.

---

## 2. OPA Gatekeeper Integration
For OPA Gatekeeper environments, generate ConstraintTemplates and Constraint manifests:
```bash
clearcutt policy java25-distroless \
  --format gatekeeper \
  --namespace apps
```
This deploys a `ConstraintTemplate` named `K8sCosignSignatureVerify` that restricts pod deployments to verified, signed, and attested OCI registries.
