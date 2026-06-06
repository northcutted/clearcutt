# ClearCutt Kubernetes Deployment & Admission Gating Blueprint

This blueprint demonstrates how to run **ClearCutt Hardened container images** inside **Kubernetes (K8s)** with strict process sandboxing, and establishes an end-to-end **"Keyboard to Cloud"** trust validation loop at admission time.

---

## 1. Production Pod Hardening

The [`deployment.yaml`](./deployment.yaml) manifest implements strict Pod Security Standards (PSS) to enforce maximum runtime isolation:

*   **Rootless Context:** Runs the container as unprivileged UID/GID `10001 (appuser)` via Pod-level `runAsUser` settings, reducing the blast radius of runtime compromise.
*   **Immutable RootFS:** Employs `readOnlyRootFilesystem: true` to prevent any modifications to the image layer at runtime.
*   **Ephemeral `/tmp` Mounting:** Maps `/tmp` to an in-memory `emptyDir` storage volume, allowing applications to write transient files (like cache folders) securely without exposing write pathways on the host node.
*   **Zero Capabilities:** Drops all standard Linux capabilities (`capabilities.drop: [ALL]`) to prevent kernel interaction exploits.
*   **No Escalation:** Sets `allowPrivilegeEscalation: false` to ensure child processes cannot elevate their execution context.

---

## 2. Dynamic Admission Gating (Kyverno)

The [`kyverno-policy.yaml`](./kyverno-policy.yaml) is a declarative Kyverno `ClusterPolicy` that acts as the cluster's secure gatekeeper.

When a deployment is submitted, Kyverno intercepts the API request and performs the following dynamic cryptographic checks **before the pod is admitted to the cluster**:

```
                       Kubernetes Cluster API Server
                                     │
                             (Deployment Request)
                                     ▼
                      ┌──────────────────────────────┐
                      │    Kyverno Admission Policy  │
                      └──────────────┬───────────────┘
                                     │
             ┌───────────────────────┴───────────────────────┐
             ▼                                               ▼
     1. Signature Check                              2. Attestation Check
┌───────────────────────────┐                   ┌───────────────────────────┐
│ Is the OCI image signed   │                   │ Does a signed SPDX SBOM   │
│ by our verified GitHub    │                   │ attestation exist in the  │
│ Actions Release OIDC?     │                   │ image registry metadata?  │
└────────────┬──────────────┘                   └────────────┬──────────────┘
             │                                               │
             └───────────────────────┬───────────────────────┘
                                     │ (Both Passed)
                                     ▼
                         [ ADMITTED TO CLUSTER ]
```

For downstream applications rebased with `clearcutt app rebase`, the same policy
file includes a template pair of rules for `ghcr.io/acme/*`:

*   The rebased image digest must be signed by the pinned rebase-engine workflow.
*   A signed `https://clearcutt.dev/attestations/rebase/v1` predicate must exist.
*   The predicate must say `rebaseDecision: allowed`, `developerSignatureVerified: true`, and must carry the expected developer identity and issuer.

Kyverno evaluates signatures and attestations as separate `verifyImages` entries,
so the policy keeps the base-image signature rule, SBOM rule, rebase-engine
signature rule, and rebase-attestation rule split for clarity.

### Keyless OIDC Assertions
Instead of managing static public/private keys in Kyverno (which introduces key rotation overhead), the policy verifies our **GitHub Actions OIDC Identity**. 
*   It checks that the certificate issuer was `https://token.actions.githubusercontent.com`.
*   It asserts that the certificate subject was our non-falsifiable release workflow: `https://github.com/northcutted/clearcutt/.github/workflows/release.yml@refs/heads/main`.

For rebased downstream applications, replace the `acme` placeholders with your
developer and rebase-engine workflow subjects. Pin exact workflow identities
wherever practical; broad regexes reduce the value of the gate.

For the build, developer-sign, diff, rebase, and attestation flow that feeds
these admission checks across every supported stack, see
[`docs/app-lifecycle.md`](../../docs/app-lifecycle.md).

---

## How to Deploy the Blueprint

1.  Install Kyverno onto your cluster:
    ```bash
    helm repo add kyverno https://kyverno.github.io/kyverno/
    helm repo update
    helm install kyverno kyverno/kyverno -n kyverno --create-namespace
    ```
2.  Apply the Admission Policy:
    ```bash
    kubectl apply -f kyverno-policy.yaml
    ```
3.  Deploy your hardened application:
    ```bash
    kubectl apply -f deployment.yaml
    ```
4.  Test policy gating. If you try to deploy an unsigned image or one without the required SBOM attestation from the clearcutt namespace, Kyverno should block admission:
    ```bash
    kubectl run uncertified --image=ghcr.io/northcutted/clearcutt/clearcutt-python3.15:slim
    # Outputs: Error from server: policy clearcutt-verify-provenance error: image verification failed...
    ```
