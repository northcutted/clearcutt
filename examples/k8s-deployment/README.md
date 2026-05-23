# ClearCutt Kubernetes Deployment & Admission Gating Blueprint

This blueprint demonstrates how to run **ClearCutt Hardened container images** inside **Kubernetes (K8s)** with absolute process sandboxing, and establishes an end-to-end **"Keyboard to Cloud"** trust validation loop at admission time.

---

## 1. Production Pod Hardening

The [`deployment.yaml`](file:///Users/eddie/Development/clearcutt-images/examples/k8s-deployment/deployment.yaml) manifest implements strict Pod Security Standards (PSS) to enforce maximum runtime isolation:

*   **Rootless Context:** Runs the container strictly as unprivileged UID/GID `10001 (appuser)` via Pod-level `runAsUser` settings, blocking container escape vectors.
*   **Immutable RootFS:** Employs `readOnlyRootFilesystem: true` to prevent any modifications to the image layer at runtime.
*   **Ephemeral `/tmp` Mounting:** Maps `/tmp` to an in-memory `emptyDir` storage volume, allowing applications to write transient files (like cache folders) securely without exposing write pathways on the host node.
*   **Zero Capabilities:** Drops all standard Linux capabilities (`capabilities.drop: [ALL]`) to prevent kernel interaction exploits.
*   **No Escalation:** Sets `allowPrivilegeEscalation: false` to ensure child processes cannot elevate their execution context.

---

## 2. Dynamic Admission Gating (Kyverno)

The [`kyverno-policy.yaml`](file:///Users/eddie/Development/clearcutt-images/examples/k8s-deployment/kyverno-policy.yaml) is a declarative Kyverno `ClusterPolicy` that acts as the cluster's secure gatekeeper.

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
     1. Signature Check                              2. SBOM Check
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

### Keyless OIDC Assertions:
Instead of managing static public/private keys in Kyverno (which introduces key rotation overhead), the policy verifies our **GitHub Actions OIDC Identity**. 
*   It checks that the certificate issuer was `https://token.actions.githubusercontent.com`.
*   It asserts that the certificate subject was our non-falsifiable release workflow: `https://github.com/eddie-northcutt/clearcutt-images/.github/workflows/release.yml@refs/heads/main`.

This guarantees that **only** images compiled, scanned, and signed inside your official, secure CI/CD release workflow can ever be deployed onto your production nodes!

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
4.  Test policy gating. If you try to deploy an unsigned image or one without an SBOM from the clearcutt namespace, Kyverno will dynamically block admission:
    ```bash
    kubectl run uncertified --image=ghcr.io/eddie-northcutt/clearcutt-python3.14:slim
    # Outputs: Error from server: policy clearcutt-verify-provenance error: image verification failed...
    ```
