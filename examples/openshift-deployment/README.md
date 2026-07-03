# ClearCutt Hardened Fleets - Red Hat OpenShift Deployment Blueprint

This directory provides a production-grade blueprint demonstrating how to deploy **ClearCutt Hardened base images** onto **Red Hat OpenShift Container Platform (OCP)**.

OpenShift enforces highly strict security controls via **Security Context Constraints (SCC)** instead of standard Kubernetes Pod Security Standards. Operating under OpenShift's default `restricted` or `restricted-v2` SCC introduces unique architectural security constraints, specifically the **Arbitrary User ID Pattern**.

---

## The OpenShift Arbitrary User ID Security Pattern

In standard Kubernetes, we enforce rootless boundaries by hardcoding a specific unprivileged UID/GID (such as `10001:10001` in the pod's `securityContext`).

However, OpenShift's `restricted` SCC **forbids hardcoded UIDs**. 
* **Dynamic Allocation:** At pod admission time, OpenShift allocates a **random, namespace-specific UID range** (e.g., UIDs between `1000070000` and `1000079999`) and forces the container to execute under a random dynamic UID from this range.
* **Root Group Membership:** To ensure files and directories are accessible to this dynamically allocated user, OpenShift automatically forces the container's active group to be the **root group (`gid: 0`)**.

### How ClearCutt Natively Supports OpenShift
1. **Dynamic User Compatibility:** ClearCutt images do not require hardcoded UIDs to remain secure. We omit the `runAsUser` pod spec parameter in our OpenShift manifests, allowing the OCP admission controller to dynamically assign the namespace UID.
2. **Writeable Directory Hardening:** In enterprise environments where applications must write files at runtime (such as temporary cache directories or logging paths):
   * Standard OpenShift guidelines mandate that writeable folders are owned by `root:root` with group read/write permissions (`chmod 775` or `777`).
   * ClearCutt implements this by mounting an in-memory `emptyDir` volume directly onto writeable paths like `/tmp` and `/app/logs` at pod runtime, ensuring the dynamically assigned UID has immediate write privileges without modifying static image store layers.

---

## Blueprint Manifests

This blueprint contains:
* **`deployment.yaml`:** An OpenShift-optimized Deployment manifest configured to comply with the standard `restricted-v2` SCC while locking down all other kernel capabilities. It deploys the published `clearcutt-corelts:slim` image (bash + busybox + CA certificates) with a placeholder command so the walkthrough below works literally. Distroless-tier images are intentionally **not** runnable on their own — they contain zero executables and no entrypoint, because they are scratch runtimes for *your* application layer. When adapting this manifest, swap in your app image built `FROM` a ClearCutt base (see [`examples/k8s-deployment/`](../k8s-deployment/) for that pattern) and remove the placeholder command.
* **`scc-binding.yaml`:** Demonstrates how to bind service accounts to specific security context constraints if your cluster requires customized privileges.

---

## Deployment & Verification

### 1. Create a New OpenShift Project
```bash
oc new-project clearcutt-sandbox
```

### 2. Apply the Hardened OpenShift Deployment
```bash
oc apply -f deployment.yaml
oc rollout status deployment/clearcutt-openshift
```

### 3. Verify the Dynamically Allocated UID
Once the rollout completes, inspect the execution user to confirm that OpenShift assigned a random high-range UID and root group (`gid: 0`). The `id` binary comes from busybox in the slim tier:
```bash
oc exec deployment/clearcutt-openshift -- id
```
**Expected Output** (your UID will differ — it comes from the range allocated to your namespace):
```text
uid=1000070000 gid=0(root) groups=0(root),1000070000
```
Reading that output carefully:
* The UID is **nameless** — no `(appuser)` suffix. The image's static `/etc/passwd` only maps UID `10001` to `appuser`; OpenShift's dynamically assigned UID has no passwd entry by design, so `id` prints the bare number. That is expected and correct under the arbitrary-UID pattern.
* `gid=0(root)` confirms the forced root-group membership that makes the mounted `emptyDir` volumes writeable.
* The trailing numeric supplemental group is the `fsGroup` the SCC admission controller applies from the namespace range; depending on cluster configuration it may be absent, leaving just `groups=0(root)`.

### 4. Inspect What the SCC Admission Controller Injected
Confirm the pod was admitted under `restricted-v2` and see the exact UID the admission controller wrote into the container security context:
```bash
oc get pod -l app=clearcutt-openshift \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n  scc: "}{.metadata.annotations.openshift\.io/scc}{"\n  runAsUser: "}{.spec.containers[0].securityContext.runAsUser}{"\n"}{end}'
```
**Expected Output:**
```text
clearcutt-openshift-5d9c7b6f4-abcde
  scc: restricted-v2
  runAsUser: 1000070000
```
This confirms that the container is running without root privileges under OpenShift's strict security boundaries, with the UID assigned at admission time rather than hardcoded in the image or manifest.
