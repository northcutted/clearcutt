# ClearCutt Docker Compose Container Hardening Blueprint

This blueprint demonstrates how to deploy **ClearCutt Hardened OCI images** inside **Docker Compose** or single-host docker sandboxes utilizing industry-standard security profiles.

By combining the cryptographic immutability of Nix store paths with strict container runtime parameters, we achieve complete containment of target application processes.

---

## The Four Core Hardening Pillars

The [`docker-compose.yml`](./docker-compose.yml) template implements the following defense-in-depth measures:

### 1. Rootless Boundaries (`user: "10001:10001"`)
Ensures the container process starts natively in our pre-provisioned unprivileged user space. If an attacker manages to break out of the application process, they land on the host system as a completely unprivileged user (UID `10001`), preventing standard container escape vectors.

### 2. Immutable Filesystem (`read_only: true`)
Mounts the container's root layers as read-only. 
*   **Why Nix fits perfectly:** In standard Docker, `read_only` often breaks containers because applications try to write logs, caches, or binaries to random paths. Because Nix-compiled images store *all* libraries and binaries in read-only `/nix/store` paths, and we map an ephemeral, memory-backed `tmpfs` volume to `/tmp`, the application has exactly what it needs to execute safely while completely blocking any local filesystem write mutations!

### 3. Total Capability Drop (`cap_drop: [ALL]`)
By default, Docker containers retain some kernel capabilities (like raw socket mappings or system time configurations). We drop **all** Linux kernel capabilities. The process can execute code but cannot manipulate network routes, raw device mounts, or OS boundaries.

### 4. Privilege Escalation Block (`no-new-privileges:true`)
Blocks the container process or child sub-processes from acquiring new privileges (e.g. via `setuid` or `setgid` dynamic binaries).

---

## How to Execute the Blueprint

1.  Place your application runtime code inside a local `./app-code` folder.
2.  Start the sandbox:
    ```bash
    docker compose up -d
    ```
3.  Verify container process permissions:
    ```bash
    docker exec clearcutt-hardened-app whoami
    # Outputs: appuser
    
    docker exec clearcutt-hardened-app touch /test
    # Outputs: touch: /test: Read-only file system
    ```
