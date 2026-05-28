# Layering ClearCutt onto a Mandated Base Image

ClearCutt's published images are built **from scratch** — a pure `/nix/store`
closure plus CA certificates and a rootless account. That is what lets the
`distroless` tier be genuinely shell-less and minimal, and it's the recommended
target if you're free to choose your base.

But plenty of platform teams operate under a **base-image mandate**: every
container *must* derive from a sanctioned Amazon Linux 2023, Red Hat UBI, or
Ubuntu Pro image — usually because that base carries a required monitoring
agent, an endpoint-security daemon, or a centrally-tracked CVE baseline.

This example shows the two ways to adopt ClearCutt under that constraint.

---

## Path A — Graft the runtime onto your mandated base (no migration)

A ClearCutt runtime is a self-contained, `RPATH`/`RUNPATH`-bound `/nix/store`
closure. Nothing in it resolves host `/lib` or `/usr/lib` paths. That means you
can copy the closure straight onto your mandated base **without modifying any
OS layer** — the sanctioned agents, package manager, and host config all
survive untouched.

See [`Dockerfile`](./Dockerfile). The core of it is a single layer:

```dockerfile
FROM ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:distroless AS clearcutt
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4

# Bring the hardened runtime closure onto the mandated base. No /lib, /usr,
# or /etc/passwd from the base is overwritten.
COPY --from=clearcutt /nix /nix
RUN runtime_bin="$(find /nix/store -maxdepth 3 -type f -path '*/bin/java' | head -n1)"; \
    ln -sf "$runtime_bin" /usr/local/bin/java && /usr/local/bin/java -version
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/java"]
```

Build it:

```bash
docker build \
  --build-arg BASE_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal:9.4 \
  --build-arg CLEARCUTT_RUNTIME=ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:distroless \
  -t my-org/java21-on-ubi:latest \
  examples/base-image-overlay
```

> [!IMPORTANT]
> **Honest trade-off.** Path A keeps your mandated base, so you also keep that
> base's attack surface: its shell, coreutils, package manager, and whatever
> CVEs ride along with them. You get ClearCutt's reproducible, RPATH-isolated
> runtime, but **not** the distroless zero-utility guarantee. Use the catalog
> site to compare the resulting CVE posture against the from-scratch images.

> [!NOTE]
> **Updating runtimes independently of the OS.** Because the runtime lives
> entirely under `/nix/store`, you bump the language version by re-pointing
> `CLEARCUTT_RUNTIME` at a newer tag and rebuilding — the mandated base layer
> (and its agents) never has to change. That's the anti-migration-tax payoff.

---

## Path B — Migrate to the from-scratch ClearCutt images

If the mandate is negotiable, deriving directly from a ClearCutt image gives
you the full hardening story (shell-less distroless, minimal closure, signed +
attested provenance). This is the same pattern as
[`examples/clearcutt-template-java`](../clearcutt-template-java):

```dockerfile
FROM ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:dev AS builder
WORKDIR /workspace
COPY . .
RUN mvn clean package

FROM ghcr.io/eddie-northcutt/clearcutt-images/clearcutt-java21:distroless@sha256:<pin>
COPY --from=builder /workspace/target/app.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
```

---

## Which should I use?

| | Path A — overlay on mandated base | Path B — migrate to from-scratch |
| :--- | :--- | :--- |
| Base OS mandate | **Satisfied** (keeps sanctioned base) | Requires exception / waiver |
| Monitoring/security agents in base | Preserved | Re-attach separately |
| Attack surface | Base OS + runtime | Runtime only (smallest) |
| Distroless zero-utility guarantee | ❌ inherits base shell/utils | ✅ |
| Runtime updates without OS change | ✅ re-point `/nix` closure | ✅ new tag |
| Recommended when | You can't change the base today | You want maximum hardening |

Path A is the low-friction on-ramp; Path B is the destination. Many teams start
with A to prove the runtime works under their controls, then graduate to B
tier-by-tier as base mandates are relaxed.
