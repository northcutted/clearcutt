# First-Class Service Images

> **Status note.** The reference fleet configures **no** service images. The
> capability described here is intact — `clearcutt service scaffold/validate/
> build/smoke/publish` all work, and the committed catalog fixture still
> exercises the service rendering path — but `postgres16`, `valkey8` and
> `oauth2-proxy7` are no longer built or published by this repository. Scaffold
> your own if your platform publishes services alongside runtimes.


Service images are the second platform-owned image lane in ClearCutt. Runtime
base images give app teams language foundations; service images give the
platform team repeatable backing services such as Postgres, Valkey, and
oauth2-proxy with the same release evidence, catalog visibility, and policy
language as the runtime fleet.

They are not runtime tiers and they do not use `clearcutt app build`. A service
image is declared in `clearcutt.fleet.yaml`, expanded into a generated backend
extension, built through `clearcutt service`, and rendered as `kind: service` in
catalog v2.

## Operator Flow

```bash
# Add the built-in service templates to clearcutt.fleet.yaml.
clearcutt service scaffold postgres16 --template postgres --version 16
clearcutt service scaffold valkey8 --template valkey --version 8
clearcutt service scaffold oauth2-proxy7 --template oauth2-proxy --version 7

# Validate every configured service and the generated backend extension.
clearcutt service validate --all

# Add Nix attr evaluation on platform build machines.
clearcutt service validate --all --nix --system x86_64-linux --core-dir core

# Build one single-arch service image locally.
clearcutt service build postgres16 --system x86_64-linux --core-dir core

# After loading the image into Docker or Podman, run the template smoke checks.
clearcutt service smoke postgres16 --engine docker
```

The CLI updates:

- `clearcutt.fleet.yaml`, the public fleet configuration.
- `core/lib/service-extensions.nix`, generated backend input. Fleet users
  should not hand-edit it.

## Built-In Templates

| Template | Default package | Port | Storage | Smoke |
| :--- | :--- | :--- | :--- | :--- |
| `postgres` | `postgresql_16` | `5432/tcp` | `/var/lib/postgresql/data` | version checks for `postgres`, `initdb`, and `pg_isready`; functional startup remains deployment-config dependent |
| `valkey` | `valkey` | `6379/tcp` | `/data` | version checks plus detached-container `valkey-cli PING` functional smoke |
| `oauth2-proxy` | `oauth2-proxy` | `4180/tcp` | stateless | version check only; meaningful server probes require provider config |

Stateful service templates create declared data directories as writable paths
for the rootless runtime user. Production deployments should mount volumes over
those paths, for example `/var/lib/postgresql/data` or `/data`, instead of
depending on image layers for durable storage.

Use `clearcutt service smoke --command-only` when you want only the configured
command-smoke checks or when a custom service needs external configuration
before it can start. Built-in functional probes currently run for templates
that can start without deployment-specific configuration, such as Valkey.

## Preview And Production Policy

New service entries default to `lifecycle.status: preview` and
`productionAllowed: false`. Preview service images still build, attach SBOMs,
run tests, and appear in the catalog, but they are not approved for production
deployment.

The vulnerability gate is intentionally different by lifecycle:

- Preview or otherwise non-production services record fixable high/critical
  findings as warning evidence.
- Active services with `productionAllowed: true` fail the vulnerability gate
  when policy thresholds are exceeded.

Promote a service only after the template, release evidence, vulnerability
posture, storage policy, and deployment guidance are ready for your environment.

## Catalog And Site

Service records require service-aware catalog generation:

```bash
clearcutt catalog generate \
  --config clearcutt.fleet.yaml \
  --include-services \
  --output dist/catalog

clearcutt --catalog dist/catalog catalog validate
clearcutt catalog site build --catalog dist/catalog --output dist/site --install
```

Runtime-only catalogs remain v1-compatible. Catalogs containing service images
emit v2 records with:

- `kind: service`
- `service.template`
- `service.version`
- `service.ports`
- `service.stateful`
- `service.dataDirs`
- `service.smoke`
- `service.smokeStatus`
- lifecycle, vulnerability, and evidence metadata

The catalog site renders service images outside the runtime matrix. Service
detail pages lead with ports, data dirs, entrypoint, runtime user, lifecycle,
vulnerability status, smoke status, evidence, and Docker/Podman/Compose/
Kubernetes examples.

Use the committed mixed fixture to verify service rendering without waiting for
a release:

```bash
clearcutt --catalog cli/internal/testdata/mixed-catalog catalog validate
clearcutt catalog site build \
  --catalog cli/internal/testdata/mixed-catalog \
  --template site \
  --output dist/service-demo \
  --install
```

## Release Behavior

Release workflows resolve service matrices separately from runtime matrices.
Each service is published as a single-arch service target, assembled into a
multi-arch `:service` image index, signed, attested, verified, exported as
release evidence, and included in the final GitHub Release asset set.

Runtime app lifecycle commands remain unchanged:

- `clearcutt app build`
- `clearcutt app diff-base`
- `clearcutt app rebase`

Those commands are for downstream application images, not platform-owned
service template images.
