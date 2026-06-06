# First-Class Service Images

ClearCutt service images are platform-owned application services such as
Postgres, Valkey, and oauth2-proxy. They are not runtime tiers and they do not
use `clearcutt app build`. A service image is declared in `clearcutt.fleet.yaml`,
expanded into a generated Nix service extension, built through
`clearcutt service`, and rendered as `kind: service` in catalog v2.

## Built-In Templates

| Template | Default package | Port | Storage | Smoke |
| :--- | :--- | :--- | :--- | :--- |
| `postgres` | `postgresql_16` | `5432/tcp` | `/var/lib/postgresql/data` | `postgres --version`, `initdb --version`, `pg_isready --version` |
| `valkey` | `valkey` | `6379/tcp` | `/data` | `valkey-server --version`, `valkey-cli --version` |
| `oauth2-proxy` | `oauth2-proxy` | `4180/tcp` | stateless | `oauth2-proxy --version` |

New service entries default to `lifecycle.status: preview` and
`productionAllowed: false`. Promote them only after the service template,
release evidence, and operational policy are ready for your environment.

## Add The MVP Services

```bash
clearcutt service scaffold postgres16 --template postgres --version 16
clearcutt service scaffold valkey8 --template valkey --version 8
clearcutt service scaffold oauth2-proxy7 --template oauth2-proxy --version 7
```

The CLI updates two files:

- `clearcutt.fleet.yaml`, which is the public fleet configuration.
- `core/lib/service-extensions.nix`, which is generated backend input. Fleet
  users should not hand-edit it.

## Validate, Build, And Smoke

```bash
clearcutt service validate --all
clearcutt service validate --all --nix --system x86_64-linux

clearcutt service build postgres16 --system x86_64-linux
clearcutt service smoke postgres16 --engine docker
```

`service build` runs the same compile, SBOM, vulnerability gate, and local
certification path as runtime images, but passes `--kind service` to the core
pipeline. `service smoke` runs the configured smoke commands against the local
service image using Docker or Podman.

## Catalog And Site

Service-aware catalogs emit v2 schema records while runtime-only catalogs remain
v1 compatible.

```bash
clearcutt catalog generate \
  --config clearcutt.fleet.yaml \
  --include-services \
  --output dist/catalog

clearcutt --catalog dist/catalog catalog validate
clearcutt catalog site build --catalog dist/catalog --output dist/site
```

Service records include:

- `kind: service`
- `service.template`
- `service.version`
- `service.ports`
- `service.stateful`
- `service.dataDirs`
- `service.smoke`
- evidence and smoke status

The site renders services outside the runtime matrix and provides service
detail pages with ports, storage, smoke status, lifecycle badges, evidence
badges, and run examples.

## Release Behavior

Release workflows now resolve service matrices separately from runtime matrices.
Each service is published as a single-arch service target, assembled into a
multi-arch `:service` image index, signed, attested, verified, exported as
release evidence, and included in the final GitHub Release asset set.

Runtime app lifecycle commands remain unchanged:

- `clearcutt app build`
- `clearcutt app diff-base`
- `clearcutt app rebase`

Those commands are for downstream application images, not service template
images.
