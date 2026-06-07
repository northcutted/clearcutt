# Service Images Example

This example shows the first-class ClearCutt service image flow for Postgres,
Valkey, and oauth2-proxy.

```bash
clearcutt service scaffold postgres16 --template postgres --version 16
clearcutt service scaffold valkey8 --template valkey --version 8
clearcutt service scaffold oauth2-proxy7 --template oauth2-proxy --version 7

clearcutt service validate --all
clearcutt service build postgres16 --system x86_64-linux
clearcutt service smoke postgres16 --engine docker

clearcutt catalog generate \
  --config clearcutt.fleet.yaml \
  --include-services \
  --output dist/catalog

clearcutt --catalog dist/catalog catalog validate
clearcutt catalog site build --catalog dist/catalog --output dist/site
```

The service entries are intentionally `preview` and
`productionAllowed: false`. Promote them after your organization has validated
runtime flags, storage policy, backup/restore posture, and release evidence.
