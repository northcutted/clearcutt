# ClearCutt Catalog Site Workspace

This workspace owns the Astro catalog site. Generated catalog, enrichment, SBOM,
and vulnerability data is written under `site/src/data` by scripts in
`core/scripts`.

```bash
cd site
npm ci
npm run typecheck
npm run build
npm run dev
```

From the repository root, use:

```bash
make site-typecheck
make site-build
make site-dev
```
