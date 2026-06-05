# Catalog Schema

ClearCutt catalog artifacts are versioned JSON files. The schema files are
published in the repository under `schemas/` and copied into every generated
catalog under `schemas/`.

## Schema Versions

Current schema version identifiers:

- `clearcutt.catalog.index/v1`
- `clearcutt.catalog.image/v1`

Validate a generated catalog against a required schema version:

```bash
clearcutt --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.index/v1

clearcutt --catalog ./dist/catalog catalog validate \
  --schema-version clearcutt.catalog.image/v1
```

## Directory Layout

```text
catalog/
  index.json
  summary.json
  images/
    <image-id>.json
  raw/
    sbom/
    provenance/
    scans/
    test-results/
  schemas/
    catalog-index.v1.schema.json
    image-record.v1.schema.json
```

## `index.json`

`index.json` is the catalog overview. It contains:

- `schemaVersion`
- `generatedAt`
- `generator`
- `source`
- top-level `summary`
- owner, repository, repository URL, and registry base
- release summaries
- language summaries
- tier summaries
- image summaries

The index is optimized for listing, filtering, dashboards, and the catalog grid.
It should not duplicate every package, layer, vulnerability, or attestation
detail.

## `images/<id>.json`

Each image record contains the detailed evidence used by image detail pages and
policy tools:

- language and tier metadata
- registry and image reference fields
- lifecycle and runtime contract
- release history
- per-architecture payloads
- SBOM packages
- OCI layers and labels
- test results
- vulnerability findings
- signatures, attestations, and provenance metadata when available

## `summary.json`

`summary.json` is a small report for CI logs, dashboards, and quick checks. It
summarizes image, release, SBOM, scan, and evidence counts without requiring a
consumer to parse every image record.

## `raw/`

The `raw/` directories are reserved for source evidence artifacts:

- `raw/sbom/`
- `raw/provenance/`
- `raw/scans/`
- `raw/test-results/`

They may be empty. They are still emitted so static-site and artifact-publishing
workflows have stable paths.

## Compatibility Rules

- Consumers should check `schemaVersion` before assuming a record shape.
- Missing optional evidence should be handled as missing evidence, not as a
  successful trust signal.
- Unknown future fields should be tolerated by readers unless they are running
  with strict validation.
- Schema files in generated catalogs should match the repository schema files
  for the same version.
