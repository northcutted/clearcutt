# Estate View Design

The site was built as a catalog for a fleet ClearCutt publishes. The product is
now governing estates ClearCutt did not build, and `graph build` / `graph layers`
emit exactly the data that answers the governance question — as JSON, Markdown
and Mermaid, but not as a page. This closes that gap.

## Problem

Three gaps, in order of severity:

1. **Correctness.** Pages documented runtime lines the fleet no longer builds,
   and the committed catalog fixture held 39 records for a 12-cell fleet.
2. **Information architecture.** The front door is "Pick a runtime image" and
   the nav reads Catalog → Containerize your app → Operate fleet. That is a
   vendor's image catalog.
3. **Missing surface.** The auditable inventory a reviewer is supposed to read
   exists only as a Markdown file. There is no HTML view of the graph.

## Non-goals

- Rebuilding the site. `LayerExplorer`, `MatrixGrid`, `VulnerabilityTable` and
  `SbomTable` are ~2,700 lines of relevant rendering that already work.
- Making the estate view depend on ClearCutt having built anything. It must
  render for an estate of entirely third-party images.
- Live registry access from the browser. The page renders artifacts produced by
  a CLI run, exactly like the catalog does.

## Data contract

Two artifacts, both optional:

| File | Producer | Kind |
| --- | --- | --- |
| `graph.json` | `clearcutt graph build --output` | `BaseImageGraph` |
| `layers.json` | `clearcutt graph layers --output` | `LayerCommonalityGraph` |

They are staged under `public/estate/`, parallel to how catalog data lands in
`public/catalog/`. `site/src/lib/estate.ts` resolves them with the same
DATA_ROOTS fallback the catalog loader uses (`public/estate` then
`src/data/estate`).

**Absence is a first-class state.** A repo with no estate scan is the common
case, not an error. The loader returns `null` rather than throwing, and the page
renders an empty state naming the three commands that populate it. This mirrors
`loadIndex()`'s behaviour being wrapped in try/catch by every page that uses it.

## Pages

### `/estate` — what is built on what

- **Summary tiles**: images observed, base families, consumers resolved, on a
  stale base, base undetermined.
- **Proof vs claim**: how many relationships are proven by layer digests versus
  taken from a label the image author wrote. This is the honesty surface and it
  leads, because it is the number that qualifies everything below it.
- **Base families**: repository, versions seen, current version, consumers,
  stale consumers.
- **Stale consumers**, worst-first: the rebase candidate list, with versions and
  days behind and the method that established the edge.
- **Undetermined**: images whose base could not be found, each with its reason.
  Reported as findings, never dropped.

### `/estate/layers` — what the fleet has in common

- **Content-identical images** first. On this repo's own registry that section
  is the headline: 16 images in 6 identical groups.
- **Fleet core / most widely carried layers**, with coverage.
- **Clusters** and the Mermaid diagram, rendered inline.
- **Per-image profile**: how much of each image is content nothing else carries.
- **Deduplication**: stored once versus the cost with no layer reuse.

## CLI

`catalog site build` and `catalog site preview` gain `--graph` and `--layers`.
When passed, the file is copied to `public/estate/`. When omitted, the estate
pages render their empty state. No new command: the site is one artifact, and
splitting `graph site build` out would mean two Astro builds.

## Information architecture

Nav becomes: **Estate → Catalog → Containerize your app → Verify evidence →
Operate fleet → CLI → Limitations**, with Estate gated on
`navigation.showEstate` (default on) so a catalog-only fork can hide it.

The homepage leads with the estate path and demotes the fleet catalog to a
"reference fixtures" card, matching the README.

## What the pages must not claim

- A layer-prefix edge proves containment, not intent, and says nothing about
  whether either image is signed or fit for production.
- Declared/assisted/weak edges rest on metadata the image author supplied.
- Currency is measured against the newest version *in the scan*, not upstream.
- Shared layers are shared content, never a base relationship.

Each is stated on the page that could otherwise imply the opposite.
