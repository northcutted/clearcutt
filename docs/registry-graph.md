# Registry Scan And The Base Image Graph

ClearCutt can discover an image estate instead of being handed one.

`clearcutt registry scan` asks a registry what it actually holds. `clearcutt graph
build` then works out which of those images are built on which, how that was
established, and how far behind each consumer is from the newest version of its base.

The result is a governance inventory for images ClearCutt did not build, did not sign,
and knows nothing about in advance.

## Why This Exists

Every other governance path in ClearCutt starts from a list of image references that a
human wrote by hand. That inverts the actual problem: the reason a platform team needs
an inventory is that nobody knows what is running on what.

`rebase discover` answers *"is this app really on the base its owner told us it was
on?"* — it needs a declared `expectedBase`. `graph build` answers the discovery
question instead: *"given these images, which are built on which?"*

## Golden Path

```bash
# 1. Ask the registry what it holds
clearcutt registry scan \
  --registry ghcr.io \
  --namespace acme/platform \
  --repository base-java21 \
  --repository payments-api \
  --output dist/scan/images.yaml

# 2. Read each image's manifest, config, layers, and labels
clearcutt import observe \
  --images dist/scan/images.yaml \
  --output dist/scan/observations.json

# 3. Derive the graph and an auditable report
clearcutt graph build \
  --observations dist/scan/observations.json \
  --output dist/scan/graph.json \
  --report dist/scan/inventory.md
```

Every step is read-only against the registry. Nothing is pulled beyond manifests and
configs, no tag is mutated, and nothing is published.

## Enumerating A Registry

`registry scan` prefers the distribution `_catalog` endpoint, filtered by
`--namespace`. Several major registries — GHCR and Docker Hub among them — do not
implement `_catalog` for a user namespace. Name the repositories instead:

```bash
clearcutt registry scan --registry ghcr.io --namespace acme/platform \
  --repository base-java21 --repository base-node22 \
  --output dist/scan/images.yaml
```

`--repository` is repeatable and accepts either a bare name (qualified against
`--namespace`) or a full path.

### Sidecar Tags

Cosign signatures, attestations, and SBOM references are published as tags shaped like
`sha256-<digest>.sig`. They are evidence *about* an image, not images a workload runs,
and in a signed estate they outnumber real tags. `registry scan` skips them and reports
the count. Pass `--include-sidecar-tags` to keep them.

### Filters

| Flag | Effect |
| --- | --- |
| `--tag-pattern` | Keep only tags matching this glob. Repeatable. |
| `--exclude-tag` | Reject tags matching this glob, even if included. Repeatable. |
| `--max-tags` | Cap tags per repository (default 25), keeping the highest-sorting. |

### Credentials

`registry scan` authenticates from the ambient keychain (Docker config, cloud
credential helpers) by default. For explicit credentials:

```bash
export ACME_TOKEN=...
clearcutt registry scan --registry ghcr.io --namespace acme/platform \
  --username acme-ci --password-env ACME_TOKEN --output dist/scan/images.yaml
```

The password is read from an environment variable rather than a flag so a registry
token never lands in shell history or a process listing.

## How A Base Relationship Is Established

`graph build` applies five detectors, strongest first, and records every one that
matched so a reviewer sees what was tried rather than only the verdict.

| Method | Confidence | What it rests on |
| --- | --- | --- |
| `layer-prefix` | `verified` | The consumer's leading layer digests **are** the base's layers. |
| `oci-base-digest` | `declared` | `org.opencontainers.image.base.digest`, which BuildKit stamps automatically. |
| `buildpacks-metadata` | `declared` | `io.buildpacks.lifecycle.metadata` run-image reference or top layer. |
| `oci-base-name` | `assisted` | `org.opencontainers.image.base.name` — names the repository, not a version. |
| `history` | `weak` | The base repository appears in the consumer's build history. |

**Only `layer-prefix` is proof.** It compares content digests, so it holds regardless
of what an image claims about itself and cannot be forged by writing a label. It also
needs no cooperation from whoever built the image, which is what makes it work on an
estate that predates any of this tooling.

Everything else is a claim the image's own author made. The graph labels it as such,
and a self-reported label never outranks layer proof — if an image claims one base and
its layers prove another, the graph reports the proven one and keeps the contradicting
claim visible on the edge.

## Drift

A base *family* is every observed version of one repository. Currency is decided by the
image config's creation timestamp, not by tag name: tags lie (`latest` moves, `v2` can
predate `v10`) while the timestamp is baked into the artifact being scanned. Tag order
is only the tiebreak when timestamps are missing, and the report says so when it had to
fall back.

Each edge carries:

- `drift`: `current`, `stale`, or `unknown`
- `versionsBehind`: published versions between the matched base and the newest one
- `daysBehind`: days between the matched base and the newest one

Reproducible builders zero the creation timestamp on purpose — Nix `dockerTools`
stamps `1970-01-01T00:00:01Z` on everything. Those are treated as *no* timestamp
rather than as a real date, so currency falls back to tag order, `daysBehind` stays
0, and the base family carries a warning saying exactly that. Ranking a whole
reproducible fleet as equally old would be worse than admitting there is no signal.

Scanning several tags per base repository is what makes drift measurable. A scan of
only the newest tag can prove a consumer is current but cannot tell a stale consumer
from an unrecognised one.

## Shared Layers And Blast Radius

Images can share content without one being built on the other. A builder that
distributes store paths across layers by popularity — Nix
`dockerTools.buildLayeredImage`, most notably — produces sibling images that share
most of their content while neither is a prefix of the other. So does any workflow
that rebuilds from a common recipe rather than stacking a base.

`graph build` reports that separately, and never as parentage:

```
Shared layers (blast radius): 100 of 167 distinct layers are in more than one image; the widest is in 14
```

Each shared layer records every image carrying it. That answers the remediation
question directly: if a layer ships a vulnerable package, these are the images
affected — regardless of whether any of them is "based on" any other.

`--max-shared-layers` caps how many are retained (default 100, widest reach first;
`-1` keeps all).

When an image cannot be placed in the graph but does share layers, the unresolved
reason says so and points here rather than leaving a dead end.

### Layer-Prefix Detection Assumes A Stacked Base

This is the main limitation to know about. `layer-prefix` proof requires the base's
layers to be a *leading run* of the consumer's — the shape Dockerfile/BuildKit, jib,
ko, and buildpacks all produce. It does not fire on:

- Nix `dockerTools.buildLayeredImage` output, where content is distributed by
  popularity rather than stacked.
- Images squashed to a single layer after the fact.
- Any rebuild-from-recipe workflow that does not inherit a parent image.

For those estates the label-based detectors still apply if the builder stamps
`org.opencontainers.image.base.*`, and the shared-layer blast radius applies always.

## Layer-Level Commonality

`clearcutt graph layers` answers the other half of the question. Where `graph build`
asks what an image is built **on** — parentage, answered by layer *order* —
`graph layers` asks what the fleet has **in common** — content, answered by layer
*membership*. The two are independent, and neither implies the other.

```bash
clearcutt graph layers \
  --observations dist/scan/observations.json \
  --output dist/scan/layers.json \
  --report dist/scan/commonality.md \
  --mermaid dist/scan/graph.mmd
```

It reports:

| Section | Answers |
| --- | --- |
| Fleet core | Which layers are in **every** image. A vulnerability here hits everything at once. |
| Common layers | Which layers reach `--coverage` (default 0.75). The highest-leverage remediation targets. |
| Content-identical images | Which references carry byte-identical layer sets. |
| Clusters | Which images move together when shared content changes. |
| Similar pairs | Jaccard and containment for every pair above `--min-similarity` (default 0.5). |
| Per-image profile | How much of each image is content nothing else carries. |
| Deduplication | What the registry stores versus what the fleet would cost with no reuse. |

### Content-Identical Images

This one is worth calling out. Images published under different references with
identical layer sets usually mean a release republished something that did not
change. On this repository's own fleet, all 16 scanned images fall into 6 identical
groups — `v0.12.2`, `v0.13.0`, and `v0.14.0` are content-identical for every tier.
Three releases, no new content.

Note that identical layers mean identical *content*, not identical *configuration*:
two images can share every layer and still differ in entrypoint, user, or labels.

### The Diagram

`--mermaid` writes the clustered commonality graph, with edges labelled by shared
layer count. It renders on GitHub, in an Artifact, and anywhere else Mermaid is
supported. The report embeds the same diagram inline.

Both are capped for readability (24 images, 40 edges) and say what was elided.

### Scale

Pair generation walks the layer index rather than the image list, so images with
nothing in common are never compared — on a sparse estate that turns a quadratic scan
into work proportional to the sharing that actually exists. Above 500 images the
pairwise and clustering legs are skipped entirely with a warning; core, coverage, and
deduplication accounting are linear in total layers and stay available.

`--max-pairs` (default 250, `-1` for all) caps reporting only. Clustering always sees
every qualifying pair.

## Roots Versus Orphans

An image with no parent is not automatically a finding.

- **Roots** are images other images were proven to sit on, repositories named by
  `--base-repository`, or versions of a repository that is serving as a base elsewhere.
  A from-scratch base image belongs here.
- **Orphans** are images whose base genuinely could not be determined. These are audit
  findings, and the report says why each one could not be placed.

## Narrowing And Gating

```bash
# Only these repositories may act as bases
clearcutt graph build --observations obs.json --output graph.json \
  --base-repository 'ghcr.io/acme/platform/base-*'

# Accept only proven relationships
clearcutt graph build --observations obs.json --output graph.json \
  --min-confidence verified

# Fail CI when anything is on a stale base, or cannot be placed
clearcutt graph build --observations obs.json --output graph.json \
  --fail-on-stale --fail-on-unknown
```

`--fail-on-stale` and `--fail-on-unknown` exit 2, the same contract as ClearCutt's
other gates. The graph and report are still written when a gate fails: the failure is
a verdict, not a crash.

## What This Does Not Prove

- A `layer-prefix` edge proves the consumer contains the base's layers. It does not
  prove that base was the intended one, nor that either image is signed, scanned, or
  fit for production.
- A `declared`, `assisted`, or `weak` edge rests on metadata the image's author
  supplied. Treat it as a claim to verify, not a finding.
- Currency is measured against the newest version **observed in this scan**, not
  against upstream. A base family that is itself out of date will still report its
  consumers as current.
- A shared layer means shared content, not a base relationship.
- No CVE, signature, SBOM, or provenance conclusion is drawn. Run
  `clearcutt import assess` for the evidence-gap view, and
  `clearcutt rebase discover` / `clearcutt rebase plan` to prepare a rebase.

## Related

- [`imported-fleets.md`](imported-fleets.md) — governing images ClearCutt did not build
- [`generic-oci-mode.md`](generic-oci-mode.md) — the `images.yaml` data model
- [`app-lifecycle.md`](app-lifecycle.md) — the rebase path for ClearCutt-built apps
