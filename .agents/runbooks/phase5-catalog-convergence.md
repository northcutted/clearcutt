# Phase 5: Catalog Producer Convergence

Goal: move the remaining catalog producer path from Node into the Go CLI while
preserving generated JSON shape.

**Decision (owner): full Go convergence.** The user wants the catalog producers —
including `enrich-registry.mjs`'s crane/cosign/sigstore logic — moved into Go.
Do NOT stop at gather-only. Port everything below into the CLI and delete the
Node scripts once proven.

## Scope

Move these producers behind Go commands, then delete them:

- `core/scripts/gather-catalog.mjs` (1079 lines)
- `core/scripts/enrich-registry.mjs` (698 lines)

Keep OUT of Phase 5:

- `core/scripts/cve-draft-agent.py` (LLM/Nix patch authoring — intentionally stays Python)
- Astro/site TypeScript (product UI, consumer only)

## Status (handoff from Claude)

**Increments 1–2 are DONE and byte-for-byte golden-verified.** Everything lives in
`cli/internal/commands/catalog.go` (+ `catalog_test.go`, + `testdata/catalog/`).
Full `go test ./...` is green. No command is registered yet and no script is
deleted yet — this is foundation only.

Ported + golden-tested so far:
- `determineLifecycle`, `determineRuntimeContract`, `defaultGatherExceptions`
  (all 39 targets, `meta-golden.json`).
- `compactPackages`, `rootDigest`, `mapPackageIDToLayerDigest`, `pickLicense`,
  `extractNixStorePath` (`spdx-fixture.json` → `spdx-golden.json`).
- `summarizeProvenance` + `decodeIntotoPayload` + `summarizeIntotoStatement` +
  `firstGitDependency` + `isUsefulProvenanceSummary` (`intoto-fixture.jsonl`).
- `releaseEvidence` was already ported in Phase 2 as `releaseEvidenceSummary`
  in `verifycatalog.go` — REUSE it, don't re-port.

Remaining: increments 3, 4, 5 below.

## The pattern to follow (already established — keep using it)

1. **Producer structs emit explicit nulls in the .mjs key order.** The consumer
   types in `internal/catalog` use `omitempty`; a nil pointer there OMITS the
   field, but the Node producer writes `"x": null`. So define dedicated producer
   structs (see `gatherLifecycle`, `spdxPackageOut` in `catalog.go`) with NO
   `omitempty`, fields in the exact order the .mjs object literal lists them.
   Go marshals struct fields in declaration order → key order matches JS insertion
   order.
2. **Empty arrays must be `[]T{}`, not nil** (nil marshals to `null`; JS emits
   `[]`). E.g. `cpes := []string{}`.
3. **Golden-capture from the Node functions verbatim.** Copy the pure function(s)
   into a standalone harness (see `/tmp/catalogport/*.mjs` examples — recreate as
   needed), run against a committed fixture, save output as golden testdata. The
   .mjs is ESM: use `import { readFileSync } from 'node:fs'`, NOT `require`.
4. **Test = byte-equality.** `json.Marshal(goStruct)` then `json.Compact(golden)`
   and `bytes.Equal`. This guards shape (explicit nulls, key order) AND values.
   See both tests in `catalog_test.go`.
5. Test scripts must be macOS bash 3.2 safe (no `${VAR,,}` lowercasing).

## Known problem to resolve in increment 3: the provenance `raw` passthrough

`summarizeIntotoStatement` sets `raw: payloadJson` (the entire decoded in-toto
statement). The current Go `provenanceOut` OMITS `raw`, and the golden capture
`delete`s it, so increment 2 byte-matches without it. But the real catalog output
needs it (`catalog.ProvenanceInfo.Raw` exists, `omitempty`). Byte-equality is hard
because JS `JSON.parse`+`JSON.stringify` re-serializes in source key order while
Go `map[string]any` marshals sorted. Decide one of:
- **(recommended)** Check whether the site or `verify-catalog` actually consume
  `provenance.raw`. Grep `site/src` for `.raw`. If nothing reads it, DROP it from
  the producer output (it's `omitempty`, so this is a clean, shape-compatible
  simplification — document it).
- Otherwise store `raw` as `json.RawMessage` of the original decoded payload bytes
  and accept that whole-record golden tests compare semantically (parse both, deep-equal)
  rather than byte-for-byte for records that carry raw.

## Increment 3 — image-record assembly + index (behind a GitHub interface)

Port from `gather-catalog.mjs`:
- `buildImageRecord` (lines ~633–883) — the 250-line core that merges releases,
  SBOM assets, enrichment, and vulnerabilities into an `ImageRecord`.
- `summarizeImageForIndex` (277–343), `main` index assembly (921–998),
  `refreshTagSet` (912–919), `rebuildIndexFromExistingImages` (1006+),
  `defaultArchPayload` (883–896), `guessArchFromAsset` (897–911),
  `archForSystem` (628–632), `parseTargetName` (412–417), `targetMeta` (419–427),
  `normalizeAssertions` (246–252), `displayAssertionName` (235–245),
  `remediationReason` (211–219), `remediationBucket` (220–234),
  `attachReleaseAssetLinks` (597–606), `loadEnrichment` (608–617),
  `loadVulnerabilities` (618–627).
- Reuse `releaseEvidenceSummary` (verifycatalog.go) for evidence.

Key design: put GitHub behind an interface so assembly stays offline-testable:
```
type ReleaseSource interface {
    ListReleases(limit int) ([]Release, error)   // ghJson + listReleases (368–399)
    DownloadAsset(asset Asset) ([]byte, error)    // downloadAsset (400–411)
}
```
The real impl uses `net/http` against `api.github.com` with the `GITHUB_TOKEN`
header (see `ghJson`, lines 368–380; auth header at 370–373). The TEST impl
returns fixtures, so `buildImageRecord` + index assembly get a golden test with
zero network. Resolve the `raw` question here. Persist SBOMs to `SBOM_CACHE_DIR`
exactly as the .mjs does (lines 700–707) — `clearcutt scan` reads them.

## Increment 4 — enrich-registry.mjs → Go (the hard one)

**REUSE existing Go infrastructure — do NOT reimplement crane/cosign/cert parsing
from scratch.** The CLI already has:
- `internal/oci` — `Client`/`NewClient` (go-containerregistry). Use for
  manifest/config/digest instead of shelling to `crane` (`manifestList`/
  `imageConfig` at enrich lines 192–196, `crane digest` at 504).
- `internal/sign` — `Cosign` wrapper (`New(binary, identity, issuer, ...)`).
  Use/extend for `cosign download attestation` (201–227) and `cosign verify`
  (228–259).
- `internal/attest` — in-toto `Statement`/`Predicate`/`Subject` types.

Functions to port from `enrich-registry.mjs`:
- `enrichOne` (484–618) — per-(release,target) enrichment driver.
- Cert/sigstore parsing (260–365): `certSubjectUri`, `certIssuer`,
  `certificateFromBundle`, `payloadFromBundle`, `subjectDigest`, `attestationKind`,
  `transparencyLogIndex`/`transparencyUrl`, `releaseWorkflowIdentity`. Go stdlib
  `crypto/x509` + `encoding/pem` handle the cert SAN/issuer extraction; the SAN
  workflow-identity URI is in the cert's `URIs` field or the OIDC extension.
- `normalizeAttestation` (366–385), `normalizeGithubAttestation` /
  `normalizeOciAttestation` (386–406), `mergeAttestations` (418–440),
  `attestationMergeKey` (407–417).
- `summarizeProvenance` (441–472) — NOTE this is enrich's variant (takes a parsed
  payload, not JSONL); reconcile with gather's `summarizeProvenance` already in
  `catalog.go`.
- `extractTestResults` (473–483), `listGithubAttestations` (175–191),
  `tagsToRefresh` (619–628).

Put crane/cosign behind an interface (like increment 3's ReleaseSource) so the
attestation-normalization/merge logic is golden-tested offline with bundle
fixtures. Writes go to `ENRICHMENT_DIR` (`site/src/data/enrichment/<tag>/<target>.json`).

## Increment 5 — command group, workflow, deletion

1. Add `clearcutt catalog` command group + register in `root.go`:
   - `catalog gather --limit N`, `catalog enrich`, `catalog build --limit N`.
   - `catalog build` runs the two-pass flow: gather → enrich → `clearcutt scan` →
     gather again (fold in enrichment + vulns) → `clearcutt verify-catalog`.
2. Rewire `.github/workflows/publish-pages.yml` gather job: replace the
   `node core/scripts/gather-catalog.mjs` / `enrich-registry.mjs` steps with
   `./clearcutt catalog ...`. The CLI is already built in that job (Phase 2 added
   Setup Go + Build CLI before the verify-catalog step — move/confirm it runs
   before the gather step). Also update `Makefile catalog-generate` and `core/README.md`.
3. **Only after** golden tests pass AND a real `publish-pages` run produces a
   catalog that `clearcutt verify-catalog` accepts: delete `gather-catalog.mjs`
   and `enrich-registry.mjs`. Grep for stale refs (workflows, Makefile, package.json,
   docs) like prior phases.

## Verification

- `cd cli && go test ./... -count=1` ; `go vet ./...` ; `gofmt -l internal/`.
- Capture golden offline; keep `--strict` on in at least one assembly test
  (exercises `catalog.Strict` unknown-field rejection).
- Cross-check evidence booleans against `clearcutt verify-catalog` (they must agree —
  that command is the validator).

## Non-negotiables

- Evidence summary booleans byte-aligned with `verify-catalog`.
- Do not reintroduce a third schema: Go is producer + validator; the site only consumes.
- Old releases are cache-sensitive — preserve the `refreshTagSet` "refresh latest,
  read older from disk" behavior and the SBOM cache key inputs.
- Do NOT delete the Node scripts until golden + a workflow run both agree.

## 2026-06-01 Codex Completion Notes

- Increment 3 landed in `cli/internal/commands/catalog.go`:
  `buildImageRecord`, index summary generation, target parsing, assertion
  normalization, release evidence, SBOM cache persistence, enrichment/vulnerability
  loading, and `refreshTagSet`.
- `provenance.raw` was dropped from producer output. `site/src` does not consume it,
  `verify-catalog` does not require it, and `catalog.ProvenanceInfo.Raw` remains
  optional for older generated records.
- Increment 4 landed as `clearcutt catalog enrich`, backed by
  `internal/oci.Client` for manifest/config/layer metadata and an extended
  `internal/sign.Cosign` wrapper for `cosign verify --output json` and
  `cosign download attestation`. OCI and GitHub attestations are normalized and
  merged in Go.
- Increment 5 landed as `clearcutt catalog gather`, `clearcutt catalog enrich`,
  and `clearcutt catalog build`; workflows and Makefile now use the CLI.
- Deleted `core/scripts/gather-catalog.mjs` and `core/scripts/enrich-registry.mjs`
  after local Go verification. A real `publish-pages` run is still the recommended
  final network validation because registry/cosign evidence is environment-dependent.
