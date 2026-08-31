# CLI Pivot Plan — From Forkable Monorepo to a Released, Self-Contained CLI

**Status:** proposed · **Owner:** platform · **Audience:** an implementer (human or
AI agent) executing this in phases.

## Goal

Turn ClearCutt from "fork this monorepo" into "download a signed `clearcutt`
binary, point it at (or scaffold) a GitHub repo, and it deploys a working
SLSA-grade fleet." The released binary must be **self-contained**: it carries
everything needed to build, gate, verify, sign, remediate, and scaffold a fleet,
and works against an arbitrary repo without a checkout of *this* tree.

## The core insight (why "native Go" and "the pivot" are one initiative)

*(Historical snapshot from when this plan was written — the shells-out description below no longer holds: the Go engine is the workflow default, `pipeline.sh` survives only behind `--engine shell`, and deterministic drafting is native with the Python agent as fallback. See the Progress section.)*

Today the CLI is a thin orchestrator that **shells into a second logic tier** in
`core/` by hardcoded relative paths:

- `core/pipeline/pipeline.sh` — build + SBOM (syft) + scan (grype) + push
  (skopeo) + sign (cosign). Reached by `fleet certify-target`/`fleet
  publish-target`/`service build` via `nix develop --command ./pipeline/pipeline.sh`.
- `core/tests/verify.sh` (+ `closure-*.py`) — the ~10 image-security gates.
  Reached by an opaque `nix develop -- ./tests/verify.sh` passthrough.
- `core/scripts/cve-draft-agent.py` — deterministic patch routing + the optional
  LLM tier. `remediation run` `exec()`s it.

A binary cannot scaffold or run logic it does not contain. **So making the logic
native Go is the mechanism that makes the CLI self-contained, which is what makes
scaffolding possible.** Q1 ("make it all native Go") and Q2 ("the pivot") are the
same work.

### What becomes Go vs what stays Nix

"All native Go" means the **ClearCutt logic** is Go. It still *invokes* a few
external binaries — and that is correct, not a gap:

| Concern | Disposition |
| --- | --- |
| Hermetic build engine (`nix build`, flake eval, closures) | **Stays Nix.** Go shells out to `nix`, like it shells out to `git`. This is the SLSA/reproducibility value prop; do not reimplement. |
| `flake.nix`, `core/lib/*.nix`, `core/overlays/**` (recipes/data) | **Stays Nix, embedded as assets.** The CLI carries and templates these; it does not "port" them. |
| Build/SBOM/scan/sign orchestration (`pipeline.sh`) | **Becomes Go** in `internal/build`. Calls `nix` directly, runs Syft/Grype through the pinned Nix dev shell until their Go APIs are embedded, keeps Cosign as the signing fallback, and uses go-containerregistry for push/index work. |
| Image-security gates (`verify.sh`, `closure-*.py`) | **Becomes Go** in `internal/gates` (closure walk, CVE-floor tuple compare, structure checks — all pure logic). |
| Remediation deterministic routing (`cve-draft-agent.py`) | **Becomes Go** in `internal/remediation`. The **LLM tier becomes an optional pluggable HTTP provider** (off by default), satisfying the "optional, not required" requirement. |
| Supply-chain tools (`grype`, `syft`, `cosign`, `crane`) | **External deps.** Several are Go libraries you can import directly; otherwise pinned subprocesses resolved via the embedded Nix shell. |

Net: the *ClearCutt codebase* becomes all-Go; it orchestrates `nix` + a handful
of pinned, mostly-Go supply-chain tools.

### Design rule: zero shell, zero ambient tools

The released binary must run with **no shell and no ambient toolbox** — ideally
runnable in a `scratch`/distroless context where only `nix` is on PATH (fitting,
given what we ship). Concretely:

- **Never invoke a shell.** No `exec.Command("bash", "-c", ...)`, no `sh -c`, no
  reliance on `/bin/sh`. All subprocesses use `exec.Command(bin, args...)` with an
  explicit argv so there is no shell parsing, quoting, or injection surface.
- **Prefer Go libraries over subprocesses** where a solid one exists:
  - OCI build/copy/push/index → `go-containerregistry` (**already a dependency**;
    retires `skopeo`/`crane`).
  - SBOM → `anchore/syft` Go API (retires the `syft` binary).
  - Scan → `anchore/grype` Go API (retires the `grype` binary; DB refresh handled
    in-process).
  - Sign/verify → `sigstore-go` / cosign libraries (retires most `cosign` shelling).
- **`nix` is the one unavoidable external binary**, invoked directly via
  `exec.Command("nix", ...)` — never through a shell. Today the Go build engine
  uses `nix build` for image realization and `nix develop --command syft|grype`
  for pinned SBOM/scan tools, so the released CLI does not require ambient
  Syft/Grype installs. Importing those libraries later can remove even that dev-shell
  subprocess while preserving the same orchestration seam.
- **Pinned-subprocess fallback is allowed** when a library is too heavy or
  immature (e.g. cosign signing initially), but it still goes through
  `exec.Command(bin, args...)` — the no-shell rule is absolute even for fallbacks.
- The `core/lib/credential-broker.sh` and `core/scripts/agent-sandbox.sh` logic
  becomes Go too; nothing in the hot path requires a shell interpreter.

Caveat to manage: importing syft+grype+cosign as libraries pulls large dependency
trees. Adopt them incrementally behind the engine seam (below), measuring binary
size and build time, and keep the pinned-subprocess fallback as the escape hatch.

## Target end-state (acceptance for "done")

```bash
clearcutt platform new --owner acme --repo golden-images   # scaffold a full fleet repo
cd golden-images && clearcutt fleet certify-target ...      # build+gate locally, no core/ checkout
clearcutt remediation run ...                               # zero-touch patch, no python on disk
clearcutt verify boundaries <image>                         # the verify.sh gates, as a Go subcommand
```

The target state is that none of these require this monorepo on disk.
`platform new` now materializes a fleet repo from either a local reference
checkout, an embedded ClearCutt source archive, or an explicitly supplied source
archive/URL, so an installed CLI can scaffold without starting inside the
monorepo or requiring network. A later guarded option can add `gh repo create` +
push.

---

## Phase 1 — Consolidate the `core/` logic into Go

Move logic, **not** Nix recipes, into Go. Each workstream lands behind the
*existing* CLI verbs so workflows and tests don't change shape; the bash/python
becomes a thin shim (or is deleted) once parity is proven.

1. **`internal/build` (replaces `pipeline.sh` `certify_target`)**
   - Port: `nix build` invocation → SBOM (syft) → scan (grype `--fail-on`,
     policy-driven, **not** a bash literal) → push (go-containerregistry) → sign
     + attest (cosign). Make the grype threshold and SBOM format come from
     `fleet.yaml`/flags.
   - DoD: `fleet certify-target` produces byte-equivalent evidence (SBOM, test
     predicate, signatures) to the bash path for a fixture target; old
     `pipeline.sh` kept temporarily behind `--engine=legacy` for A/B.
2. **`internal/gates` (replaces `verify.sh` + `closure-*.py`)**
   - Port each gate: closure-purity `/nix/store` walk, runtime-CVE floor tuple
     compare, structure tests, credential-broker/sandbox isolation, matrix/floor
     drift. Expose single-image gates as `clearcutt verify boundaries` and the
     representative PR-gate loop as `clearcutt verify boundary-suite`.
   - DoD: gate verdicts match `verify.sh` on the same images; `pr-gate.yml`
     calls `clearcutt verify boundary-suite` instead of `./tests/verify.sh`.
3. **`internal/remediation` (replaces `cve-draft-agent.py`)**
   - Port deterministic Tier-1 (version bump) / Tier-2 (fetchpatch) overlay
     synthesis + the rebuild-and-rescan proof loop. Define an `LLMProvider`
     interface; ship a no-op default and an optional OpenRouter/Anthropic
     provider gated by an explicit `--llm` flag + key. LLM is strictly a
     fallback tier.
   - DoD: `remediation run` drafts+verifies a known overlay with `--llm=off`;
     `cve-patch-agent.yml` no longer calls a `.py` file.

**Verification gate for Phase 1:** `go test ./...` green; the PR-gate matrix
green on a real branch; evidence diff between Go and legacy engines is empty.

## Phase 2 — Embed the fleet skeleton into the binary

Use the established `//go:embed` pattern (already used for schemas in
`internal/catalog/schema_files.go`, plus `sitetemplate` and `versionpolicy`).

1. Landed: `internal/platformsource` embeds the **reference source archive**:
   - `.github/workflows/*` (release, pr-gate, rebase, scheduled-scan, etc.)
   - `.github/actions/*` (setup-nix and certify-app)
   - `core/flake.nix`, `core/flake.lock`, `core/lib/*.nix`, `core/overlays/**`,
     and any residual `.sh`/`.py` not yet ported
   - `schemas/*.json`
   - docs, examples, the site template, and CLI source needed by the current
     scaffolded workflow shape
   - generated/local state such as `site/src/data/catalog`, `cli/site`, coverage
     files, binaries, and the embedded zip itself are excluded by shared rules.
2. Landed: **Drift guard** asserts the embedded source archive is byte-identical
   to the source tree under those shared rules, so the binary cannot silently
   ship stale flake/workflow/source assets.
3. Landed: scaffolded fleet-operation workflows now use
   `.github/actions/install-clearcutt` to install a verified released CLI by
   default. Repositories that intentionally dogfood local source can set
   `CLEARCUTT_CLI_MODE=local`; the generated operator path no longer rebuilds
   `./clearcutt` from local source in release, catalog, rebase, remediation,
   cache-seeding, or fleet validation jobs.

**Verification gate:** `go test ./...` green incl. the new drift test; binary
size sanity-checked; `go vet`/`gofmt` clean.

## Phase 3 — `platform new` / `platform scaffold`

Status: `platform new [dir]` now copies the reference kit from a local ClearCutt
checkout when available, from an embedded source archive outside a checkout, or
from an explicit source zip archive/URL. It localizes identity with the existing
`platform init` machinery and is covered by checkout-backed, archive-backed, and
embedded no-network scaffold/status tests. The embedded archive has a drift
guard against the live source tree.

1. New verb `platform new --owner O --repo R [--dir PATH] [--registry HOST]`:
   - Materialize the embedded skeleton into `--dir` (default `./<repo>`).
   - Run the **existing** `runPlatformInit` localization over it (config, docs,
     metadata, app templates, example localization — already implemented in
     `platform.go`).
   - Emit `registry.host` plus `CLEARCUTT_REGISTRY_USER/TOKEN` setup guidance (see
     [registry-swap.md](../../registry-swap.md)).
2. Optional bootstrap `--push`: `git init` + `gh repo create O/R` + initial
   commit + push (guarded; no-op without `gh`/auth, with a clear message).
3. Single-source the registry host: have the scaffolded `fleet-matrix` job emit
   `registry_host` from `fleet.yaml` as a job output and reference it in the
   login steps, preserving the `registry.host` source of truth noted in
   registry-swap.md. Status: landed through `platform registry-env`.

**Verification gate:** `platform new` into a temp dir produces a tree where
`platform status` reports all checks pass, `platform doctor --github` can
preflight the pushed repo, `go`/`nix` build the CLI, and `actionlint` passes on
the generated workflows. Add an integration test that scaffolds → `platform
status` → asserts green.

## Phase 4 — Reposition

1. Lead `README.md`, `getting-started.md`, `platform-kit.md` with: install signed
   binary → `platform new` → own the generated repo. Demote "fork the monorepo"
   to the **contributor** path.
2. Derive the template-pinned CLI version from the binary build version
   (`-ldflags`), not the hardcoded `currentClearCuttRelease` literal
   (`app_template.go`), validated in CI against the latest tag.
3. Publish the binary install path prominently (it already exists and is
   cosign-verifiable).

**Verification gate:** a clean-machine walkthrough (install → `platform new` →
build → verify) works end to end and matches the README.

---

## Sequencing & risk

- **Phase 1 is the critical path and the biggest effort** (porting ~2.5k lines of
  bash/python to Go with parity tests). Do it workstream-by-workstream behind the
  existing verbs; keep the legacy engine selectable until each parity diff is
  empty. This de-risks the whole pivot — Phases 2–4 are mechanical once the logic
  is Go.
- **Do not port Nix.** The most common failure mode here is an agent trying to
  reimplement `nix build`/closures in Go. The flake and recipes are embedded
  assets, not logic to translate.
- **Keep evidence shape stable.** Schemas (`schemas/*`) are the contract; the Go
  engines must emit the same predicates the bash engines do, validated against
  the committed schemas.

## Progress

- **Port-map (done).** A survey confirmed the native-Go foundation is already
  substantial and the port should EXTEND it, not rewrite: `internal/oci`
  (go-containerregistry: daemon-free pull/push/build/rebase, fixture-testable via
  in-memory registry), `internal/certify` (walks docker-save + OCI-layout layers),
  `internal/scan` (grype-JSON → catalog findings), `internal/sign` (cosign behind
  an `exec` seam — keep as a pinned subprocess, no sigstore libs), `internal/attest`
  and `internal/catalogbuild` (pure in-toto/SPDX transforms). So Phase-1
  `internal/build` is largely **wiring these together around `nix build`**, not a
  from-scratch translation. Only `internal/sign` and `internal/commands/scan.go`
  shell out today, both via explicit-argv `exec.Command` (already zero-shell).
- **Boundary gates landed (2/?).** Both image-security gates that previously lived
  only in Python are now native Go, behind a shared layer-walker
  (`internal/certify/layers.go`):
  - `closure-purity-check.py` → `internal/certify/closure.go` + `clearcutt verify
    closure-purity` (full `/nix/store` walk — shells, package managers incl.
    versioned pip, setuid/setgid, whiteouts, explained-exception allowlist).
  - `closure-cve-check.py` → `internal/certify/runtimecve.go` + `clearcutt verify
    runtime-cve` (runtime-patch completeness: default-deny any shipped
    openssl/sqlite below the `runtime-dep-floor.json` floor; tuple version compare;
    artifact-skip anchoring). The port also fixes a latent leading-slash bug where
    store-level whiteouts never discarded.
  - Umbrella `clearcutt verify boundaries` runs both over one closure.
  - `clearcutt verify boundary-suite` owns the PR-gate representative loop:
    it realizes missing `coreLTS-slim` / `coreLTS-distroless` archives through
    Nix, runs closure-purity on distroless, and runs runtime-CVE on slim +
    distroless.
  All fixture-tested without a live `nix` build for command behavior; `pr-gate.yml`
  now calls the CLI boundary suite instead of `./tests/verify.sh`. Remaining call
  sites to migrate: `pipeline.sh:265,290` (need `clearcutt` on PATH in the dev
  shell) and `flake.nix:445,459` (build-sandbox gates — need the CLI in the
  build closure); Python stays until those move.
- **Aggregated single-PR (3A) landed.** `clearcutt remediation run` now accumulates
  every campaign overlay onto ONE rolling branch (`cve-remediation/auto`, configurable)
  and opens/updates a single draft PR with a `gh pr list --head` dedup guard — not a
  PR per CVE. The agent branches off the rolling HEAD, so the orchestrator fast-forwards
  the rolling branch to fold each overlay in (`resetRollingBranch`/`foldIntoRolling`/
  `openOrUpdateAggregatedPR` in `remediation_run.go`). Git/gh run behind a `cmdRunner`
  seam; 6 unit tests (fake runner) + the updated real-git integration test. This is the
  Go-only slice of the remediation port.
- **Deterministic scheduled drafting control landed.** `clearcutt remediation run
  --llm off` now filters to deterministic evidence-backed campaigns, and the
  scheduled workflow can opt into weekly draft PRs with
  `CLEARCUTT_SCHEDULED_REMEDIATION_DRAFTS=true` without requiring
  `OPENROUTER_API_KEY`.
- **Native deterministic recipe synthesis landed.** When deterministic evidence
  carries either a direct `route` + `overlay_expression` recipe or explicit
  source/patch URL plus hash metadata, the Go CLI now validates the route
  allowlist, writes the per-CVE overlay and evidence sidecar, creates the
  remediation branch, and folds it into the aggregated PR path without invoking
  `cve-draft-agent.py`. This native deterministic path now runs before retained
  backend fallback in both `--llm off` and `--llm auto`; `auto` only falls back
  for unresolved campaigns that still need hash iteration, build probing,
  rescanning, or optional LLM-provider work.
- **Manual remediation workflow now enters through the CLI.** `cve-patch-agent.yml`
  calls `clearcutt remediation run` with explicit package/CVE/version/source
  inputs and no longer invokes `cve-draft-agent.py` directly. The retained Python
  agent remains an internal fallback behind the CLI boundary for hash iteration,
  build probing, rescanning, and optional LLM-provider work.
- **Scheduled scan wrapper is now CLI-owned.** `scheduled-scan.yml` calls
  `clearcutt scan --update-db` directly through the core Nix dev shell. The old
  `core/scripts/scheduled-scan.sh` wrapper has been removed, and `platform
  status` now checks that scheduled scanning delegates to the CLI and does not
  reintroduce the shell wrapper.
- **Scheduled KEV refresh is now CLI-owned.** `scheduled-scan.yml` calls
  `clearcutt scan refresh-kev` instead of owning CISA KEV download and
  `kev-status.json` generation with inline `curl`/`jq`. The command writes the
  catalog cache plus status JSON and keeps refresh unavailability non-fatal by
  default.
- **Scheduled remediation parameters are now CLI-owned.** The scheduled scan and
  draft jobs call `clearcutt remediation workflow-params --github-output
  "$GITHUB_OUTPUT"` instead of parsing `matrix export --source fleet` with
  inline `jq`. The command emits scan depth, campaign limits, dev-tier inclusion,
  and compact remediation policy JSON from `clearcutt.fleet.yaml`.
- **Scheduled plan/report/run shell assembly is now CLI-owned.** `remediation
  plan` consumes the same CI env defaults as `remediation run`, `remediation
  report --allow-missing` replaces always-run shell file checks, and
  `remediation run --require-llm-key` owns the OpenRouter key preflight while
  scheduled events prefer `SCHEDULED_REMEDIATION_LIMIT` and force dev-tier
  inclusion off.
- **Native-Go build engine is now the default CLI path (certify, publish, and index assembly).** `internal/build` ports
  `pipeline.sh certify_target`: `nix build` → Syft → Grype (with the tier/kind
  warning-vs-fail policy) → the **in-process** closure-purity + runtime-cve gates
  (no python) → the same test-results predicate. Subprocesses run behind a `Runner`
  seam (zero shell). `fleet certify-target`, `fleet publish-target`, `service
  build`, and `service publish` default to the Go engine; the CLI still accepts
  the legacy `shell` engine, and release, PR, and seed-cache workflows can
  temporarily set `CLEARCUTT_BUILD_ENGINE=shell` while debugging parity. `fleet
  publish-target` reuses the same native certify path and pushes the per-arch
  staging image through go-containerregistry. `service build` and `service
  publish` now run the same native certify path with
  service-specific policy metadata, and service publish pushes the per-arch staging
  image through go-containerregistry. Runtime `fleet assemble-target` and service
  `service assemble` now build and publish their multi-architecture image indexes
  through go-containerregistry instead of `crane index append`/`crane digest`.
  The retained `core/pipeline/pipeline.sh` fallback still owns shell wrapper
  mechanics, but its closure-purity and runtime-CVE checks now delegate to
  `clearcutt verify ...` instead of invoking the Python gate scripts directly.
  `fleet workflow-matrices` owns the release and PR-gate runtime/service matrix
  aggregation plus `GITHUB_OUTPUT` shaping, leaving those workflows to provide
  checkout, CLI installation, approvals, and matrix fan-out.
  `fleet seed-cache-plan` owns cache-seeding matrix export, Nix dry-run parsing,
  eval-error handling, and `GITHUB_OUTPUT` shaping, leaving the seed workflow to
  provide approvals, matrix fan-out, and cache-write secrets.
  `catalog workflow-params` now owns Pages release-limit/scan-depth output, and
  `catalog site build --generate-vex --site-url --base-path` owns catalog-site
  packaging plus per-image OpenVEX generation, leaving the Pages workflow to
  transfer artifacts and deploy through GitHub Pages. `catalog build --core-dir
  core --update-db` now routes Grype through the scaffolded Nix backend and owns
  DB refresh, so the Pages workflow no longer installs scanner tooling or
  branches around force-refresh behavior in shell.
  `fleet build-cli-assets` owns the release CLI binary OS/architecture matrix,
  version ldflags, optional `cosign sign-blob` loop, release asset manifest, and
  deterministic `SHA256SUMS.txt`, leaving the release workflow to provide Go,
  Cosign, OIDC, artifact upload, and the SLSA reusable workflow boundary.
  `verify release-evidence` also resolves the published digest through the Go OCI
  client before invoking the cryptographic verifiers. Cosign still owns signing
  and attestations, SLSA verifier still owns the SLSA provenance check, and the
  GitHub CLI still owns GitHub-native attestation verification, but fleet/service
  signing, attestation export, and release-evidence verification can now run those
  tools through the scaffolded core flake with `nix develop --command` instead of
  requiring ambient installs. `slsa-verifier` is packaged as a flake-local binary
  derivation because the current pinned nixpkgs revision does not expose it. The production Go runner now leaves `nix build`
  direct and resolves Syft/Grype through `nix develop --command`, so a released CLI needs the Nix
  backend and the scaffolded core flake rather than ambient scanner binaries. Unit tests
  cover a fake Runner over crafted runtime/service archives, Nix-backed tool resolution,
  Go-owned archive push, Go-owned index push, Go-owned digest resolution, and a real-gate
  verdict; the actual `nix build` of a Linux image is CI-verified (a Darwin box has no
  linux-builder, and the engine fails fast on `*-darwin`).
- **Next:** prove the Go engine lanes in CI, then port the remaining retained
  `cve-draft-agent.py` hash-iteration/build/rescan loop + optional-LLM-provider path.

## Related workstreams (separate from this pivot, cross-referenced)

- **Aggregated single CVE PR** (one rolling branch + `gh pr list` dedup) — lands
  naturally inside the Phase-1 `internal/remediation` port. See
  [autonomous remediation notes].
- **Rebase auto-update via an opt-in app-supplied smoke hook** — platform does
  not own app tests; it runs a user-provided probe and gates on exit code.
- **Honest SLSA level + reproducibility evidence** — derive the level from the
  predicate; wire the already-implemented `verify rebuild --require-layer-match`
  into CI as differentiated evidence. See [security-model.md](../../security-model.md).
